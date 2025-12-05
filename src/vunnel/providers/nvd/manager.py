from __future__ import annotations

import datetime
import logging
import os
from typing import TYPE_CHECKING, Any

from vunnel import result
from vunnel.providers.nvd.api import NvdAPI
from vunnel.providers.nvd.overrides import NVDOverrides
from vunnel.tool import fixdate

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel import schema as schema_def
    from vunnel.workspace import Workspace


class Manager:
    __nvd_input_db__ = "nvd-input.db"

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        schema: schema_def.Schema,
        overrides_url: str,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        download_retry_count: int = 10,
        api_key: str | None = None,
        overrides_enabled: bool = False,
    ) -> None:
        self.workspace = workspace

        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self.api = NvdAPI(api_key=api_key, logger=logger, timeout=download_timeout, retries=download_retry_count)

        self.overrides = NVDOverrides(
            enabled=overrides_enabled,
            url=overrides_url,
            workspace=workspace,
            logger=logger,
            download_timeout=download_timeout,
            retries=download_retry_count,
        )

        self.urls = [self.api._cve_api_url_]
        self.schema = schema

    def __enter__(self) -> Manager:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def get(
        self,
        last_updated: datetime.datetime | None,
        skip_if_exists: bool = False,
    ) -> Generator[tuple[str, dict[str, Any]], Any]:
        """main method to fetch and process NVD vulnerability data.

        This orchestrates a few concerns:
        1. downloads NVD API data (with incremental updates by default)
        2. applies configuration overrides for CPE matching
        3. enriches records with fix dates from external databases
        4. processes CVEs that have override data but weren't in the main sync
        5. handles CVEs with updated fix dates even if not in incremental sync

        Args:
            last_updated: Only process CVEs modified after this datetime (for incremental updates)
            skip_if_exists: Skip download if local data already exists

        Yields:
            Tuples of (record_id, processed_vulnerability_record) for each CVE
        """
        # download dependencies
        if self.overrides.enabled:
            self.overrides.download()

        self.fixdater.download()

        # main NVD data download and processing
        cves_processed = set()
        for record_id, record in self._download_nvd_input(last_updated, skip_if_exists):
            cves_processed.add(id_to_cve(record_id))
            yield record_id, record

        self.logger.info(f"Added {len(cves_processed)} CVEs")

        yield from self._finalize_all_records(cves_processed)

    def _finalize_all_records(self, already_processed: set[str]) -> Generator[tuple[str, dict[str, Any]], Any]:
        """process any CVEs in the local database that weren't processed yet.

        This ensures that any CVEs that might have been missed in the main download
        (e.g., due to being very old and not recently modified) but have fix dates
        are still processed and yielded.

        This also allows synthesis of new CVE records from overrides where there isn't
        yet json data available from NVD, for instance for a CVE that is already
        published in the wild but is still showing as reserved in CVE or NVD

        Args:
            already_processed: Set of CVE IDs that have already been processed

        Yields:
            Tuples of (record_id, processed_vulnerability_record) for each CVE
        """
        if not self.fixdater:
            return

        self.logger.info("applying current fix dates and overrides to remaining CVEs...")

        overrides_applied = 0

        with self._sqlite_reader() as reader:
            for record in reader.each():
                cve_id = record.item["cve"]["id"].upper()
                if cve_id in already_processed:
                    continue

                original_record = record.item
                if not original_record:
                    self.logger.warning(f"missing original data for CVE {cve_id}")
                    continue

                modified, record_with_overrides = self._apply_override(cve_id=cve_id, record=original_record)
                if modified:
                    overrides_applied += 1

                already_processed.add(cve_id)
                yield cve_to_id(cve_id), self._apply_fix_dates(cve_id=cve_id, record=record_with_overrides)

        # Now we need to synthesize an NVD record for any overrides where there wasn't an existing NVD record
        if self.overrides.enabled:
            for cve_id in self.overrides.cves():
                if cve_id in already_processed:
                    continue

                synthesized_record = self._synthesize_nvd_record_from_override(cve_id=cve_id)
                if not synthesized_record:
                    continue

                overrides_applied += 1
                already_processed.add(cve_id)
                yield cve_to_id(cve_id), self._apply_fix_dates(cve_id=cve_id, record=synthesized_record)

        self.logger.info(f"applied {overrides_applied} CVE overrides")

    def _download_nvd_input(
        self,
        last_updated: datetime.datetime | None,
        skip_if_exists: bool = False,
    ) -> Generator[tuple[str, dict[str, Any]], Any]:
        with self._nvd_input_writer() as writer:
            if skip_if_exists and self._can_update_incrementally(last_updated):
                yield from self._download_updates(last_updated, writer)  # type: ignore  # noqa: PGH003
            else:
                yield from self._download_all(writer)

    def _nvd_input_writer(self) -> result.Writer:
        return result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.KEEP,
            logger=self.logger,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=self._input_nvd_path,
        )

    def _sqlite_reader(self) -> result.SQLiteReader:
        return result.SQLiteReader(sqlite_db_path=self._input_nvd_path)

    @property
    def _input_nvd_path(self) -> str:
        return os.path.join(self.workspace.input_path, self.__nvd_input_db__)

    def _can_update_incrementally(self, last_updated: datetime.datetime | None) -> bool:
        input_db_path = os.path.join(self.workspace.input_path, self.__nvd_input_db__)
        if not os.path.exists(input_db_path):
            return False

        if not last_updated:
            return False

        now = datetime.datetime.now(tz=datetime.UTC)
        days_since_last_sync = (now - last_updated).days

        if days_since_last_sync >= NvdAPI.max_date_range_days:
            self.logger.info(
                f"last sync was {days_since_last_sync} days ago (more than {NvdAPI.max_date_range_days} days, the max range value of the NVD API), downloading all data",  # noqa: E501
            )
            return False

        return True

    def _download_all(self, writer: result.Writer) -> Generator[tuple[str, dict[str, Any]], Any]:
        self.logger.info("downloading all CVEs")

        # TODO: should we delete all existing state in this case first?

        for response in self.api.cve():
            yield from self._unwrap_records(response, writer)

    def _download_updates(
        self,
        last_updated: datetime.datetime,
        writer: result.Writer,
    ) -> Generator[tuple[str, dict[str, Any]], Any]:
        self.logger.debug(f"downloading CVEs changed since {last_updated.isoformat()}")

        # get the list of CVEs that have been updated since the last sync
        now = datetime.datetime.now(tz=datetime.UTC)
        for idx, response in enumerate(self.api.cve(last_mod_start_date=last_updated, last_mod_end_date=now)):
            if idx == 0:
                total_results = response.get("totalResults", None)
                if total_results:
                    self.logger.debug(f"discovered {total_results} updated CVEs")

            yield from self._unwrap_records(response, writer)

    def _unwrap_records(
        self,
        response: dict[str, Any],
        writer: result.Writer,
    ) -> Generator[tuple[str, dict[str, Any]], Any]:
        """extract individual CVE records from NVD API response and apply processing.

        Takes paginated NVD API responses and processes each vulnerability:
        1. extracts individual CVE records from the response
        2. stores raw data for future override processing
        3. applies overrides and known fix dates to create final output records
        """
        for vuln in response["vulnerabilities"]:
            cve_id = vuln["cve"]["id"]
            record_id = cve_to_id(cve_id)

            # keep input for future overrides
            writer.write(record_id, self.schema, vuln)

            # apply overrides and fix dates to output
            _, record_with_overrides = self._apply_override(cve_id=cve_id, record=vuln)
            yield record_id, self._apply_fix_dates(cve_id=cve_id, record=record_with_overrides)

    def _is_empty_override(self, override: dict[str, Any] | None) -> bool:
        return override is None or "cve" not in override or "configurations" not in override["cve"]

    def _synthesize_nvd_record_from_override(self, cve_id: str) -> dict[str, Any] | None:
        override = self.overrides.cve(cve_id)
        if self._is_empty_override(override):
            return None

        annotation = override.get("_annotation")  # type: ignore[union-attr]
        if not annotation:
            return None

        self.logger.trace(f"synthesizing NVD record from override for {cve_id}")  # type: ignore[attr-defined]

        cve_record = {
            "id": cve_id,
            "sourceIdentifier": annotation.get("cna", "anchore"),
            "published": annotation.get("published", datetime.datetime.now(datetime.UTC).isoformat()),
            "lastModified": annotation.get("modified", datetime.datetime.now(datetime.UTC).isoformat()),
            "vulnStatus": "Reserved",
        }

        description = annotation.get("description")

        if not description:
            self.logger.warning(f"failed synthesizing NVD record from override for {cve_id} because description is required")
            return None

        cve_record["descriptions"] = [
            {
                "lang": "en",
                "value": description,
            },
        ]

        references = annotation.get("references", [])
        refs = []

        for r in references:
            refs.append(
                {
                    "url": r,
                },
            )

        cve_record["references"] = refs
        _, record = self._apply_override(cve_id=cve_id, record={"cve": cve_record})
        return record

    def _apply_override(self, cve_id: str, record: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """apply configuration overrides to modify CPE matching rules for a CVE.

        Overrides allow customizing the affected software configurations for specific CVEs.
        This is useful for correcting vendor-supplied configuration data or adding
        additional software versions that are affected.
        """
        override = self.overrides.cve(cve_id)
        modified = False
        if override:
            self.logger.trace(f"applying override for {cve_id}")  # type: ignore[attr-defined]
            # ignore empty overrides
            if self._is_empty_override(override):
                return False, record
            # explicitly only support CPE configurations for now and always override the
            # original record configurations. Can figure out more complicated scenarios
            # later if needed
            record["cve"]["configurations"] = override["cve"]["configurations"]
            modified = True

        return modified, record

    def _apply_fix_dates(self, cve_id: str, record: dict[str, Any]) -> dict[str, Any]:
        """enrich CVE records with fix date information from external databases.

        Traverses the CVE's configuration structure to find CPE matches and looks up
        corresponding fix dates from the fix date database. Adds fix date information
        as structured fields in the schema-compliant format.

        The fix date includes version, date, and kind information to help users
        understand when vulnerabilities were first observed to be fixed.
        """
        if not self.fixdater:
            return record

        configurations = record.get("cve", {}).get("configurations", [])
        if not configurations:
            return record

        # traverse configurations -> nodes -> cpeMatch to find CPE entries
        for config in configurations:
            for node in config.get("nodes", []):
                cpe_matches = node.get("cpeMatch", [])
                for cpe_match in cpe_matches:
                    criteria = cpe_match.get("criteria", "")
                    if not criteria or not criteria.startswith("cpe:"):
                        continue

                    # only add fix dates to vulnerable CPE matches
                    if not cpe_match.get("vulnerable", False):
                        continue

                    # use the versionEndExcluding as an indicator of a fixed version. If no fixed version if
                    # found, then continue to the next record.
                    fix_version = cpe_match.get("versionEndExcluding", None)

                    if not fix_version:
                        continue

                    # look up fix dates for this CPE and CVE
                    # get the underlying FixDate objects with version info
                    fix_date = self.fixdater.best(
                        vuln_id=cve_id,
                        cpe_or_package=criteria,
                        fix_version=fix_version,
                        ecosystem=None,  # nvd has no ecosystem
                    )

                    if fix_date and fix_date.date:
                        cpe_match["fix"] = {
                            "version": fix_date.version or "",
                            "date": fix_date.date.isoformat(),
                            "kind": fix_date.kind,
                        }

        return record


def cve_to_id(cve: str) -> str:
    """convert CVE identifier to hierarchical storage path.

    Organizes CVEs by year for efficient file system storage.
    Example: CVE-2023-1234 -> "2023/cve-2023-1234"
    """
    year = cve.split("-")[1]
    return os.path.join(year, cve).lower()


def id_to_cve(cve_id: str) -> str:
    """extract CVE identifier from hierarchical storage path.

    Reverses cve_to_id conversion for lookups.
    Example: "2023/cve-2023-1234" -> CVE-2023-1234
    """
    return cve_id.split("/")[1].upper()
