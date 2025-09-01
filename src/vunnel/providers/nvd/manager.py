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

    def get(
        self,
        last_updated: datetime.datetime | None,
        skip_if_exists: bool = False,
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        """main method to fetch and process NVD vulnerability data.

        This orchestrates e few concerns:
        1. downloads NVD API data (with incremental updates by default)
        2. applies configuration overrides for CPE matching
        3. enriches records with fix dates from external databases
        4. handles CVEs with updated fix dates even if not in incremental sync

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

        # track CVEs with changed fix dates that need reprocessing
        changed_cve_ids = set()
        if last_updated:
            changed_vuln_ids = self.fixdater.get_changed_vuln_ids_since(last_updated)
            changed_cve_ids = set(changed_vuln_ids)

        # main NVD data download and processing
        cves_processed = set()
        for record_id, record in self._download_nvd_input(last_updated, skip_if_exists):
            cves_processed.add(id_to_cve(record_id))
            yield record_id, record

        # process remaining override CVEs
        yield from self._process_override_cves(cves_processed)

        # process remaining CVEs with changed fix dates
        yield from self._process_changed_fix_date_cves(changed_cve_ids, cves_processed)

    def _download_nvd_input(
        self,
        last_updated: datetime.datetime | None,
        skip_if_exists: bool = False,
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
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

    def _download_all(self, writer: result.Writer) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        self.logger.info("downloading all CVEs")

        # TODO: should we delete all existing state in this case first?

        for response in self.api.cve():
            yield from self._unwrap_records(response, writer)

    def _download_updates(
        self,
        last_updated: datetime.datetime,
        writer: result.Writer,
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
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
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
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
            writer.write(record_id.lower(), self.schema, vuln)

            # apply overrides and fix dates to output
            record_with_overrides = self._apply_override(cve_id=cve_id, record=vuln)
            yield record_id, self._apply_fix_dates(cve_id=cve_id, record=record_with_overrides)

    def _apply_override(self, cve_id: str, record: dict[str, Any]) -> dict[str, Any]:
        """apply configuration overrides to modify CPE matching rules for a CVE.

        Overrides allow customizing the affected software configurations for specific CVEs.
        This is useful for correcting vendor-supplied configuration data or adding
        additional software versions that are affected.
        """
        override = self.overrides.cve(cve_id)
        if override:
            self.logger.trace(f"applying override for {cve_id}")  # type: ignore[attr-defined]
            # ignore empty overrides
            if override is None or "cve" not in override:
                return record
            # explicitly only support CPE configurations for now and always override the
            # original record configurations. Can figure out more complicated scenarios
            # later if needed
            if "configurations" not in override["cve"]:
                return record

            record["cve"]["configurations"] = override["cve"]["configurations"]

        return record

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

    def _process_override_cves(self, cves_processed: set[str]) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        """process CVEs that need override application but weren't in the main download.

        Some CVEs may have overrides defined but not be included in incremental downloads
        (because they weren't recently modified in NVD). This method ensures all CVEs
        with overrides are processed by fetching them from the local SQLite database
        and applying both overrides and fix dates.
        """
        if not self.overrides.enabled:
            self.logger.debug("overrides are not enabled, skipping...")
            return

        self.urls.append(self.overrides.url)
        self.logger.debug("applying NVD data overrides...")

        override_cves = {cve.lower() for cve in self.overrides.cves()}
        override_remaining_cves = override_cves - cves_processed

        if not override_remaining_cves:
            self.logger.debug("no remaining CVEs need overrides")
            return

        with self._sqlite_reader() as reader:
            for cve in override_remaining_cves:
                original_record = reader.read(cve_to_id(cve))
                if not original_record:
                    self.logger.warning(f"override for {cve} not found in original data")
                    continue

                original_record = original_record["item"]
                if not original_record:
                    self.logger.warning(f"missing original data for {cve}")
                    continue

                record_with_overrides = self._apply_override(cve, original_record)
                yield cve_to_id(cve), self._apply_fix_dates(cve, record_with_overrides)

        self.logger.debug(f"applied overrides for {len(override_remaining_cves)} CVEs")

    def _process_changed_fix_date_cves(self, changed_cve_ids: set[str], cves_processed: set[str]) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        """process CVEs with changed fix dates that weren't already handled.

        Even during incremental updates, some CVEs may not be reprocessed by NVD
        but their fix date information may have been updated in our external database.
        This method ensures those CVEs get reprocessed with the latest fix date data
        by fetching them from local storage and applying current overrides and fix dates.
        """
        if not self.fixdater or not changed_cve_ids:
            return

        remaining_changed_cves = changed_cve_ids - cves_processed
        if not remaining_changed_cves:
            return

        self.logger.debug(f"processing {len(remaining_changed_cves)} CVEs with changed fix dates...")

        with self._sqlite_reader() as reader:
            for cve in remaining_changed_cves:
                original_record = reader.read(cve_to_id(cve))
                if not original_record:
                    self.logger.warning(f"CVE with changed fix date {cve} not found in original data")
                    continue

                original_record = original_record["item"]
                if not original_record:
                    self.logger.warning(f"missing original data for CVE with changed fix date {cve}")
                    continue

                record_with_overrides = self._apply_override(cve, original_record)
                yield cve_to_id(cve), self._apply_fix_dates(cve, record_with_overrides)


def cve_to_id(cve: str) -> str:
    """convert CVE identifier to hierarchical storage path.

    Organizes CVEs by year for efficient file system storage.
    Example: CVE-2023-1234 -> "2023/CVE-2023-1234"
    """
    year = cve.split("-")[1]
    return os.path.join(year, cve)


def id_to_cve(cve_id: str) -> str:
    """extract CVE identifier from hierarchical storage path.

    Reverses cve_to_id conversion for lookups.
    Example: "2023/CVE-2023-1234" -> CVE-2023-1234
    """
    return cve_id.split("/")[1]
