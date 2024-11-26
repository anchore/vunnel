from __future__ import annotations

import datetime
import logging
import os
from typing import TYPE_CHECKING, Any

from vunnel import result
from vunnel.providers.nvd.api import NvdAPI
from vunnel.providers.nvd.overrides import NVDOverrides

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
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        download_retry_count: int = 10,
        api_key: str | None = None,
        overrides_enabled: bool = False,
    ) -> None:
        self.workspace = workspace

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
        self.overrides.download()

        cves_processed = set()
        for record_id, record in self._download_nvd_input(last_updated, skip_if_exists):
            cves_processed.add(id_to_cve(record_id))
            yield record_id, record

        if self.overrides.enabled:
            self.urls.append(self.overrides.url)
            self.logger.debug("applying NVD data overrides...")

            override_cves = {cve.lower() for cve in self.overrides.cves()}
            override_remaining_cves = override_cves - cves_processed
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

                    yield cve_to_id(cve), self._apply_override(cve, original_record)

            self.logger.debug(f"applied overrides for {len(override_remaining_cves)} CVEs")
        else:
            self.logger.debug("overrides are not enabled, skipping...")

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
        for vuln in response["vulnerabilities"]:
            cve_id = vuln["cve"]["id"]
            record_id = cve_to_id(cve_id)

            # keep input for future overrides
            writer.write(record_id.lower(), self.schema, vuln)

            # apply overrides to output
            yield record_id, self._apply_override(cve_id=cve_id, record=vuln)

    def _apply_override(self, cve_id: str, record: dict[str, Any]) -> dict[str, Any]:
        override = self.overrides.cve(cve_id)
        if override:
            self.logger.debug(f"applying override for {cve_id}")
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


def cve_to_id(cve: str) -> str:
    year = cve.split("-")[1]
    return os.path.join(year, cve)


def id_to_cve(cve_id: str) -> str:
    return cve_id.split("/")[1]
