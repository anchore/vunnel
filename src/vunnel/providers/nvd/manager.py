from __future__ import annotations

import datetime
import logging
import os
from typing import TYPE_CHECKING, Any

from .api import NvdAPI

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace


class Manager:
    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        api_key: str | None = None,
    ) -> None:
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self.api = NvdAPI(api_key=api_key, logger=logger, timeout=download_timeout)
        self.urls = [self.api._cve_api_url_]  # noqa: SLF001

    def get(
        self,
        last_updated: datetime.datetime | None,
        skip_if_exists: bool = False,
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        if skip_if_exists and self._can_update_incrementally(last_updated):
            yield from self._download_updates(last_updated)  # type: ignore  # noqa: PGH003
        else:
            yield from self._download_all()

    def _can_update_incrementally(self, last_updated: datetime.datetime | None) -> bool:
        if not last_updated:
            return False

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        days_since_last_sync = (now - last_updated).days

        if days_since_last_sync >= NvdAPI.max_date_range_days:
            self.logger.info(
                f"last sync was {days_since_last_sync} days ago (more than {NvdAPI.max_date_range_days} days, the max range value of the NVD API), downloading all data",  # noqa: E501
            )
            return False

        return True

    def _download_all(self) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        self.logger.info("downloading all CVEs")

        # TODO: should we delete all existing state in this case first?

        for response in self.api.cve():
            yield from self._unwrap_records(response)

    def _download_updates(self, last_updated: datetime.datetime) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        self.logger.debug(f"downloading CVEs changed since {last_updated.isoformat()}")

        # get the list of CVEs that have been updated since the last sync
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for idx, response in enumerate(self.api.cve(last_mod_start_date=last_updated, last_mod_end_date=now)):
            if idx == 0:
                total_results = response.get("totalResults", None)
                if total_results:
                    self.logger.debug(f"discovered {total_results} updated CVEs")

            yield from self._unwrap_records(response)

    def _unwrap_records(self, response: dict[str, Any]) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        for vuln in response["vulnerabilities"]:
            cve_id = vuln["cve"]["id"]
            year = cve_id.split("-")[1]
            yield os.path.join(year, cve_id), vuln
