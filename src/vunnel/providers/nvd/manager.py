# flake8: noqa

import datetime
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Generator

from dataclass_wizard import fromdict

from vunnel import utils
from vunnel.workspace import Workspace

from .api import NvdAPI

METADATA_FILENAME: str = "metadata.json"


@dataclass
class Metadata:
    timestamp: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(tz=datetime.timezone.utc))

    @staticmethod
    def read(root: str) -> "Metadata":
        path = os.path.join(root, METADATA_FILENAME)

        with open(path, encoding="utf-8") as f:
            return fromdict(Metadata, json.load(f))

    def write(self, root: str) -> None:
        path = os.path.join(root, METADATA_FILENAME)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, cls=utils.DTEncoder, indent=2)


class Manager:
    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        start_year: int = 2002,
        end_year: int | None = None,
        api_key: str | None = None,
    ) -> None:
        self.workspace = workspace
        self.start_year = start_year
        self.end_year = end_year

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self.api = NvdAPI(api_key=api_key, logger=logger, timeout=download_timeout)
        self.urls = [self.api._cve_api_url_]

    def get(self, skip_if_exists: bool = False) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        if skip_if_exists and self._can_update_incrementally():
            yield from self._download_updates()
        else:
            yield from self._download_all()

    def _can_update_incrementally(self) -> bool:
        try:
            metadata = Metadata.read(self.workspace.scratch_path)
        except FileNotFoundError:
            self.logger.warning(f"no existing cache files found, downloading all data")
            return False

        last_sync = metadata.timestamp

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        days_since_last_sync = (now - last_sync).days

        if days_since_last_sync > NvdAPI.max_date_range_days:
            self.logger.warning(
                f"last sync was {days_since_last_sync} days ago (more than {NvdAPI.max_date_range_days} days, a limitation of the NVD API), downloading all data"
            )
            return False

        return True

    def _download_all(self) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        self.logger.info("downloading all CVEs")

        # TODO: should we delete all existing state in this case first?

        # we need to track the last sync time for incremental updates on subsequent runs
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        for response in self.api.cve():
            yield from self._unwrap_records(response)

        Metadata(timestamp=now).write(self.workspace.scratch_path)

    def _download_updates(self) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        metadata = Metadata.read(self.workspace.scratch_path)
        last_sync = metadata.timestamp

        self.logger.debug(f"downloading CVEs changed since {last_sync.isoformat()}")

        # we need to track the last sync time for incremental updates on subsequent runs
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        # get the list of CVEs that have been updated since the last sync
        for idx, response in enumerate(self.api.cve(last_mod_start_date=last_sync, last_mod_end_date=now)):
            if idx == 0:
                total_results = response.get("totalResults", None)
                if total_results:
                    self.logger.debug(f"discovered {total_results} updated CVEs")

            yield from self._unwrap_records(response)

        Metadata(timestamp=now).write(self.workspace.scratch_path)

    def _unwrap_records(self, response: dict[str, Any]) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        for vuln in response["vulnerabilities"]:
            cve_id = vuln["cve"]["id"]
            year = cve_id.split("-")[1]
            yield os.path.join(year, cve_id), vuln
