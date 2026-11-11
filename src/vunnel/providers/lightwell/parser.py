from __future__ import annotations

import logging
import os
import zipfile
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


namespace = "lightwell"


class Parser:
    _source_url_ = "https://github.com/project-lightwell/lightwell-osv/archive/refs/heads/main.zip"

    def __init__(
        self,
        ws: Workspace,
        download_timeout: int = 125,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.url = self._source_url_
        self.download_timeout = download_timeout
        self.urls = [self.url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.zip_path = os.path.join(self.workspace.input_path, "lightwell-osv.zip")

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self.logger.info(f"downloading lightwell advisories from {self.url}")
        http.download_to_file(self.url, self.zip_path, self.logger, timeout=self.download_timeout)

    def _load(self) -> Generator[dict[str, Any]]:
        self.logger.info("loading advisories from zip archive")

        with zipfile.ZipFile(self.zip_path) as zf:
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                if info.is_dir():
                    continue
                parts = info.filename.split("/")
                if len(parts) < 2 or parts[-2] != "advisories" or not parts[-1].endswith(".json"):
                    continue
                with zf.open(info) as f:
                    yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]

        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry["schema_version"]

        vuln_entry.setdefault("database_specific", {}).setdefault("anchore", {})["record_type"] = "advisory"

        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        self._download()

        self.fixdater.download()

        for vuln_entry in self._load():
            osv.patch_fix_date(vuln_entry, self.fixdater)
            yield self._normalize(vuln_entry)
