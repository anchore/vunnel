from __future__ import annotations

import logging
import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


namespace = "ocaml"


class Parser:
    # OSV records generated from https://github.com/ocaml/security-advisories (generated-osv branch)
    _source_url_ = "https://github.com/ocaml/security-advisories/archive/refs/heads/generated-osv.zip"
    _advisory_file_ = re.compile(r"^OSEC-\d{4}-\d+\.json$")

    def __init__(  # noqa: PLR0913
        self,
        ws: Workspace,
        url: str | None = None,
        download_timeout: int = 125,
        skip_download: bool = False,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws, skip_download=skip_download)
        self.fixdater = fixdater
        self.workspace = ws
        self.url = url or self._source_url_
        self.download_timeout = download_timeout
        self.skip_download = skip_download
        self.urls = [self.url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.zip_path = os.path.join(self.workspace.input_path, "security-advisories.zip")
        self.extract_dir = os.path.join(self.workspace.input_path, "security-advisories")

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self.logger.info(f"downloading ocaml security advisories from {self.url}")
        http.download_to_file(self.url, self.zip_path, self.logger, timeout=self.download_timeout)

    def _extract(self) -> None:
        shutil.rmtree(self.extract_dir, ignore_errors=True)
        os.makedirs(self.extract_dir, exist_ok=True)
        dest_root = Path(os.path.abspath(self.extract_dir))
        with zipfile.ZipFile(self.zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                target = Path(os.path.normpath(os.path.join(dest_root, info.filename)))
                if dest_root != target and dest_root not in target.parents:
                    self.logger.warning(f"skipping zip entry outside destination: {info.filename!r}")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    def _load(self) -> Generator[dict[str, Any]]:
        self.logger.info("loading data from extracted ocaml security advisories")

        if not os.path.isdir(self.extract_dir):
            self.logger.warning(f"no directory found at {self.extract_dir}; nothing to load")
            return

        # the archive is laid out as <branch-dir>/<year>/OSEC-<year>-<n>.json; other files are not advisories
        for root, dirs, files in os.walk(self.extract_dir):
            dirs.sort()
            for name in sorted(files):
                if not self._advisory_file_.match(name):
                    continue
                with open(os.path.join(root, name), encoding="utf-8") as f:
                    yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        # the OSV record is kept as it is; grype-db transforms it into the grype schema
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry["schema_version"]
        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        if self.skip_download:
            self.logger.info(f"skipping download; using existing data under {self.extract_dir}")
        else:
            self._download()
            self._extract()

        self.fixdater.download()

        for vuln_entry in self._load():
            osv.patch_fix_date(vuln_entry, self.fixdater)
            yield self._normalize(vuln_entry)
