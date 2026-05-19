from __future__ import annotations

import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.utils import http_wrapper as http
from vunnel.utils import silent_remove

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


namespace = "govulndb"


class Parser:
    _source_url_ = "https://vuln.go.dev/vulndb.zip"

    def __init__(
        self,
        ws: Workspace,
        url: str | None = None,
        download_timeout: int = 125,
        skip_download: bool = False,
        logger: logging.Logger | None = None,
    ):
        self.workspace = ws
        self.url = url or self._source_url_
        self.download_timeout = download_timeout
        self.skip_download = skip_download
        self.urls = [self.url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.zip_path = os.path.join(self.workspace.input_path, "vulndb.zip")
        self.extract_dir = os.path.join(self.workspace.input_path, "vulndb")

    def __enter__(self) -> Parser:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        return None

    def _download(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        silent_remove(self.zip_path)
        self.logger.info(f"downloading go vulnerability database from {self.url}")
        r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
        with open(self.zip_path, "wb") as fp:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    fp.write(chunk)

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
        self.logger.info("loading data from extracted vulnerability database")

        id_dir = os.path.join(self.extract_dir, "ID")
        if not os.path.isdir(id_dir):
            self.logger.warning(f"no ID directory found under {self.extract_dir}; nothing to load")
            return

        for name in sorted(os.listdir(id_dir)):
            if not name.endswith(".json"):
                continue
            full_path = os.path.join(id_dir, name)
            with open(full_path, encoding="utf-8") as f:
                yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry["schema_version"]
        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        if self.skip_download:
            self.logger.info(f"skipping download; using existing data under {self.extract_dir}")
        else:
            self._download()
            self._extract()

        for vuln_entry in self._load():
            yield self._normalize(vuln_entry)
