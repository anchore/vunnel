from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace

from .client import Client


class Parser:
    def __init__(self, ws: Workspace, logger: logging.Logger | None = None, skip_download: bool = False):
        self.workspace = ws
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.client = Client(
            download_path=os.path.join(self.workspace.input_path, "osv"),
            logger=self.logger,
            skip_download=skip_download,
        )
        self.urls = self.client.urls

    def _load(self) -> Generator[dict[str, Any], None, None]:
        for path in self.client.get():
            with open(path, encoding="utf-8") as f:
                yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry.get("schema_version", "1.7.0")
        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        for vuln_entry in self._load():
            yield self._normalize(vuln_entry)
