from __future__ import annotations

import json
import logging
import os
import zipfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

from pathlib import Path
from typing import Any

import requests

from vunnel import utils, workspace

NAMESPACES = {"Rocky Linux:8": "rocky:8", "Rocky Linux:9": "rocky:9"}


class Parser:
    _zip_base_url_ = "https://osv-vulnerabilities.storage.googleapis.com/"

    def __init__(self, ws: workspace.Workspace, download_timeout: int = 125, logger: logging.Logger | None = None):
        self.workspace = ws
        self.download_timeout = download_timeout
        self.namespaces = {}
        self.urls = []

        for ecosystem in NAMESPACES:
            namespace = NAMESPACES[ecosystem]
            url = self._zip_base_url_ + ecosystem + "/all.zip"
            self.namespaces[namespace] = {
                "file": os.path.join(ws.input_path, ecosystem),
                "extract_path": os.path.join(ws.input_path, namespace),
                "url": url,
            }
            self.urls.append(url)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self) -> Generator[tuple[str, str, dict[str, dict[str, Any]]], None, None]:
        self._download()
        yield from self._normalize()

    @utils.retry_with_backoff()
    def _download(self) -> None:
        for namespace in self.namespaces:
            filepath = self.namespaces[namespace]["file"]
            url = self.namespaces[namespace]["url"]

            self.logger.info(f"downloading zipped vulnerability data from {url}")

            r = requests.get(url, timeout=self.download_timeout)
            r.raise_for_status()

            with open(filepath, "wb") as f:
                f.write(r.content)

    def _normalize(self) -> Generator[tuple[str, str, dict[str, dict[str, Any]]], None, None]:
        for namespace in self.namespaces:
            filepath = self.namespaces[namespace]["file"]
            extract_path = self.namespaces[namespace]["extract_path"]

            # Unzip contents and present flat file(s)
            with zipfile.ZipFile(filepath, "r") as z:
                z.extractall(extract_path)

            # Remove ZIP as not needed
            if os.path.isfile(filepath):
                os.remove(filepath)

            # Return file content(s)
            for json_file_path in Path(extract_path).glob("*.json"):
                with open(json_file_path, encoding="utf-8") as f:
                    # TODO - Map to OpenSourceVulnerability?

                    json_content = json.loads(f.read())
                    vuln_id = json_content["id"]

                    yield namespace, vuln_id, json_content
