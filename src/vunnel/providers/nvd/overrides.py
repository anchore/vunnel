from __future__ import annotations

import glob
import logging
import os
import threading
from typing import TYPE_CHECKING, Any

from orjson import loads

from vunnel.utils import archive
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from vunnel.workspace import Workspace


class NVDOverrides:
    __file_name__ = "nvd-overrides.tar.gz"
    __extract_name__ = "nvd-overrides"

    def __init__(  # noqa: PLR0913
        self,
        enabled: bool,
        url: str,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        retries: int = 5,
    ):
        self.enabled = enabled
        self.__url__ = url
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.retries = retries
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.__data_by_cve__: dict[str, Any] | None = None
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        return self.__url__

    def download(self) -> None:
        if not self.enabled:
            self.logger.debug("overrides are not enabled, skipping download...")
            return

        req = http.get(self.__url__, self.logger, stream=True, timeout=self.download_timeout, retries=self.retries)

        file_path = os.path.join(self.workspace.input_path, self.__file_name__)
        with open(file_path, "wb") as fp:
            for chunk in req.iter_content():
                fp.write(chunk)

        archive.extract(file_path, self._extract_path)

    @property
    def _extract_path(self) -> str:
        return os.path.join(self.workspace.input_path, self.__extract_name__)

    def _build_data_by_cve(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for path in glob.glob(os.path.join(self._extract_path, "**/data/**/", "CVE-*.json"), recursive=True):
            cve_id = os.path.basename(path).removesuffix(".json").upper()
            with open(path) as f:
                data[cve_id] = loads(f.read())
        return data

    def _ensure_loaded(self) -> dict[str, Any]:
        if self.__data_by_cve__ is None:
            with self._lock:
                if self.__data_by_cve__ is None:
                    self.__data_by_cve__ = self._build_data_by_cve()
        data = self.__data_by_cve__
        if data is None:
            raise RuntimeError("_build_data_by_cve returned None unexpectedly")
        return data

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None

        return self._ensure_loaded().get(cve_id.upper())

    def cves(self) -> list[str]:
        if not self.enabled:
            return []

        return list(self._ensure_loaded().keys())
