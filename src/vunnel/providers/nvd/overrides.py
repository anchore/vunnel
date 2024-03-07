import glob
import logging
import os
import tarfile
from typing import Any

from orjson import loads

from vunnel.utils import http
from vunnel.workspace import Workspace


class NVDOverrides:
    __file_name__ = "nvd-overrides.tar.gz"
    __extract_name__ = "nvd-overrides"

    def __init__(
        self,
        url: str,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
    ):
        self.__url__ = url
        self.workspace = workspace
        self.download_timeout = download_timeout
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.__filepaths_by_cve__ = None

    @property
    def url(self) -> str:
        return self.__url__

    def download(self):
        req = http.get(self.__url__, self.logger, stream=True, timeout=self.download_timeout)

        file_path = os.path.join(self.workspace.input_path, self.__file_name__)
        with open(file_path, "wb") as fp:
            for chunk in req.iter_content():
                fp.write(chunk)

        untar_file(file_path, self.extract_path)

    @property
    def extract_path(self):
        return os.path.join(self.workspace.input_path, self.__extract_name__)

    def _build_files_by_cve(self):
        self.__filepaths_by_cve__ = {}
        for path in glob.glob(os.path.join(self.extract_path, "**/data/**/", "CVE-*.json"), recursive=True):
            cve_id = os.path.basename(path).removesuffix(".json").upper()
            self.__filepaths_by_cve__[cve_id] = path

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        if self.__filepaths_by_cve__ is None:
            self._build_files_by_cve()
        # TODO: implement in-memory index
        path = self.__filepaths_by_cve__.get(cve_id.upper())
        if path and os.path.exists(path):
            with open(path) as f:
                return loads(f.read())
        return None

    def cves(self) -> list[str]:
        if self.__filepaths_by_cve__ is None:
            self._build_files_by_cve()
        return list(self.__filepaths_by_cve__.keys())


def untar_file(file_path, extract_path):
    with tarfile.open(file_path, "r:gz") as tar:
        tar.extractall(path=extract_path)
