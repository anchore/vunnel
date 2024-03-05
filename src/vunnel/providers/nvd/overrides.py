import glob
import json
import logging
import os
import tarfile
from typing import Any

from vunnel.utils import http
from vunnel.workspace import Workspace


class NVDOverrides:
    __url__ = "http://localhost:8080/overrides.tar.gz"
    __file_name__ = "nvd-overrides.tar.gz"
    __extract_name__ = "nvd-overrides"

    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
    ):
        self.workspace = workspace
        self.download_timeout = download_timeout
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def url(self):
        return [self.__url__]

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

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        # TODO: implement in-memory index
        path = os.path.join(self.extract_path, "data", "nvd", "overrides", f"{cve_id.upper()}.json")
        if os.path.exists(path):
            with open(path) as f:
                return json.loads(f.read())
        return None

    def cves(self) -> list[str]:
        names = []
        for path in glob.glob(os.path.join(self.extract_path, "data", "nvd", "overrides", "CVE-*.json")):
            names.append(os.path.basename(path).replace(".json", ""))
        return names


def untar_file(file_path, extract_path):
    with tarfile.open(file_path, "r:gz") as tar:
        tar.extractall(path=extract_path)
