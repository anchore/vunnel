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

    def __init__(  # noqa: PLR0913
        self,
        enabled: bool,
        url: str,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
    ):
        self.enabled = enabled
        self.__url__ = url
        self.workspace = workspace
        self.download_timeout = download_timeout
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.__filepaths_by_cve__: dict[str, str] = {}

    @property
    def url(self) -> str:
        return self.__url__

    def download(self) -> None:
        if not self.enabled:
            self.logger.debug("overrides are not enabled, skipping download...")
            return

        req = http.get(self.__url__, self.logger, stream=True, timeout=self.download_timeout)

        file_path = os.path.join(self.workspace.input_path, self.__file_name__)
        with open(file_path, "wb") as fp:
            for chunk in req.iter_content():
                fp.write(chunk)

        untar_file(file_path, self._extract_path)

    @property
    def _extract_path(self) -> str:
        return os.path.join(self.workspace.input_path, self.__extract_name__)

    def _build_files_by_cve(self) -> None:
        filepaths_by_cve__: dict[str, str] = {}
        for path in glob.glob(os.path.join(self._extract_path, "**/data/**/", "CVE-*.json"), recursive=True):
            cve_id = os.path.basename(path).removesuffix(".json").upper()
            filepaths_by_cve__[cve_id] = path

        self.__filepaths_by_cve__ = filepaths_by_cve__

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None

        if self.__filepaths_by_cve__ is None:
            self._build_files_by_cve()

        # TODO: implement in-memory index
        path = self.__filepaths_by_cve__.get(cve_id.upper())
        if path and os.path.exists(path):
            with open(path) as f:
                return loads(f.read())
        return None

    def cves(self) -> list[str]:
        if not self.enabled:
            return []

        if self.__filepaths_by_cve__ is None:
            self._build_files_by_cve()
        return list(self.__filepaths_by_cve__.keys())


def untar_file(file_path: str, extract_path: str) -> None:
    with tarfile.open(file_path, "r:gz") as tar:

        def filter_path_traversal(tarinfo: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
            # we do not expect any relative file paths that would result in the clean
            # path being different from the original path
            # e.g.
            #  expected:   results/results.db
            #  unexpected: results/../../../../etc/passwd
            # we filter (drop) any such entries

            if path != os.path.normpath(path):
                return None
            return tarinfo

        # note: we have a filter that drops any entries that would result in a path traversal
        # which is what S202 is referring to (linter isn't smart enough to understand this)
        tar.extractall(path=extract_path, filter=filter_path_traversal)  # noqa: S202
