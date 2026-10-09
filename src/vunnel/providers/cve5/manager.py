from __future__ import annotations

import fnmatch
import logging
import os
import tarfile
import zlib
from typing import TYPE_CHECKING

import orjson

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Generator
    from typing import Any

    from vunnel.workspace import Workspace


class Manager:
    __file_name__ = "cvelistV5.tar.gz"

    def __init__(
        self,
        url: str,
        workspace: Workspace,
        download_timeout: int = 125,
        user_agent: str | None = None,
        logger: logging.Logger | None = None,
    ):
        self.url = url
        self.urls = [url]
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.user_agent = user_agent
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download(self) -> str:
        path = os.path.join(self.workspace.input_path, self.__file_name__)
        kwargs: dict[str, Any] = {}
        if self.user_agent:
            kwargs["user_agent"] = self.user_agent
        http.download_to_file(self.url, path, self.logger, timeout=self.download_timeout, **kwargs)
        return path

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """download the archive and yield (identifier, record) for each CVE-*.json member, unchanged."""
        path = self._download()
        count = 0
        try:
            # stream mode reads the archive once without extracting it to disk
            with tarfile.open(path, mode="r|gz") as tar:
                for member in tar:
                    if not member.isfile() or not fnmatch.fnmatch(os.path.basename(member.name), "CVE-*.json"):
                        continue
                    fh = tar.extractfile(member)
                    if fh is None:
                        continue
                    try:
                        record = orjson.loads(fh.read())
                    except orjson.JSONDecodeError as e:
                        raise ValueError(f"{member.name} in {self.url} is not valid JSON") from e
                    count += 1
                    yield cve_to_id(record["cveMetadata"]["cveId"]), record
        except (tarfile.TarError, EOFError, zlib.error) as e:
            raise ValueError(f"unable to read archive from {self.url}: {e}") from e

        if count == 0:
            raise ValueError(f"no CVE-*.json records found in archive from {self.url}")


def cve_to_id(cve: str) -> str:
    """convert a CVE identifier to the hierarchical storage path the nvd provider uses.

    Example: CVE-2023-1234 -> "2023/cve-2023-1234"
    """
    year = cve.split("-")[1]
    return os.path.join(year, cve).lower()
