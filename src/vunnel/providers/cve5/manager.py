from __future__ import annotations

import fnmatch
import logging
import os
import tarfile
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import orjson
import zstandard

from vunnel.utils import hasher
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Generator
    from typing import Any

    from vunnel.workspace import Workspace


class Manager:
    __file_name__ = "cve5.tar.zst"

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
        self.archive_url = url
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.user_agent = user_agent
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _kwargs(self) -> dict[str, Any]:
        return {"user_agent": self.user_agent} if self.user_agent else {}

    def _manifest(self) -> tuple[str, str]:
        """fetch the manifest at self.url and return (archive url, expected sha256 hex digest)."""
        response = http.get(self.url, self.logger, timeout=self.download_timeout, **self._kwargs())
        try:
            manifest = response.json()
        except ValueError as e:
            raise ValueError(f"manifest at {self.url} is not valid JSON") from e
        if not isinstance(manifest, dict) or not all(isinstance(manifest.get(k), str) for k in ("path", "checksum")):
            raise ValueError(f"manifest at {self.url} is not a JSON object with string 'path' and 'checksum'")
        return urljoin(self.url, manifest["path"]), manifest["checksum"].removeprefix("sha256:")

    def _download(self) -> str:
        archive_url, checksum = self._manifest()
        path = os.path.join(self.workspace.input_path, self.__file_name__)
        http.download_to_file(archive_url, path, self.logger, timeout=self.download_timeout, **self._kwargs())
        actual = hasher.Method.SHA256.digest(path, label=False)
        if actual != checksum:
            raise ValueError(f"checksum mismatch for archive {archive_url}: manifest has {checksum}, downloaded file has {actual}")
        self.urls = [self.url, archive_url]
        self.archive_url = archive_url
        return path

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """download the archive named by the manifest and yield (identifier, record) for each CVE-*.json member, unchanged."""
        path = self._download()
        count = 0
        try:
            # stream mode reads the archive once without extracting it to disk
            with (
                open(path, "rb") as ifh,
                zstandard.ZstdDecompressor(max_window_size=2147483648).stream_reader(ifh, read_across_frames=True) as reader,
                tarfile.open(fileobj=reader, mode="r|") as tar,
            ):
                for member in tar:
                    if not member.isfile() or not fnmatch.fnmatch(os.path.basename(member.name), "CVE-*.json"):
                        continue
                    fh = tar.extractfile(member)
                    if fh is None:
                        continue
                    try:
                        record = orjson.loads(fh.read())
                    except orjson.JSONDecodeError as e:
                        raise ValueError(f"{member.name} in {self.archive_url} is not valid JSON") from e
                    count += 1
                    yield cve_to_id(record["cveMetadata"]["cveId"]), record
        except (tarfile.TarError, EOFError, zstandard.ZstdError) as e:
            raise ValueError(f"unable to read archive from {self.archive_url}: {e}") from e

        if count == 0:
            raise ValueError(f"no CVE-*.json records found in archive from {self.archive_url}")


def cve_to_id(cve: str) -> str:
    """convert a CVE identifier to the hierarchical storage path the nvd provider uses.

    Example: CVE-2023-1234 -> "2023/cve-2023-1234"
    """
    year = cve.split("-")[1]
    return os.path.join(year, cve).lower()
