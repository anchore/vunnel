from __future__ import annotations

import fnmatch
import logging
import os
import tarfile
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import orjson
import zstandard
from packageurl import PackageURL

from vunnel.tool import fixdate
from vunnel.utils import hasher
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType
    from typing import Any

    from vunnel.workspace import Workspace


class Manager:
    __file_name__ = "cve5.tar.zst"

    def __init__(  # noqa: PLR0913
        self,
        url: str,
        workspace: Workspace,
        download_timeout: int = 125,
        user_agent: str | None = None,
        logger: logging.Logger | None = None,
        fixdater: fixdate.Finder | None = None,
    ):
        self.url = url
        self.urls = [url]
        self.archive_url = url
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.user_agent = user_agent
        self.fixdater = fixdater or fixdate.default_finder(workspace)
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Manager:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

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
        """download the archive named by the manifest and yield (identifier, record) for each CVE-*.json member.

        Records are unchanged apart from the x_observedFixDates lists added to their containers.
        """
        self.fixdater.download()
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
                    yield cve_to_id(record["cveMetadata"]["cveId"]), self._apply_fix_dates(record)
        except (tarfile.TarError, EOFError, zstandard.ZstdError) as e:
            raise ValueError(f"unable to read archive from {self.archive_url}: {e}") from e

        if count == 0:
            raise ValueError(f"no CVE-*.json records found in archive from {self.archive_url}")

    def _apply_fix_dates(self, record: dict[str, Any]) -> dict[str, Any]:
        """add an x_observedFixDates list to each container with a fix bound.

        The bounds are the affected versions[] items with a lessThan (other than "*") and the vulnerable
        cpeApplicability matches with a versionEndExcluding. A lessThanOrEqual states no fix, so it gets no entry.
        """
        cve_id = record["cveMetadata"]["cveId"]
        containers = record.get("containers", {})
        for container in [containers.get("cna", {}), *containers.get("adp", [])]:
            entries = [e for bound in _bounds(container, cve_id, self.logger) if (e := self._observed(cve_id, *bound))]
            if entries:
                container["x_observedFixDates"] = entries
        return record

    def _observed(self, cve_id: str, locator: dict[str, str], lookup: str, ecosystem: str | None, fix_version: str) -> dict[str, str] | None:
        result = self.fixdater.best(vuln_id=cve_id, cpe_or_package=lookup, fix_version=fix_version, ecosystem=ecosystem)
        if not result or not result.date:
            return None
        return {**locator, "fixVersion": fix_version, "date": result.date.isoformat(), "kind": result.kind}


def _bounds(container: dict[str, Any], cve_id: str, logger: logging.Logger) -> Generator[tuple[dict[str, str], str, str | None, str]]:
    """yield (locator as stated, lookup key, ecosystem, fix version) for each fix bound in a container."""
    for affected in container.get("affected", []):
        purl = affected.get("packageURL")
        name = affected.get("packageName")
        if purl:
            # the purl is the locator as stated; the lookup key drops its version (the bound's job), qualifiers and subpath
            locator = {"packageURL": purl}
            try:
                parsed = PackageURL.from_string(purl)
            except ValueError as e:
                # a CNA's malformed purl must not stop the run, it just has nothing to date
                logger.warning(f"skipping fix dates for unparseable purl {purl!r} in {cve_id}: {e}")
                continue
            lookup = parsed._replace(version=None, qualifiers=None, subpath=None).to_string()
            ecosystem = parsed.type
        elif name:
            locator = {k: affected[k] for k in ("collectionURL",) if affected.get(k)} | {"packageName": name}
            lookup, ecosystem = name, None
        else:
            # nothing to key a date by (kernel commit ranges, for one)
            continue
        for version in affected.get("versions", []):
            fix_version = version.get("lessThan")
            # an unaffected item states no vulnerable range, so it has no fix to date
            if version.get("status") == "affected" and fix_version and fix_version != "*":
                yield locator, lookup, ecosystem, fix_version

    yield from _cpe_bounds(container)


def _cpe_bounds(container: dict[str, Any]) -> Generator[tuple[dict[str, str], str, str | None, str]]:
    """yield a bound for each vulnerable cpeApplicability match with a versionEndExcluding, keyed by its criteria."""
    for config in container.get("cpeApplicability", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if match.get("vulnerable") and match.get("versionEndExcluding") and criteria.startswith("cpe:"):
                    yield {"criteria": criteria}, criteria, None, match["versionEndExcluding"]


def cve_to_id(cve: str) -> str:
    """convert a CVE identifier to the hierarchical storage path the nvd provider uses.

    Example: CVE-2023-1234 -> "2023/cve-2023-1234"
    """
    year = cve.split("-")[1]
    return os.path.join(year, cve).lower()
