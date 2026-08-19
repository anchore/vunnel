from __future__ import annotations

import copy
import logging
import os
import tarfile
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

# Default CVSS vector-string prefix to prepend for each OSV severity type when
# the score does not already carry a "CVSS:x.y/" prefix. Downstream consumers
# (e.g. grype-db) expect the full CVSS vector string including this prefix.
_CVSS_TYPE_PREFIXES = {
    "CVSS_V2": "CVSS:2.0/",
    "CVSS_V3": "CVSS:3.0/",
    "CVSS_V4": "CVSS:4.0/",
}


class Parser:
    # an unauthenticated archive download (rather than a git clone) avoids any
    # dependency on a git binary or the host's git configuration
    _download_url_ = "https://github.com/bell-sw/osv-database/archive/refs/heads/master.tar.gz"
    _archive_name_ = "osv-database.tar.gz"

    def __init__(
        self,
        ws: Workspace,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.download_timeout = download_timeout
        self.urls = [self._download_url_]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _archive_path(self) -> str:
        return os.path.join(self.workspace.input_path, self._archive_name_)

    def _download(self) -> None:
        self.logger.info(f"downloading vulnerability data from {self._download_url_}")
        req = http.get(self._download_url_, self.logger, stream=True, timeout=self.download_timeout)
        with open(self._archive_path(), "wb") as fp:
            for chunk in req.iter_content(chunk_size=65536):
                fp.write(chunk)

    def _load(self) -> Generator[dict[str, Any]]:
        self.logger.info("loading data from downloaded archive")

        if not os.path.exists(self._archive_path()):
            self.logger.warning("no downloaded archive to load")
            return

        # stream advisories straight out of the tarball rather than extracting
        # ~16k small files to disk; members are never written out, so hostile
        # member paths (traversal, symlinks) have nothing to act on. the github
        # archive nests content under a "<repo>-<branch>/" top-level directory.
        with tarfile.open(self._archive_path(), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile() or "BELL-CVE" not in member.name.split("/"):
                    continue
                if not member.name.endswith(".json"):
                    self.logger.debug(f"skipping non-JSON file: {member.name}")
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                try:
                    yield orjson.loads(fh.read())
                except orjson.JSONDecodeError:
                    # one malformed advisory in the upstream repo should not
                    # abort the whole provider run
                    self.logger.warning(f"skipping malformed advisory file: {member.name}")

    def _normalize_severities(self, vuln_entry: dict[str, Any]) -> dict[str, Any]:
        # Normalize CVSS severity vector strings so that each carries a
        # "CVSS:x.y/" prefix appropriate to its type. If a score already has a
        # "CVSS:" prefix (e.g. "CVSS:3.1/...") it is preserved as-is. Empty
        # scores and entries without severities are left untouched. The input
        # entry is not mutated; a copy is returned.
        severities = vuln_entry.get("severity")
        if not severities:
            return vuln_entry

        normalized = copy.deepcopy(vuln_entry)
        for severity in normalized["severity"]:
            score = severity.get("score", "")
            if not score or score.startswith("CVSS:"):
                continue
            prefix = _CVSS_TYPE_PREFIXES.get(severity.get("type", ""))
            if prefix:
                severity["score"] = prefix + score

        return normalized

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        # We want to return the OSV record as it is (using OSV schema)
        # We'll transform it into the Grype-specific vulnerability schema
        # on grype-db
        vuln_entry = self._normalize_severities(vuln_entry)
        vuln_id = vuln_entry["id"]
        # missing schema_version only matters for its major version: the provider
        # maps any same-major value to its own pinned schema
        vuln_schema = vuln_entry.get("schema_version", "1.0.0")

        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        self._download()

        self.fixdater.download()

        for vuln_entry in self._load():
            if not isinstance(vuln_entry, dict) or not vuln_entry.get("id"):
                self.logger.warning("skipping advisory without an id")
            elif "withdrawn" in vuln_entry:
                self.logger.debug(f"skipping withdrawn entry: {vuln_entry['id']}")
            else:
                # annotate each affected range with first-observed fix dates
                # (database_specific.anchore.fixes), which grype-db surfaces as
                # fix availability
                osv.patch_fix_date(vuln_entry, self.fixdater)
                # Normalize the loaded data. Note: CVSS_V2 severities are kept
                # deliberately — _normalize_severities gives their bare vectors
                # the "CVSS:2.0/" prefix that downstream consumers (grype-db)
                # require to parse them.
                yield self._normalize(vuln_entry)
