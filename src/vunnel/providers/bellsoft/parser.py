from __future__ import annotations

import copy
import logging
import os
import re
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

# This constant lives in parser.py so the parser does not import the package __init__.
PINNED_OSV_SCHEMA_VERSION = "1.7.5"

# The OSV schema requires a version prefix on CVSS_V3 and CVSS_V4 scores.
# It forbids one on CVSS_V2, so CVSS_V2 has no entry here.
_CVSS_TYPE_PREFIXES = {
    "CVSS_V3": "CVSS:3.0/",
    "CVSS_V4": "CVSS:4.0/",
}

# The id becomes the result identifier (a filename in the flat-file store), so
# this also rules out path separators.
_ID_PATTERN = re.compile(r"BELL-[A-Za-z0-9._-]+")


class Parser:
    # A tarball download avoids a dependency on the git binary and the host's git config.
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

        # A zero-result run is a no-op in the framework, so a missing archive
        # must fail loudly rather than silently keep serving stale data.
        if not os.path.exists(self._archive_path()):
            raise FileNotFoundError(f"no downloaded archive to load at {self._archive_path()}")

        # Members are streamed and never extracted to disk.
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
                    self.logger.warning(f"skipping malformed advisory file: {member.name}")

    def _normalize_severities(self, vuln_entry: dict[str, Any]) -> dict[str, Any]:
        # Upstream ships ~18k third-party files. Structurally odd input passes
        # through unchanged so a single bad advisory does not abort the run.
        severities = vuln_entry.get("severity")
        if not severities or not isinstance(severities, list):
            return vuln_entry

        normalized = copy.deepcopy(vuln_entry)
        for severity in normalized["severity"]:
            if not isinstance(severity, dict):
                continue
            score = severity.get("score", "")
            if not score or not isinstance(score, str):
                continue
            # The schema patterns are anchored and case-sensitive, so stray
            # whitespace or a lowercase "cvss:" would otherwise get a second prefix.
            score = score.strip()
            if score[:5].upper() == "CVSS:":
                severity["score"] = "CVSS:" + score[5:]
                continue
            prefix = _CVSS_TYPE_PREFIXES.get(severity.get("type", ""))
            severity["score"] = prefix + score if prefix else score

        return normalized

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        # grype-db transforms the OSV record, so it passes through as-is here.
        vuln_entry = self._normalize_severities(vuln_entry)
        vuln_id = vuln_entry["id"]
        # A missing schema_version takes the pinned default. A present but
        # malformed value passes through, so update() skips the record.
        vuln_schema = vuln_entry.get("schema_version", PINNED_OSV_SCHEMA_VERSION)

        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        self._download()

        self.fixdater.download()

        # Withdrawn advisories are ~26% of the corpus, so one summary replaces a
        # log line per record.
        withdrawn = 0
        # update() lowercases ids into result identifiers, so ids that differ
        # only in case would overwrite each other.
        seen: set[str] = set()

        for vuln_entry in self._load():
            vuln_id = vuln_entry.get("id") if isinstance(vuln_entry, dict) else None
            if not isinstance(vuln_id, str) or not _ID_PATTERN.fullmatch(vuln_id):
                self.logger.warning(f"skipping advisory with missing or invalid id: {vuln_id!r}")
                continue
            if "withdrawn" in vuln_entry:
                withdrawn += 1
                continue
            try:
                osv.patch_fix_date(vuln_entry, self.fixdater)
                normalized = self._normalize(vuln_entry)
            except (AttributeError, TypeError) as e:
                self.logger.warning(f"skipping malformed advisory {vuln_id}: {e!r}")
                continue
            if vuln_id.lower() in seen:
                self.logger.warning(f"skipping advisory {vuln_id}: its id duplicates an earlier one when lowercased")
                continue
            seen.add(vuln_id.lower())
            yield normalized

        if withdrawn:
            self.logger.info(f"skipped {withdrawn} withdrawn advisories")
