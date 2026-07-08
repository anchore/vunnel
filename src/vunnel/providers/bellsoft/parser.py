from __future__ import annotations

import copy
import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

from .git import GitWrapper

# Default CVSS vector-string prefix to prepend for each OSV severity type when
# the score does not already carry a "CVSS:x.y/" prefix. Downstream consumers
# (e.g. grype-db) expect the full CVSS vector string including this prefix.
_CVSS_TYPE_PREFIXES = {
    "CVSS_V2": "CVSS:2.0/",
    "CVSS_V3": "CVSS:3.0/",
    "CVSS_V4": "CVSS:4.0/",
}


class Parser:
    _git_src_url_ = "https://github.com/bell-sw/osv-database.git"
    _git_src_branch_ = "master"

    def __init__(
        self,
        ws: Workspace,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.git_url = self._git_src_url_
        self.git_branch = self._git_src_branch_
        self.urls = [self.git_url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        _checkout_dst_ = os.path.join(self.workspace.input_path, "osv-database")
        self.git_wrapper = GitWrapper(
            source=self.git_url,
            branch=self.git_branch,
            checkout_dest=_checkout_dst_,
            logger=self.logger,
        )

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _load(self) -> Generator[dict[str, Any]]:
        self.logger.info("loading data from git repository")

        vuln_data_dir = os.path.join(self.workspace.input_path, "osv-database", "BELL-CVE")
        for root, dirs, files in os.walk(vuln_data_dir):
            dirs.sort()
            for file in sorted(files):
                if not file.endswith(".json"):
                    self.logger.debug(f"skipping non-JSON file: {file}")
                    continue
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, encoding="utf-8") as f:
                        yield orjson.loads(f.read())
                except orjson.JSONDecodeError:
                    # one malformed advisory in the upstream repo should not
                    # abort the whole provider run
                    self.logger.warning(f"skipping malformed advisory file: {full_path}")

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
        # Initialize the git repository
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()

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
