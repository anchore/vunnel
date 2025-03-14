from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace

from .git import GitWrapper


class Parser:
    _git_src_url_ = "https://github.com/AlmaLinux/osv-database.git"
    _git_src_branch_ = "master"

    def __init__(self, ws: Workspace, logger: logging.Logger | None = None, alma_linux_versions: list[str] | None = None):
        if alma_linux_versions is None:
            alma_linux_versions = ["8", "9"]
        self.alma_linux_versions = alma_linux_versions
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

    def _load(self, version: str) -> Generator[dict[str, Any], None, None]:
        self.logger.info("loading data from git repository")

        # TODO: almalinux8 and almalinux9 subdirectories
        vuln_data_dir = os.path.join(self.workspace.input_path, "osv-database", "advisories", f"almalinux{version}")
        for root, dirs, files in os.walk(vuln_data_dir):
            dirs.sort()
            for file in sorted(files):
                full_path = os.path.join(root, file)
                with open(full_path, encoding="utf-8") as f:
                    yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any], version: str) -> tuple[str, str, dict[str, Any]]:
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]

        # We want to return the OSV record as it is (using OSV schema)
        # We'll transform it into the Grype-specific vulnerability schema
        # on grype-db
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry.get("schema_version", "1.7.0")  # TODO: this is a bit of a hack;
        # we should see whether upstream is willing to put schema versions in the data.
        return os.path.join(f"almalinux{version}", vuln_id), vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        # Initialize the git repository
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()
        for version in self.alma_linux_versions:
            for vuln_entry in self._load(version):
                # Normalize the loaded data
                yield self._normalize(vuln_entry, version)
