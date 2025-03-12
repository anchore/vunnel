from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace

from .git import GitWrapper

namespace = "bitnami"


class Parser:
    _git_src_url_ = "https://github.com/bitnami/vulndb.git"
    _git_src_branch_ = "main"

    def __init__(self, ws: Workspace, logger: logging.Logger | None = None):
        self.workspace = ws
        self.git_url = self._git_src_url_
        self.git_branch = self._git_src_branch_
        self.urls = [self.git_url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        _checkout_dst_ = os.path.join(self.workspace.input_path, "vulndb")
        self.git_wrapper = GitWrapper(
            source=self.git_url,
            branch=self.git_branch,
            checkout_dest=_checkout_dst_,
            logger=self.logger,
        )

    def _load(self) -> Generator[dict[str, Any], None, None]:
        self.logger.info("loading data from git repository")

        vuln_data_dir = os.path.join(self.workspace.input_path, "vulndb", "data")
        for root, dirs, files in os.walk(vuln_data_dir):
            dirs.sort()
            for file in sorted(files):
                full_path = os.path.join(root, file)
                with open(full_path, encoding="utf-8") as f:
                    yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]

        # We want to return the OSV record as it is (using OSV schema)
        # We'll transform it into the Grype-specific vulnerability schema
        # on grype-db
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry["schema_version"]
        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        # Initialize the git repository
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()

        # Load the data from the git repository
        for vuln_entry in self._load():
            # Normalize the loaded data
            yield self._normalize(vuln_entry)
