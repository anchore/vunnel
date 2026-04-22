from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import yaml

from vunnel.tool import fixdate
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

from .git import GitWrapper

# Default OSV schema version to use when not specified in the YAML file
_DEFAULT_SCHEMA_VERSION_ = "1.6.1"

# Repository directory name for the R advisory database
_REPO_DIR_NAME_ = "r-advisory-database"


class Parser:
    _git_src_url_ = "https://github.com/RConsortium/r-advisory-database.git"
    _git_src_branch_ = "main"

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
        self.urls = [self._git_src_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        checkout_dest = os.path.join(self.workspace.input_path, _REPO_DIR_NAME_)
        self.git_wrapper = GitWrapper(
            source=self.git_url,
            branch=self.git_branch,
            checkout_dest=checkout_dest,
            logger=self.logger,
        )

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _load(self) -> Generator[dict[str, Any]]:
        self.logger.info(f"loading data from git repository {self.git_url}")

        vuln_data_dir = os.path.join(self.workspace.input_path, _REPO_DIR_NAME_, "vulns")
        for root, dirs, files in os.walk(vuln_data_dir):
            dirs.sort()
            for file in sorted(files):
                if not file.endswith(".yaml"):
                    continue
                full_path = os.path.join(root, file)
                with open(full_path, encoding="utf-8") as f:
                    try:
                        yield yaml.safe_load(f)
                    except yaml.YAMLError as e:
                        self.logger.warning(f"failed to parse YAML file {full_path}: {e}")
                        continue

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]

        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry.get("schema_version", _DEFAULT_SCHEMA_VERSION_)

        # RSEC YAML files use "upstream" for CVE references, but OSV schema uses "aliases".
        # Normalize by moving upstream values to aliases.
        if "upstream" in vuln_entry:
            upstream = vuln_entry.pop("upstream")
            if upstream:
                existing_aliases = vuln_entry.get("aliases") or []
                for cve in upstream:
                    if cve not in existing_aliases:
                        existing_aliases.append(cve)
                vuln_entry["aliases"] = existing_aliases

        # Prepend canonical references. grype-db uses the first reference URL as the
        # dataSource field, so the advisory database link should come first.
        canonical_refs: list[dict[str, str]] = []
        affected = vuln_entry.get("affected")
        if affected:
            package_name = affected[0].get("package", {}).get("name")
            if package_name:
                advisory_url = self.git_url.removesuffix(".git")
                canonical_refs.append({
                    "type": "ADVISORY",
                    "url": f"{advisory_url}/blob/{self.git_branch}/vulns/{package_name}/{vuln_id}.yaml",
                })
        canonical_refs.append({
            "type": "WEB",
            "url": f"https://osv.dev/vulnerability/{vuln_id}",
        })

        existing_refs = vuln_entry.get("references") or []
        vuln_entry["references"] = canonical_refs + existing_refs

        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        # Initialize the git repository
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()

        self.fixdater.download()

        # Load the data from the git repository
        for vuln_entry in self._load():
            if vuln_entry is None:
                continue
            # Normalize the loaded data
            osv.patch_fix_date(vuln_entry, self.fixdater)
            yield self._normalize(vuln_entry)
