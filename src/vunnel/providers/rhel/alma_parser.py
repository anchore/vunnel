from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import orjson

if TYPE_CHECKING:
    from vunnel.workspace import Workspace

from .alma_git import AlmaGitWrapper


class AlmaParser:
    _git_src_url_ = "https://github.com/AlmaLinux/osv-database.git"
    _git_src_branch_ = "master"

    def __init__(self, workspace: Workspace, logger: logging.Logger | None = None, alma_linux_versions: list[str] | None = None):
        if alma_linux_versions is None:
            alma_linux_versions = ["8", "9", "10"]
        self.alma_linux_versions = alma_linux_versions
        self.workspace = workspace
        self.git_url = self._git_src_url_
        self.git_branch = self._git_src_branch_
        self.urls = [self.git_url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self._checkout_dst = os.path.join(self.workspace.input_path, "alma-osv-database")
        self.git_wrapper = AlmaGitWrapper(
            source=self.git_url,
            branch=self.git_branch,
            checkout_dest=self._checkout_dst,
            logger=self.logger,
        )

    def download_alma_data(self) -> None:
        self.logger.info("downloading Alma Linux OSV database for RHEL provider")
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()

    def _rhsa_to_alsa(self, rhsa_id: str) -> str:
        if rhsa_id.startswith("RHSA-"):
            return rhsa_id.replace("RHSA-", "ALSA-")
        if rhsa_id.startswith("RHBA-"):
            return rhsa_id.replace("RHBA-", "ALBA-")
        if rhsa_id.startswith("RHEA-"):
            return rhsa_id.replace("RHEA-", "ALEA-")
        return rhsa_id.replace("RH", "AL")

    def _get_alma_advisory_file_path(self, alma_advisory_id: str, version: str) -> str:
        return os.path.join(
            self._checkout_dst,
            "advisories",
            f"almalinux{version}",
            f"{alma_advisory_id}.json",
        )

    def _normalize_rpm_version(self, version: str) -> str:
        """Add explicit epoch of '0:' if version doesn't already have one."""
        if version and ":" not in version:
            return f"0:{version}"
        return version

    def get_alma_fix_version(self, rhsa_id: str, version: str, package_name: str) -> str | None:
        alma_advisory_id = self._rhsa_to_alsa(rhsa_id)
        file_path = self._get_alma_advisory_file_path(alma_advisory_id, version)

        if not os.path.exists(file_path):
            self.logger.debug(f"Alma advisory file not found: {file_path}")
            return None

        try:
            with open(file_path, encoding="utf-8") as f:
                advisory_data = orjson.loads(f.read())

            affected = advisory_data.get("affected", [])
            for affected_item in affected:
                package = affected_item.get("package", {})
                if package.get("name") == package_name:
                    ranges = affected_item.get("ranges", [])
                    for range_item in ranges:
                        events = range_item.get("events", [])
                        for event in events:
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                normalized_version = self._normalize_rpm_version(fixed_version)
                                self.logger.debug(f"Found Alma fix for {package_name} in {alma_advisory_id}: {normalized_version}")
                                return normalized_version

        except Exception as e:
            self.logger.warning(f"Failed to parse Alma advisory file {file_path}: {e}")
            return None

        self.logger.debug(f"No fix found for package {package_name} in Alma advisory {alma_advisory_id}")
        return None
