from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vunnel.workspace import Workspace

from .alma_errata_client import AlmaErrataClient


class AlmaParser:
    """AlmaLinux parser using HTTP-based errata.json files"""

    def __init__(self, workspace: Workspace, logger: logging.Logger | None = None, alma_linux_versions: list[str] | None = None):
        if alma_linux_versions is None:
            alma_linux_versions = ["8", "9", "10"]
        self.alma_linux_versions = alma_linux_versions
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self.errata_client = AlmaErrataClient(
            workspace=workspace,
            logger=logger,
            alma_linux_versions=alma_linux_versions,
        )

        # Expose URLs for compatibility
        self.urls = self.errata_client.urls

    def download_alma_data(self) -> None:
        """Download and index AlmaLinux errata data"""
        self.logger.info("downloading AlmaLinux errata data for RHEL provider")
        self.errata_client.delete_errata_files()
        self.errata_client.download()

    def _rhsa_to_alsa(self, rhsa_id: str) -> str:
        """Convert RHSA ID to ALSA ID"""
        if rhsa_id.startswith("RHSA-"):
            return rhsa_id.replace("RHSA-", "ALSA-")
        if rhsa_id.startswith("RHBA-"):
            return rhsa_id.replace("RHBA-", "ALBA-")
        if rhsa_id.startswith("RHEA-"):
            return rhsa_id.replace("RHEA-", "ALEA-")
        return rhsa_id.replace("RH", "AL")

    def _normalize_rpm_version(self, version: str) -> str:
        """Add explicit epoch of '0:' if version doesn't already have one."""
        if version and ":" not in version:
            return f"0:{version}"
        return version

    def get_alma_fix_version(self, rhsa_id: str, version: str, package_name: str) -> str | None:
        """
        Get AlmaLinux fix version for a package using fast in-memory lookup.

        Args:
            rhsa_id: Red Hat advisory ID (e.g., "RHSA-2022:6158")
            version: RHEL/AlmaLinux version ("8", "9", "10")
            package_name: Package name (e.g., "php")

        Returns:
            Normalized version string with explicit epoch, or None if not found
        """
        alma_advisory_id = self._rhsa_to_alsa(rhsa_id)

        # Fast O(1) lookup using in-memory index
        package_version = self.errata_client.get_package_version(alsa_id=alma_advisory_id, version=version, package_name=package_name)

        if package_version:
            normalized_version = self._normalize_rpm_version(package_version)
            self.logger.debug(f"found Alma fix for {package_name} in {alma_advisory_id}: {normalized_version}")
            return normalized_version

        self.logger.debug(f"no fix found for package {package_name} in Alma advisory {alma_advisory_id}")
        return None

