from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import orjson

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from vunnel.workspace import Workspace


class AlmaErrataClient:
    """HTTP-based client for AlmaLinux errata.json files"""

    def __init__(self, workspace: Workspace, logger: logging.Logger | None = None, alma_linux_versions: list[str] | None = None):
        if alma_linux_versions is None:
            alma_linux_versions = ["8", "9", "10"]
        self.alma_linux_versions = alma_linux_versions
        self.workspace = workspace
        self.base_url = "https://errata.almalinux.org"
        self.urls = [f"{self.base_url}/{version}/errata.json" for version in alma_linux_versions]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self._data_dir = os.path.join(self.workspace.input_path, "alma-errata-data")
        self._alma_index: dict[str, dict[str, dict[str, str]]] = {}

    def delete_errata_files(self) -> None:
        if os.path.exists(self._data_dir):
            import shutil

            shutil.rmtree(self._data_dir)

    def download(self) -> None:
        os.makedirs(self._data_dir, exist_ok=True)

        for version in self.alma_linux_versions:
            self._download_errata_file(version)

        self._build_index()

    def _download_errata_file(self, version: str) -> None:
        url = f"{self.base_url}/{version}/errata.json"
        output_path = os.path.join(self._data_dir, f"errata-{version}.json")

        self.logger.info(f"downloading AlmaLinux {version} errata from {url}")

        response = http.get(url, logger=self.logger, timeout=300)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            f.write(response.content)

        self.logger.debug(f"downloaded {len(response.content)} bytes to {output_path}")

    def _build_index(self) -> None:
        self.logger.info("building AlmaLinux errata index for fast lookups")

        for version in self.alma_linux_versions:
            errata_file = os.path.join(self._data_dir, f"errata-{version}.json")

            if not os.path.exists(errata_file):
                self.logger.warning(f"errata file not found: {errata_file}")
                continue

            try:
                with open(errata_file, "rb") as f:
                    errata_data = orjson.loads(f.read())

                version_index = {}
                advisory_count = 0
                package_count = 0

                for advisory in errata_data:
                    alsa_id = advisory.get("updateinfo_id", "")
                    if not alsa_id.startswith(("ALSA-", "ALBA-", "ALEA-")):
                        continue

                    advisory_count += 1
                    package_map = {}

                    pkglist = advisory.get("pkglist", {})
                    packages = pkglist.get("packages", [])

                    for package in packages:
                        pkg_name = package.get("name")
                        if not pkg_name:
                            continue

                        epoch = package.get("epoch", "0")
                        pkg_version = package.get("version", "")
                        release = package.get("release", "")

                        if pkg_version and release:
                            full_version = f"{epoch}:{pkg_version}-{release}"
                            package_map[pkg_name] = full_version
                            package_count += 1

                    if package_map:
                        version_index[alsa_id] = package_map

                self._alma_index[version] = version_index
                self.logger.info(f"indexed AlmaLinux {version}: {advisory_count} advisories, {package_count} packages")

            except Exception as e:
                self.logger.error(f"failed to parse errata file {errata_file}: {e}")
                self._alma_index[version] = {}

    def get_advisory_data(self, alsa_id: str, version: str) -> dict[str, str] | None:
        """
        Get package data for a specific ALSA advisory.

        Args:
            alsa_id: Advisory ID (e.g., "ALSA-2022:6158")
            version: AlmaLinux version ("8", "9", "10")

        Returns:
            Dictionary mapping package names to full version strings, or None if not found
        """
        if version not in self._alma_index:
            return None

        return self._alma_index[version].get(alsa_id)

    def get_package_version(self, alsa_id: str, version: str, package_name: str) -> str | None:
        advisory_data = self.get_advisory_data(alsa_id, version)
        if not advisory_data:
            return None
        return advisory_data.get(package_name)

    def get_alma_specific_advisories(self, version: str) -> dict[str, dict[str, str]]:
        """
        Get all AlmaLinux-specific (A-prefixed) advisories for a given version.

        Returns:
            Dict mapping ALSA IDs to package maps: {alsa_id: {package_name: version}}
        """
        if version not in self._alma_index:
            return {}

        alma_specific = {}
        version_data = self._alma_index[version]

        for alsa_id, package_map in version_data.items():
            # Check if this is an AlmaLinux-specific advisory (A-prefixed)
            # Match patterns like ALSA-YYYY:AXXXXX, ALBA-YYYY:AXXXXX, ALEA-YYYY:AXXXXX
            if ":" in alsa_id:
                advisory_number = alsa_id.split(":", 1)[1]
                if advisory_number.startswith("A"):
                    alma_specific[alsa_id] = package_map

        return alma_specific
