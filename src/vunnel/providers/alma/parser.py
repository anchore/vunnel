from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace

from .git import GitWrapper

_known_library_gaps_ = {
    "ALSA-2019:3706": {"lua": "lua-libs"},
    "ALSA-2020:5487": {"pacemaker": "pacemaker-libs"},
    "ALSA-2021:4386": {"gcc": "libgcc"},
    "ALSA-2021:4393": {"cups": "cups-libs"},
    "ALSA-2021:4489": {"rpm-build": "rpm-build-libs"},
    "ALSA-2021:4587": {"gcc": "libgcc"},
    "ALSA-2022:0368": {"rpm-build": "rpm-build-libs"},
    "ALSA-2022:7928": {"device-mapper-multipath": "device-mapper-multipath-libs"},
}


class Parser:
    _git_src_url_ = "https://github.com/AlmaLinux/osv-database.git"
    _git_src_branch_ = "master"

    # Known library package gaps in AlmaLinux advisories
    # Some ALSAs are missing library packages that are available in the repos but not mentioned in the advisory
    # TODO: Remove once AlmaLinux fixes these gaps upstream
    # Last audit: 2025-10-14

    def __init__(self, ws: Workspace, logger: logging.Logger | None = None, alma_linux_versions: list[str] | None = None):
        if alma_linux_versions is None:
            alma_linux_versions = ["8", "9", "10"]
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

    def _load(self, version: str) -> Generator[dict[str, Any]]:
        self.logger.info("loading data from git repository")

        # TODO: almalinux8 and almalinux9 subdirectories
        vuln_data_dir = os.path.join(self.workspace.input_path, "osv-database", "advisories", f"almalinux{version}")
        for root, dirs, files in os.walk(vuln_data_dir):
            dirs.sort()
            for file in sorted(files):
                full_path = os.path.join(root, file)
                with open(full_path, encoding="utf-8") as f:
                    yield orjson.loads(f.read())

    def _add_missing_library_packages(self, vuln_entry: dict[str, Any]) -> None:
        """Add missing library packages to advisories that have known gaps.

        Some ALSAs omit library packages that are available in repos but not mentioned in the advisory.
        This causes false positives when those library packages are installed.
        We temporarily fix this in vunnel until AlmaLinux fixes the upstream data.
        """
        vuln_id = vuln_entry.get("id")
        if not vuln_id or vuln_id not in _known_library_gaps_:
            return

        gaps = _known_library_gaps_[vuln_id]
        if "affected" not in vuln_entry:
            return

        # Find the affected entries for base packages and clone them for library packages
        for affected_pkg in list(vuln_entry["affected"]):  # Use list() to avoid modifying during iteration
            pkg_name = affected_pkg.get("package", {}).get("name")
            if pkg_name in gaps:
                library_pkg_name = gaps[pkg_name]

                # Check if library package already exists
                existing_names = {p.get("package", {}).get("name") for p in vuln_entry["affected"]}
                if library_pkg_name in existing_names:
                    continue

                # Clone the affected entry for the library package
                library_affected = affected_pkg.copy()
                library_affected["package"] = affected_pkg["package"].copy()
                library_affected["package"]["name"] = library_pkg_name

                # Add to affected list
                vuln_entry["affected"].append(library_affected)
                self.logger.debug(f"Added missing library package '{library_pkg_name}' to {vuln_id} (base package: {pkg_name})")

    def _normalize(self, vuln_entry: dict[str, Any], version: str) -> tuple[str, str, dict[str, Any]]:
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]

        # We want to return the OSV record as it is (using OSV schema)
        # We'll transform it into the Grype-specific vulnerability schema
        # on grype-db
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry.get("schema_version", "1.7.0")  # TODO: this is a bit of a hack;
        # we should see whether upstream is willing to put schema versions in the data.

        # Parse modularity from summary field
        rpm_modularity = None
        summary = vuln_entry.get("summary", "")
        if summary:
            rpm_modularity = self._parse_modularity_from_summary(summary)

        # Add modularity to affected packages if found
        if rpm_modularity and "affected" in vuln_entry:
            for affected_pkg in vuln_entry["affected"]:
                if "ecosystem_specific" not in affected_pkg:
                    affected_pkg["ecosystem_specific"] = {}
                affected_pkg["ecosystem_specific"]["rpm_modularity"] = rpm_modularity

        # Add missing library packages for known advisory gaps
        self._add_missing_library_packages(vuln_entry)

        # Add anchore-specific metadata to indicate this is an advisory record
        if "database_specific" not in vuln_entry:
            vuln_entry["database_specific"] = {}
        if "anchore" not in vuln_entry["database_specific"]:
            vuln_entry["database_specific"]["anchore"] = {}
        vuln_entry["database_specific"]["anchore"]["record_type"] = "advisory"

        return os.path.join(f"almalinux{version}", vuln_id), vuln_schema, vuln_entry

    def _parse_modularity_from_summary(self, summary: str) -> str | None:
        """Parse modularity information from OSV summary field.

        Expected format: '<Severity>: <module_name>:<module_version> security update'
        Examples:
        - 'Moderate: mariadb:10.3 security update'
        - 'Important: nodejs:16 security update'
        """
        if not summary:
            return None

        # Find first space (after severity)
        first_space = summary.find(" ")
        if first_space == -1:
            return None

        # Find second space (after colon and module info)
        second_space = summary.find(" ", first_space + 1)
        if second_space == -1:
            return None

        # Extract the module info between first and second space
        module_info = summary[first_space + 1 : second_space].strip()

        # Check if it has the colon pattern for modularity
        if ":" in module_info and not module_info.startswith(":") and not module_info.endswith(":"):
            return module_info

        return None

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        # Initialize the git repository
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()
        for version in self.alma_linux_versions:
            for vuln_entry in self._load(version):
                # Normalize the loaded data
                yield self._normalize(vuln_entry, version)
