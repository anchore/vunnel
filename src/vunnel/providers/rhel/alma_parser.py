from __future__ import annotations

import copy
import logging
from typing import TYPE_CHECKING, Any

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


class AlmaVulnerabilityCreator:
    """Handles creation of AlmaLinux vulnerability records from RHEL records."""

    def __init__(self, alma_parser: AlmaParser | None = None, logger: logging.Logger | None = None):
        self.alma_parser = alma_parser

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def create_alma_vulnerability_copy(  # noqa: C901, PLR0912
        self,
        namespace: str,
        record: dict[str, dict[str, Any]],
        include_alma_fixes: bool = True,
    ) -> dict[str, dict[str, Any]] | None:
        """
        Create an Alma Linux copy of a RHEL vulnerability record if applicable.

        Handles cases in priority order:
        1. AlmaLinux has A-prefixed advisory (always takes precedence) - use Alma version
        2. AlmaLinux has corresponding advisory with package entry - use Alma version
        3. AlmaLinux has corresponding advisory but no package entry - inherit RHEL version
        4. AlmaLinux has no corresponding advisory - inherit RHEL version
        5. RHEL has no fix and no AlmaLinux-specific fix - keep NoAdvisory=True

        Args:
            namespace: The vulnerability namespace (e.g., "rhel:8")
            record: The vulnerability record dict
            include_alma_fixes: Whether to include AlmaLinux fixes

        Returns:
            Modified copy for Alma Linux if applicable, None otherwise
        """
        if not include_alma_fixes:
            return None

        # Only process RHEL 8, 9, and 10
        if namespace not in ["rhel:8", "rhel:9", "rhel:10"]:
            return None

        rhel_version = namespace.split(":")[1]
        alma_namespace = f"almalinux:{rhel_version}"

        # Create a deep copy of the record (expects {"Vulnerability": {...}})
        alma_record = copy.deepcopy(record)
        alma_record["Vulnerability"]["NamespaceName"] = alma_namespace

        fixed_in_entries = alma_record["Vulnerability"]["FixedIn"]
        for fixed_in in fixed_in_entries:
            fixed_in["NamespaceName"] = alma_namespace

            package_name = fixed_in["Name"]
            vendor_advisory = fixed_in.get("VendorAdvisory", {})
            rhel_has_no_advisory = vendor_advisory.get("NoAdvisory", False)

            # Always check for AlmaLinux-specific advisories (A-prefixed) first
            if self.alma_parser:
                alma_a_fix_found = self._check_alma_specific_advisories(package_name, rhel_version, fixed_in)
                if alma_a_fix_found:
                    continue  # Successfully found Alma-specific fix, skip other logic

            # Case 1: RHEL has no fix and no Alma-specific fix was found
            if rhel_has_no_advisory:
                # Keep NoAdvisory = True (RHEL behavior) since no Alma-specific fix exists
                continue

            # Cases 2, 3, 4: RHEL has advisory, check AlmaLinux corresponding advisory
            advisory_summaries = vendor_advisory.get("AdvisorySummary", [])
            if not advisory_summaries:
                # No RHEL advisory info, can't map to Alma advisory
                fixed_in["Version"] = "None"
                # Keep NoAdvisory = False since AlmaLinux doesn't make "won't-fix" commitments
                if "AdvisorySummary" in fixed_in["VendorAdvisory"]:
                    del fixed_in["VendorAdvisory"]["AdvisorySummary"]
                continue

            alma_advisory_found = False
            for advisory in advisory_summaries:
                rhsa_id = advisory.get("ID", "")
                if not rhsa_id.startswith(("RHSA-", "RHBA-", "RHEA-")):
                    continue

                if self.alma_parser:
                    # Convert RHSA to ALSA ID
                    alma_advisory_id = rhsa_id.replace("RHSA-", "ALSA-").replace("RHBA-", "ALBA-").replace("RHEA-", "ALEA-")

                    # Check if the AlmaLinux advisory exists at all
                    alma_advisory_data = self.alma_parser.errata_client.get_advisory_data(alma_advisory_id, rhel_version)

                    if alma_advisory_data is not None:
                        # Advisory exists - now check if package is in it
                        alma_fix_version = alma_advisory_data.get(package_name)

                        if alma_fix_version:
                            # Case 3: AlmaLinux has corresponding advisory with package entry
                            normalized_version = self.alma_parser._normalize_rpm_version(alma_fix_version)  # noqa: SLF001
                            fixed_in["Version"] = normalized_version
                        # else: Case 2: Advisory exists but no package entry - keep RHEL version

                        alma_advisory_found = True

                        # Update advisory metadata
                        advisory["ID"] = alma_advisory_id
                        alma_advisory_url_id = alma_advisory_id.replace(":", "-")
                        advisory["Link"] = f"https://errata.almalinux.org/{rhel_version}/{alma_advisory_url_id}.html"
                        break
                    # else: Advisory doesn't exist - continue to Case 4 logic

            # Case 4: No corresponding AlmaLinux advisory found
            if not alma_advisory_found:
                # Inherit the RHEL version constraint if it exists and is not "None"
                rhel_version_constraint = fixed_in.get("Version")
                if rhel_version_constraint and rhel_version_constraint != "None":
                    # Keep the RHEL version constraint - AlmaLinux likely uses the same fix
                    self.logger.debug(f"Inheriting RHEL version constraint for {package_name}: {rhel_version_constraint}")
                    # Keep the existing Version field (inherit from RHEL)
                else:
                    # No RHEL fix available
                    fixed_in["Version"] = "None"

                # Keep NoAdvisory = False since AlmaLinux doesn't make "won't-fix" commitments
                # Remove advisory summaries since no AlmaLinux advisory exists
                if "AdvisorySummary" in fixed_in["VendorAdvisory"]:
                    del fixed_in["VendorAdvisory"]["AdvisorySummary"]

        return alma_record

    def _check_alma_specific_advisories(self, package_name: str, rhel_version: str, fixed_in: dict[str, Any]) -> bool:
        """
        Check for AlmaLinux-specific advisories (A-prefixed) when RHEL has no fix.

        Returns:
            True if Alma-specific fix found and applied, False otherwise
        """
        if not self.alma_parser:
            return False

        # Get all A-prefixed advisories for this version
        alma_specific_advisories = self.alma_parser.errata_client.get_alma_specific_advisories(rhel_version)

        # Check each A-prefixed advisory for this package
        for alsa_id, package_map in alma_specific_advisories.items():
            if package_name in package_map:
                alma_version = package_map[package_name]
                if alma_version:
                    # Normalize version
                    normalized_version = self.alma_parser._normalize_rpm_version(alma_version)  # noqa: SLF001
                    fixed_in["Version"] = normalized_version
                    fixed_in["VendorAdvisory"] = {
                        "NoAdvisory": False,
                        "AdvisorySummary": [
                            {
                                "ID": alsa_id,
                                "Link": f"https://errata.almalinux.org/{rhel_version}/{alsa_id.replace(':', '-')}.html",
                            },
                        ],
                    }
                    return True

        return False
