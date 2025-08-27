from __future__ import annotations

import copy
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from vunnel.workspace import Workspace

from .alma_errata_client import AlmaErrataClient


class AlmaParser:
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

        self.urls = self.errata_client.urls

    def download_alma_data(self) -> None:
        self.logger.info("downloading AlmaLinux errata data for RHEL provider")
        self.errata_client.delete_errata_files()
        self.errata_client.download()

    def _rhsa_to_alsa(self, rhsa_id: str) -> str:
        if rhsa_id.startswith("RHSA-"):
            return rhsa_id.replace("RHSA-", "ALSA-")
        if rhsa_id.startswith("RHBA-"):
            return rhsa_id.replace("RHBA-", "ALBA-")
        if rhsa_id.startswith("RHEA-"):
            return rhsa_id.replace("RHEA-", "ALEA-")
        return rhsa_id.replace("RH", "AL")

    def _normalize_rpm_version(self, version: str) -> str:
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

        package_version = self.errata_client.get_package_version(alsa_id=alma_advisory_id, version=version, package_name=package_name)

        if package_version:
            normalized_version = self._normalize_rpm_version(package_version)
            self.logger.debug(f"found Alma fix for {package_name} in {alma_advisory_id}: {normalized_version}")
            return normalized_version

        self.logger.debug(f"no fix found for package {package_name} in Alma advisory {alma_advisory_id}")
        return None

    def consensus_version(self, advisory_id: str) -> str | None:
        """
        Check if all packages referenced by an advisory are fixed at the same version.

        Args:
            advisory_id: Advisory ID (e.g., "ALSA-2022:6158" or "RHSA-2022:6158")

        Returns:
            The consensus version if all packages have the same version, None otherwise
        """
        # Convert RHSA to ALSA if needed
        alma_advisory_id = self._rhsa_to_alsa(advisory_id) if advisory_id.startswith(("RHSA-", "RHBA-", "RHEA-")) else advisory_id

        # Check all AlmaLinux versions for this advisory
        for version in self.alma_linux_versions:
            advisory_data = self.errata_client.get_advisory_data(alma_advisory_id, version)

            if advisory_data:
                # Get all package versions from this advisory
                package_versions = list(advisory_data.values())

                if not package_versions:
                    continue

                # Normalize all versions
                normalized_versions = [self._normalize_rpm_version(v) for v in package_versions]

                # Check if all versions are the same
                unique_versions = set(normalized_versions)
                if len(unique_versions) == 1:
                    return normalized_versions[0]
                # Found the advisory but packages have different versions
                return None

        # Advisory not found in any version
        return None


class AlmaVulnerabilityCreator:
    """Handles creation of AlmaLinux vulnerability records from RHEL records."""

    def __init__(self, alma_parser: AlmaParser | None = None, logger: logging.Logger | None = None):
        self.alma_parser = alma_parser

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def create_alma_vulnerability_copy(
        self,
        namespace: str,
        record: dict[str, dict[str, Any]],
        include_alma_fixes: bool = True,
    ) -> dict[str, dict[str, Any]] | None:
        """
        Create an Alma Linux copy of a RHEL vulnerability record if applicable. This method
        encodes several assumptions about how AlmaLinux tracks and applies fixes relative to RHEL, necessary
        because AlmaLinux advisories often have fewer packages listed than RHEL advisories, and in particular,
        RHEL disclosures often only name the source RPM as a vulnerable package, and AlmaLinux advisories often
        omit the source RPM as a fixed package. Depending on the availability of AlmaLinux advisories and
        and fix data for the particular package name, the following scenarios are handled in order, returning
        a new vulnerability record based on the first scenaqrio that applies:

        Applies transformations in priority order:
        1. AlmaLinux has A-prefixed advisory (always takes precedence) - use Alma version

        For example, https://errata.almalinux.org/8/ALSA-2025-A004.html represent the fact that
        AlmaLinux 8 patched https://access.redhat.com/security/cve/CVE-2025-6019 ahead of RHEL 8,
        specifically that libblockdev was patched at version 2.28-6.el8.alma.1, whereas RHEL didn't
        patch until 2.28-7.el8_10 (see https://access.redhat.com/errata/RHSA-2025:9878). Note also
        that the segment `el8.alma.1` indicates this is an AlmaLinux-specific package version.

            $ grype db search --vuln CVE-2025-6019 | rg ':8'
            CVE-2025-6019  libblockdev  rpm        almalinux:distro:almalinux:8   < 0:2.28-6.el8.alma.1
            CVE-2025-6019  libblockdev  rpm        redhat:distro:redhat:8         < 0:2.28-7.el8_10

        2. AlmaLinux has corresponding advisory with package entry - use Alma version

        This fixes a class of false positives where AlmaLinux and RHEL both fixed a package in a module,
        but because the version of RPMs that are part of an RPM module includes a build number, the versions
        are not comparable between RHEL and AlmaLinux. Generally, RHEL has higher builder numbers. For example,
        https://errata.almalinux.org/8/ALSA-2023-5259.html fixes mariadb from the 10.3 module
        at 10.3.39-1.module_el8.8.0+3609+204d4ab0 (note 3609 in the middle)
        while https://access.redhat.com/errata/RHSA-2023:5259 fixes mariadb for the 10.3 module at
        10.3.39-1.module+el8.8.0+19673+72b0d35f (note 19673 in the middle). Because 19673 > 3609, this would
        result in false positives because the patched version on AlmaLinux is actually lower than RHEL's.

            $ grype db search --vuln CVE-2022-32084 | rg ':8'
            CVE-2022-32084  mariadb  rpm        almalinux:distro:almalinux:8  < 3:10.3.39-1.module_el8.8.0+3609+204d4ab0
            CVE-2022-32084  mariadb  rpm        almalinux:distro:almalinux:8  < 3:10.5.22-1.module_el8.8.0+3620+5d452900
            CVE-2022-32084  mariadb  rpm        redhat:distro:redhat:8        < 3:10.3.39-1.module+el8.8.0+19673+72b0d35f
            CVE-2022-32084  mariadb  rpm        redhat:distro:redhat:8        < 3:10.5.22-1.module+el8.8.0+20134+a92c7654
            (one row for mariadb 10.3, one for mariadb 10.5)

            $ grype db search --vuln CVE-2007-4559 --pkg python38 | rg ':8'
            CVE-2007-4559  python38  rpm        almalinux:distro:almalinux:8  < 0:3.8.17-2.module_el8.9.0+3633+e453b53a
            CVE-2007-4559  python38  rpm        redhat:distro:redhat:8        < 0:3.8.17-2.module+el8.9.0+19642+a12b4af6

        3. AlmaLinux advisory exists and reports all packages were fixed at the same version, and there's
        substring commonality between the query package and the packages reported by the Alma advisory - use that version

        If all packages in the AlmaLinux advisory are fixed at the same version (consensus version),
        we use that consensus version for the missing package if there's substring commonality between
        the query package and the packages reported by the Alma advisory. Here is an example where
        there is substring commonality:

            $ grype db search --vuln CVE-2007-4559 --pkg python3 | rg ':8'
            CVE-2007-4559  python3  rpm        almalinux:distro:almalinux:8  < 0:3.6.8-56.el8_9.alma.1
            CVE-2007-4559  python3  rpm        redhat:distro:redhat:8        < 0:3.6.8-47.el8_6.4 (EUS)
            CVE-2007-4559  python3  rpm        redhat:distro:redhat:8        < 0:3.6.8-56.el8_9

        In this case, https://errata.almalinux.org/8/ALSA-2023-7151.html mentions many packages, but
        not python3 specifically. However, all packages were fixed at 3.6.8-56.el8_9.alma.1, AND there are
        packages that contain `python3` in their name, e.g. `python3-libs`, so we assume that python3 is also fixed
        at this version.

        The substgring commonality check is necessary to avoid triggering this logic for packages that are
        simply absent from the AlmaLinux advisory. For example, for CVE-2022-32891, the RHSA fixes two
        source RPMs, `glib2` at 2.56.4-159.el8 and webkit2gtk3 at 2.36.7-1.el8, see https://access.redhat.com/errata/RHSA-2022:7704,
        but the AlmaLinux advsiroy only mentions webkit2gtk3 variants, so even though the consensus version is 2.36.7-1.el8,
        we do not assume that glib2 is fixed at that version because there is no substring commonality between glib2 and the various
        package names on https://errata.almalinux.org/8/ALSA-2022-7704.html, e.g. `webkit2gtk3-jsc-devel`.

        4. Fall back to RHEL version - inherit RHEL version and advisory information

        This covers two scenarios: AlmaLinux has corresponding advisory but no package entry (and no consensus),
        or AlmaLinux has no corresponding advisory at all. In both cases, we make the assumption that if
        Red Hat fixed something, Alma has pulled in the fix. This assumption is necessary because there are
        numerous advisories where AlmaLinux has a shorter list of packages than RHEL, especially AlmaLinux will
        often omit the source RPM from the advisory, whereas RHEL data historically centers around the source RPM.
        For example, for https://access.redhat.com/security/cve/CVE-2007-4559, RHEL has a fix for "python3",
        specifically 'python3-3.6.8-56.el8_9.src.rpm' at https://access.redhat.com/errata/RHSA-2023:7151,
        but AlmaLinux does not have a package entry for "python3" at https://errata.almalinux.org/8/ALSA-2023-7151.html.
        Because AlmaLinux fixes a million python3 binary RPMs at 3.6.8-56.el8_9.alma.1, we assume that
        AlmaLinux has fixed the python3 package as well, even though it is not explicitly listed in the advisory.

            $ grype db search --vuln CVE-2007-4559 --pkg python3.11 | rg ':8'
            CVE-2007-4559  python3.11  rpm        almalinux:distro:almalinux:8  < 0:3.11.5-1.el8_9
            CVE-2007-4559  python3.11  rpm        redhat:distro:redhat:8        < 0:3.11.5-1.el8_9

        This assumption is important because Grype will match binary RPMs against vulnerabilities disclosed
        against their source RPM, so we have to assume that the source RPM is fixed.

        This also catches simple cases where there's no RHEL advisory, for example, https://access.redhat.com/security/cve/CVE-2005-2541
        is not fixed, so there's no AlmaLinux or RHEL advisory.

        This also happens when there is no equivalent ALSA even though there is an RHSA. For example,
        https://access.redhat.com/errata/RHSA-2019:3517, which fixes https://access.redhat.com/security/cve/CVE-2015-1593
        for the kernel, has no equivalent in ALSAs (https://errata.almalinux.org/8/ALSA-2019-3517.html is a 404).

            $ grype db search --vuln CVE-2015-1593 --pkg kernel | rg ':8'
            CVE-2015-1593  kernel   rpm        almalinux:distro:almalinux:8  < 0:4.18.0-147.el8
            CVE-2015-1593  kernel   rpm        redhat:distro:redhat:8        < 0:4.18.0-147.el8

        Args:
            namespace: The vulnerability namespace (e.g., "rhel:8")
            record: The vulnerability record dict
            include_alma_fixes: Whether to include AlmaLinux fixes

        Returns:
            Modified copy for Alma Linux if applicable, None otherwise
        """
        if not self._should_process_record(namespace, include_alma_fixes):
            return None

        alma_record = self._create_base_alma_record(record, namespace)
        rhel_version = namespace.split(":")[1]

        for i, fixed_in in enumerate(alma_record["Vulnerability"]["FixedIn"]):
            fixed_in["NamespaceName"] = f"almalinux:{rhel_version}"
            package_name = fixed_in["Name"]

            # Try each transformation in priority order matching docstring
            transformers = [
                self._try_alma_specific_advisory,
                self._try_corresponding_alma_advisory_with_package,
                self._try_alma_advisory_consensus_version,
                self._inherit_rhel_version,  # Always succeeds
            ]

            for transformer in transformers:
                transformed_fixed_in = transformer(fixed_in, rhel_version, package_name)
                if transformed_fixed_in is not None:
                    # Replace the fixed_in entry with the transformation result
                    alma_record["Vulnerability"]["FixedIn"][i] = transformed_fixed_in
                    break

        return alma_record

    def _should_process_record(self, namespace: str, include_alma_fixes: bool) -> bool:
        """Check if this record should be processed for AlmaLinux transformation."""
        if not include_alma_fixes:
            return False
        # Only process RHEL 8, 9, and 10
        return namespace in ["rhel:8", "rhel:9", "rhel:10"]

    def _create_base_alma_record(self, record: dict[str, dict[str, Any]], namespace: str) -> dict[str, dict[str, Any]]:
        """Create the base AlmaLinux record with updated namespace."""
        rhel_version = namespace.split(":")[1]
        alma_namespace = f"almalinux:{rhel_version}"

        # Create a deep copy of the record (expects {"Vulnerability": {...}})
        alma_record = copy.deepcopy(record)
        alma_record["Vulnerability"]["NamespaceName"] = alma_namespace
        return alma_record

    def _try_alma_specific_advisory(self, fixed_in: dict[str, Any], rhel_version: str, package_name: str) -> dict[str, Any] | None:
        """Case 1: AlmaLinux has A-prefixed advisory (always takes precedence) - use Alma version"""
        if not self.alma_parser:
            return None

        # Get all A-prefixed advisories for this version
        alma_specific_advisories = self.alma_parser.errata_client.get_alma_specific_advisories(rhel_version)

        # Check each A-prefixed advisory for this package
        for alsa_id, package_map in alma_specific_advisories.items():
            if package_name in package_map:
                alma_version = package_map[package_name]
                if alma_version:
                    # Normalize version
                    normalized_version = self.alma_parser._normalize_rpm_version(alma_version)  # noqa: SLF001

                    # Create complete new FixedIn record
                    new_fixed_in = copy.deepcopy(fixed_in)
                    new_fixed_in["Version"] = normalized_version
                    new_fixed_in["VendorAdvisory"] = {
                        "NoAdvisory": False,
                        "AdvisorySummary": [
                            {
                                "ID": alsa_id,
                                "Link": f"https://errata.almalinux.org/{rhel_version}/{alsa_id.replace(':', '-')}.html",
                            },
                        ],
                    }
                    return new_fixed_in
        return None

    def _try_corresponding_alma_advisory_with_package(self, fixed_in: dict[str, Any], rhel_version: str, package_name: str) -> dict[str, Any] | None:
        """Case 2: AlmaLinux has corresponding advisory with package entry - use Alma version"""
        if not self.alma_parser:
            return None

        vendor_advisory = fixed_in.get("VendorAdvisory", {})

        # Only proceed if RHEL has an advisory (not NoAdvisory=True)
        if vendor_advisory.get("NoAdvisory", False):
            return None

        advisory_summaries = vendor_advisory.get("AdvisorySummary", [])
        if not advisory_summaries:
            return None

        # Try to map each RHEL advisory to AlmaLinux
        for advisory in advisory_summaries:
            rhsa_id = advisory.get("ID", "")
            if not rhsa_id.startswith(("RHSA-", "RHBA-", "RHEA-")):
                continue

            # Convert RHSA to ALSA ID
            alma_advisory_id = rhsa_id.replace("RHSA-", "ALSA-").replace("RHBA-", "ALBA-").replace("RHEA-", "ALEA-")

            # Check if the AlmaLinux advisory exists at all
            alma_advisory_data = self.alma_parser.errata_client.get_advisory_data(alma_advisory_id, rhel_version)

            if alma_advisory_data is not None:
                # Advisory exists - now check if package is in it
                alma_fix_version = alma_advisory_data.get(package_name)

                if alma_fix_version:
                    # Case 2: AlmaLinux has corresponding advisory with package entry
                    normalized_version = self.alma_parser._normalize_rpm_version(alma_fix_version)  # noqa: SLF001

                    # Create complete new FixedIn record
                    new_fixed_in = copy.deepcopy(fixed_in)
                    new_fixed_in["Version"] = normalized_version

                    # Create updated advisory summary
                    updated_advisory = copy.deepcopy(advisory)
                    updated_advisory["ID"] = alma_advisory_id
                    alma_advisory_url_id = alma_advisory_id.replace(":", "-")
                    updated_advisory["Link"] = f"https://errata.almalinux.org/{rhel_version}/{alma_advisory_url_id}.html"

                    new_fixed_in["VendorAdvisory"] = {
                        **vendor_advisory,
                        "AdvisorySummary": [updated_advisory],
                    }
                    return new_fixed_in

        return None

    def _try_alma_advisory_consensus_version(
        self,
        fixed_in: dict[str, Any],
        rhel_version: str,
        package_name: str,
    ) -> dict[str, Any] | None:
        """Case 3: AlmaLinux advisory exists but no package entry, but all packages fixed at some version - use that version"""
        if not self.alma_parser:
            return None

        vendor_advisory = fixed_in.get("VendorAdvisory", {})

        # Only proceed if RHEL has an advisory (not NoAdvisory=True)
        if vendor_advisory.get("NoAdvisory", False):
            return None

        advisory_summaries = vendor_advisory.get("AdvisorySummary", [])
        if not advisory_summaries:
            return None

        # Try to map each RHEL advisory to AlmaLinux
        for advisory in advisory_summaries:
            rhsa_id = advisory.get("ID", "")
            if not rhsa_id.startswith(("RHSA-", "RHBA-", "RHEA-")):
                continue

            # Convert RHSA to ALSA ID
            alma_advisory_id = rhsa_id.replace("RHSA-", "ALSA-").replace("RHBA-", "ALBA-").replace("RHEA-", "ALEA-")

            # Check if the AlmaLinux advisory exists at all
            alma_advisory_data = self.alma_parser.errata_client.get_advisory_data(alma_advisory_id, rhel_version)

            if alma_advisory_data is not None:
                # Advisory exists - check if package is NOT in it (case 3)
                alma_fix_version = alma_advisory_data.get(package_name)

                if not alma_fix_version:
                    # Check for consensus version
                    consensus_ver = self.alma_parser.consensus_version(alma_advisory_id)
                    if consensus_ver and self._has_package_substring_commonality(package_name, alma_advisory_data.keys()):
                        # Use consensus version if there's substring commonality
                        new_fixed_in = copy.deepcopy(fixed_in)
                        new_fixed_in["Version"] = consensus_ver

                        # Create updated advisory summary
                        updated_advisory = copy.deepcopy(advisory)
                        updated_advisory["ID"] = alma_advisory_id
                        alma_advisory_url_id = alma_advisory_id.replace(":", "-")
                        updated_advisory["Link"] = f"https://errata.almalinux.org/{rhel_version}/{alma_advisory_url_id}.html"

                        new_fixed_in["VendorAdvisory"] = {
                            **vendor_advisory,
                            "AdvisorySummary": [updated_advisory],
                        }
                        return new_fixed_in

        return None

    def _has_package_substring_commonality(self, query_package: str, advisory_packages: Iterable[str]) -> bool:
        """
        Check if there's substring commonality between query package and advisory packages.

        Splits package names on '-' characters and checks if any segments from the query
        package appear in any of the advisory package names.

        Args:
            query_package: The package being queried (e.g., "python3", "glib2")
            advisory_packages: Package names from the AlmaLinux advisory

        Returns:
            True if there's substring commonality, False otherwise

        Examples:
            - query_package="python3", advisory_packages=["python3-libs", "python3-devel"] -> True
            - query_package="glib2", advisory_packages=["webkit2gtk3", "webkit2gtk3-jsc"] -> False
        """
        if not query_package or not advisory_packages:
            return False

        # Split query package into segments
        query_segments = set(query_package.split("-"))

        # Check if any query segments appear in any advisory package
        for advisory_package in advisory_packages:
            advisory_segments = set(advisory_package.split("-"))
            if query_segments & advisory_segments:  # Set intersection - any common segments
                return True

        return False

    def _inherit_rhel_version(self, fixed_in: dict[str, Any], _rhel_version: str, package_name: str) -> dict[str, Any]:
        """Case 4: AlmaLinux has no corresponding advisory - inherit RHEL version and NoAdvisory value"""
        vendor_advisory = fixed_in.get("VendorAdvisory", {})
        rhel_has_no_advisory = vendor_advisory.get("NoAdvisory", False)

        new_fixed_in = copy.deepcopy(fixed_in)

        if rhel_has_no_advisory:
            # Inherit RHEL's NoAdvisory=True decision
            # Keep the existing VendorAdvisory structure
            pass
        else:
            # RHEL has an advisory but no AlmaLinux advisory found
            rhel_version_constraint = fixed_in.get("Version")

            new_fixed_in["VendorAdvisory"] = {
                **vendor_advisory,
                "NoAdvisory": False,  # AlmaLinux doesn't make "won't-fix" commitments
            }

            # Remove advisory summaries since no AlmaLinux advisory exists
            if "AdvisorySummary" in new_fixed_in["VendorAdvisory"]:
                del new_fixed_in["VendorAdvisory"]["AdvisorySummary"]

            if rhel_version_constraint and rhel_version_constraint != "None":
                # Keep the RHEL version constraint - AlmaLinux likely uses the same fix
                self.logger.debug(f"Inheriting RHEL version constraint for {package_name}: {rhel_version_constraint}")
                # Version already copied from fixed_in
            else:
                # No RHEL fix available
                new_fixed_in["Version"] = "None"

        return new_fixed_in
