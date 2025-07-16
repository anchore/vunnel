from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vunnel import provider, result, schema

from .parser import Parser

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    parallelism: int = 4
    full_sync_interval: int = 2  # in days
    skip_namespaces: list[str] = field(default_factory=lambda: ["rhel:3", "rhel:4"])
    rhsa_source: str = "CSAF"  # "CSAF" or "OVAL"
    ignore_hydra_errors: bool = False
    include_alma_fixes: bool = True


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            max_workers=self.config.parallelism,
            full_sync_interval=self.config.full_sync_interval,
            rhsa_provider_type=self.config.rhsa_source,
            ignore_hydra_errors=self.config.ignore_hydra_errors,
            skip_namespaces=self.config.skip_namespaces,
            logger=self.logger,
            skip_download=self.config.runtime.skip_download,
            include_alma_fixes=self.config.include_alma_fixes,
        )

    @classmethod
    def name(cls) -> str:
        return "rhel"

    @classmethod
    def supports_skip_download(cls) -> bool:
        return True

    def create_alma_vulnerability_copy(self, namespace: str, record: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]] | None:
        """
        Create an Alma Linux copy of a RHEL vulnerability record if applicable.

        Handles cases in priority order:
        1. AlmaLinux has A-prefixed advisory (always takes precedence) - use Alma version
        2. AlmaLinux has corresponding advisory with package entry - use Alma version
        3. AlmaLinux has corresponding advisory but no package entry - inherit RHEL version
        4. AlmaLinux has no corresponding advisory - set Version="None", NoAdvisory=False
        5. RHEL has no fix and no AlmaLinux-specific fix - keep NoAdvisory=True

        Args:
            namespace: The vulnerability namespace (e.g., "rhel:8")
            record: The vulnerability record dict

        Returns:
            Modified copy for Alma Linux if applicable, None otherwise
        """
        if not self.config.include_alma_fixes:
            return None

        # Only process RHEL 8, 9, and 10
        # TODO: replace with a list computed from what directories alma has
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
            # These should take precedence over both RHEL fixes and corresponding advisories
            if self.parser.alma_parser:
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

                if self.parser.alma_parser:
                    # Convert RHSA to ALSA ID
                    alma_advisory_id = rhsa_id.replace("RHSA-", "ALSA-").replace("RHBA-", "ALBA-").replace("RHEA-", "ALEA-")

                    # Check if the AlmaLinux advisory exists at all
                    alma_advisory_data = self.parser.alma_parser.errata_client.get_advisory_data(alma_advisory_id, rhel_version)

                    if alma_advisory_data is not None:
                        # Advisory exists - now check if package is in it
                        alma_fix_version = alma_advisory_data.get(package_name)

                        if alma_fix_version:
                            # Case 3: AlmaLinux has corresponding advisory with package entry
                            normalized_version = self.parser.alma_parser._normalize_rpm_version(alma_fix_version)
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
        if not self.parser.alma_parser:
            return False

        # In a real implementation, we would search through all Alma advisories
        # for A-prefixed ones that contain the package. For now, we'll check
        # if there's a direct lookup by trying common A-prefixed patterns.

        # This is a simplified approach - in practice you'd need to iterate through
        # all Alma advisories looking for A-prefixed ones with the package
        alma_advisories = self.parser.alma_parser.errata_client._alma_index.get(rhel_version, {})

        for alsa_id, package_map in alma_advisories.items():
            if ":A" in alsa_id and package_name in package_map:
                # Found Alma-specific advisory with this package
                alma_version = package_map[package_name]
                if alma_version:
                    # Normalize version
                    normalized_version = self.parser.alma_parser._normalize_rpm_version(alma_version)
                    fixed_in["Version"] = normalized_version
                    fixed_in["VendorAdvisory"] = {
                        "NoAdvisory": False,
                        "AdvisorySummary": [
                            {
                                "ID": alsa_id,
                                "Link": f"https://errata.almalinux.org/{rhel_version}/{alsa_id.replace(':', '-')}.html",
                            }
                        ],
                    }
                    return True

        return False

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        # Download Alma data if needed
        self.parser.download_alma_data()

        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                namespace = namespace.lower()
                vuln_id = vuln_id.lower()

                # Write the original RHEL record
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.__schema__,
                    payload=record,
                )

                # If applicable, create and write Alma copy
                alma_record = self.create_alma_vulnerability_copy(namespace, record)
                if alma_record:
                    alma_namespace = alma_record["Vulnerability"]["NamespaceName"]
                    writer.write(
                        identifier=os.path.join(alma_namespace, vuln_id),
                        schema=self.__schema__,
                        payload=alma_record,
                    )
        if len(writer) == 0 and self.config.runtime.skip_download:
            raise RuntimeError("skip download used on empty workspace")
        return self.parser.urls, len(writer)
