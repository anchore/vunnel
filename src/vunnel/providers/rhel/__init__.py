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

        Args:
            namespace: The vulnerability namespace (e.g., "rhel:8")
            record: The vulnerability record dict

        Returns:
            Modified copy for Alma Linux if applicable, None otherwise
        """
        if not self.config.include_alma_fixes:
            return None

        # Only process RHEL 8, 9, and 10
        # TODO: relace with a list computed from what directories alma has
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

            if vendor_advisory.get("NoAdvisory", True):
                # RHEL has wont-fix, Alma has no fix either
                continue

            advisory_summaries = vendor_advisory.get("AdvisorySummary", [])
            alma_fix_found = False

            for advisory in advisory_summaries:
                rhsa_id = advisory.get("ID", "")
                if not rhsa_id.startswith(("RHSA-", "RHBA-", "RHEA-")):
                    continue

                if self.parser.alma_parser:
                    alma_fix_version = self.parser.alma_parser.get_alma_fix_version(
                        rhsa_id,
                        rhel_version,
                        package_name,
                    )

                    if alma_fix_version:
                        # Use AlmaLinux version if available
                        fixed_in["Version"] = alma_fix_version
                    # If no AlmaLinux version found, inherit RHEL version (keep existing value)

                    # Convert advisory links regardless of whether AlmaLinux version was found
                    alma_advisory_id = rhsa_id.replace("RHSA-", "ALSA-").replace("RHBA-", "ALBA-").replace("RHEA-", "ALEA-")
                    advisory["ID"] = alma_advisory_id
                    alma_advisory_url_id = alma_advisory_id.replace(":", "-")
                    advisory["Link"] = f"https://errata.almalinux.org/{rhel_version}/{alma_advisory_url_id}.html"

                    alma_fix_found = True
                    break

            # Note: Removed the logic that sets Version="None" for missing AlmaLinux data
            # Now we inherit RHEL version constraints and only convert advisory metadata

        return alma_record

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
