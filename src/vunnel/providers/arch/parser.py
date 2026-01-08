from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from vunnel.utils import http_wrapper
from vunnel.utils.vulnerability import FixedIn, Vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

SEVERITY_MAPPING = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}


class Parser:
    def __init__(self, url: str, timeout: int, logger: logging.Logger | None = None):
        self.url = url
        self.timeout = timeout
        if logger is None:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _fetch(self) -> list[dict[str, Any]]:
        """Fetch the all.json data from Arch Linux security tracker with retry logic."""
        self.logger.info(f"Fetching Arch Linux vulnerability data from {self.url}")

        response = http_wrapper.get(
            self.url,
            logger=self.logger,
            retries=3,
            backoff_in_seconds=2,
            timeout=self.timeout,
            user_agent="vunnel/1.0 (archlinux-provider)",
        )

        self.logger.debug(f"Successfully fetched data from {self.url}")
        return response.json()

    def parse(self) -> Generator[tuple[str, dict[str, Any]]]:
        """Parse the Arch Linux security data and yield normalized vulnerability records."""
        data = self._fetch()

        if not isinstance(data, list):
            self.logger.error(f"Expected list from all.json, got {type(data)}")
            raise ValueError("Invalid data format from all.json: expected list")

        self.logger.info(f"Processing {len(data)} vulnerability records")

        for record in data:
            try:
                # The AVG ID is in the "name" field (e.g., "AVG-2843")
                group_id = record.get("name", "").strip()
                if not group_id:
                    self.logger.warning("Skipping record with missing name field")
                    continue

                # Skip "Not affected" entries - these are tracked but don't represent actual vulnerabilities
                status = record.get("status", "").strip()
                if status == "Not affected":
                    self.logger.debug(f"Skipping {group_id}: status is 'Not affected'")
                    continue

                # Extract fields from the record
                packages = record.get("packages", [])
                fixed_version = record.get("fixed") or ""
                fixed_version = fixed_version.strip() if fixed_version else ""
                severity = record.get("severity", "").strip()
                vuln_type = record.get("type", "").strip()
                issues = record.get("issues", [])
                advisories = record.get("advisories", [])

                # Normalize severity
                mapped_severity = SEVERITY_MAPPING.get(severity, "Unknown")

                # Build FixedIn entries for each affected package
                # Use "None" as version for unfixed vulnerabilities
                fixed_in_list: list[FixedIn] = []
                for package_name in packages:
                    if package_name:
                        fixed_in_list.append(
                            FixedIn(
                                Name=package_name,
                                NamespaceName="arch:rolling",
                                VersionFormat="pacman",
                                Version=fixed_version if fixed_version else "None",
                                Module=None,
                                VendorAdvisory=None,
                            ),
                        )

                # Build metadata with CVEs and advisories
                metadata: dict[str, Any] = {}
                if issues:
                    metadata["CVE"] = [{"Name": cve, "Link": f"https://nvd.nist.gov/vuln/detail/{cve}"} for cve in issues]
                if advisories:
                    metadata["Advisories"] = advisories

                # Build the Vulnerability object
                vuln = Vulnerability(
                    Name=group_id,
                    NamespaceName="arch:rolling",
                    Description=vuln_type or f"Arch vulnerability {group_id}",
                    Severity=mapped_severity,
                    Link=f"https://security.archlinux.org/{group_id}",
                    CVSS=[],
                    FixedIn=fixed_in_list,
                    Metadata=metadata,
                )

                self.logger.debug(f"Processed vulnerability {group_id}")

                # Yield the normalized record with group_id as the identifier
                yield group_id.lower(), vuln.to_payload()

            except Exception:
                self.logger.exception("Error processing vulnerability record")
                # Continue processing other records on error
                continue
