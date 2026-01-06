from __future__ import annotations

import copy
import logging
from typing import TYPE_CHECKING, Generator

from vunnel.utils import http_wrapper
from vunnel.utils.vulnerability import vulnerability_element

if TYPE_CHECKING:
    pass

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

    def _fetch(self) -> list[dict]:
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

    def parse(self) -> Generator[tuple[str, dict], None, None]:
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

                # Extract fields from the record
                packages = record.get("packages", [])
                fixed_version = record.get("fixed") or ""
                fixed_version = fixed_version.strip() if fixed_version else ""
                severity = record.get("severity", "").strip()
                status = record.get("status", "").strip()
                vuln_type = record.get("type", "").strip()
                issues = record.get("issues", [])
                advisories = record.get("advisories", [])

                # Normalize severity
                mapped_severity = SEVERITY_MAPPING.get(severity, "Unknown")

                # Build the vulnerability payload
                payload = copy.deepcopy(vulnerability_element)

                vuln = payload["Vulnerability"]
                vuln["Name"] = group_id
                vuln["NamespaceName"] = "arch:rolling"
                vuln["Description"] = vuln_type or f"Arch vulnerability {group_id}"
                vuln["Severity"] = mapped_severity
                vuln["Link"] = f"https://security.archlinux.org/{group_id}"

                # Add FixedIn entry for each affected package
                # Use "None" as version for unfixed vulnerabilities
                for package_name in packages:
                    if package_name:
                        fixed_in = {
                            "Name": package_name,
                            "Version": fixed_version if fixed_version else "None",
                            "VersionFormat": "pacman",
                            "NamespaceName": "arch:rolling",
                        }
                        vuln["FixedIn"].append(fixed_in)

                # Add metadata with CVEs and advisories
                # CVE format must be array of {Name, Link} objects for grype-db
                metadata = {}
                if issues:
                    metadata["CVE"] = [{"Name": cve, "Link": f"https://nvd.nist.gov/vuln/detail/{cve}"} for cve in issues]
                if advisories:
                    metadata["Advisories"] = advisories

                if metadata:
                    vuln["Metadata"] = metadata
                else:
                    # Remove empty Metadata if there's no content
                    del vuln["Metadata"]

                self.logger.debug(f"Processed vulnerability {group_id}")

                # Yield the normalized record with group_id as the identifier
                yield group_id.lower(), payload

            except Exception as e:
                self.logger.error(f"Error processing vulnerability record: {e}", exc_info=True)
                # Continue processing other records on error
                continue
