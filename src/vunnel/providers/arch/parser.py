from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.utils import http_wrapper
from vunnel.utils.vulnerability import FixedIn, Vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace

SEVERITY_MAPPING = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}


class Parser:
    _input_file_ = "all.json"

    def __init__(self, ws: workspace.Workspace, url: str, timeout: int, logger: logging.Logger | None = None):
        self.workspace = ws
        self.url = url
        self.timeout = timeout
        if logger is None:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.input_file_path = os.path.join(self.workspace.input_path, self._input_file_)

    def _download(self) -> None:
        """Download the all.json data from Arch Linux security tracker and save to disk."""
        self.logger.info(f"Downloading Arch Linux vulnerability data from {self.url}")

        response = http_wrapper.get(
            self.url,
            logger=self.logger,
            retries=3,
            backoff_in_seconds=2,
            timeout=self.timeout,
            user_agent="vunnel/1.0 (archlinux-provider)",
        )

        os.makedirs(self.workspace.input_path, exist_ok=True)

        with open(self.input_file_path, "wb") as f:
            f.write(orjson.dumps(response.json(), option=orjson.OPT_INDENT_2))

        self.logger.debug(f"Saved input data to {self.input_file_path}")

    def _load(self) -> list[dict[str, Any]]:
        """Load the all.json data from disk."""
        self.logger.debug(f"Loading data from {self.input_file_path}")
        with open(self.input_file_path, "rb") as f:
            return orjson.loads(f.read())

    def parse(self) -> Generator[tuple[str, dict[str, Any]]]:
        """Parse the Arch Linux security data and yield normalized vulnerability records."""
        self._download()
        data = self._load()

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
