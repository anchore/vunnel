from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper
from vunnel.utils.vulnerability import FixAvailability, FixedIn, Vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel import workspace

SEVERITY_MAPPING = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}


class Parser:
    _input_file_ = "all.json"

    def __init__(
        self,
        ws: workspace.Workspace,
        url: str,
        timeout: int,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        self.workspace = ws
        self.url = url
        self.timeout = timeout
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        if logger is None:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.input_file_path = os.path.join(self.workspace.input_path, self._input_file_)

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self) -> None:
        """Download the all.json data from Arch Linux security tracker and save to disk."""
        self.fixdater.download()
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

    def _build_fixed_in_entries(
        self,
        packages: list[str],
        fixed_version: str,
        issues: list[str],
        group_id: str,
        ecosystem: str,
    ) -> list[FixedIn]:
        """Build FixedIn entries for each affected package."""
        fixed_in_list: list[FixedIn] = []
        for package_name in packages:
            if not package_name:
                continue

            available: FixAvailability | None = None
            if fixed_version:
                # Use CVE ID if available, otherwise use AVG ID
                vuln_id = issues[0] if issues else group_id
                result = self.fixdater.best(
                    vuln_id=vuln_id,
                    cpe_or_package=package_name,
                    fix_version=fixed_version,
                    ecosystem=ecosystem,
                )
                if result and result.date:
                    available = FixAvailability(
                        Date=result.date.isoformat(),
                        Kind=result.kind,
                    )

            fixed_in_list.append(
                FixedIn(
                    Name=package_name,
                    NamespaceName=ecosystem,
                    VersionFormat="pacman",
                    Version=fixed_version if fixed_version else "None",
                    Module=None,
                    VendorAdvisory=None,
                    Available=available,
                ),
            )
        return fixed_in_list

    def _build_metadata(self, issues: list[str], advisories: list[str]) -> dict[str, Any]:
        """Build metadata dict with CVEs and advisories."""
        metadata: dict[str, Any] = {}
        if issues:
            metadata["CVE"] = [{"Name": cve, "Link": f"https://nvd.nist.gov/vuln/detail/{cve}"} for cve in issues]
        if advisories:
            metadata["Advisories"] = advisories
        return metadata

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

                # Build FixedIn entries and metadata
                ecosystem = "arch:rolling"
                fixed_in_list = self._build_fixed_in_entries(packages, fixed_version, issues, group_id, ecosystem)
                metadata = self._build_metadata(issues, advisories)

                # Build the Vulnerability object
                vuln = Vulnerability(
                    Name=group_id,
                    NamespaceName=ecosystem,
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
