from __future__ import annotations

import concurrent.futures
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Any

import orjson
import requests

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
        # Cache for ASA advisory dates, populated by _prefetch_asa_dates.
        # Thread-safe: single dict operations (get/set) are atomic in CPython due to the GIL.
        self._asa_date_cache: dict[str, str | None] = {}

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

    def _fetch_and_cache_asa_date(self, asa_id: str) -> None:
        """Fetch publication date for an ASA advisory and store in cache.

        This method is called during prefetch only. It fetches the date from the
        Arch Linux security tracker and caches it for later lookup.
        """
        # Validate ASA ID format before constructing URL (defensive check)
        if not re.match(r"^ASA-\d{6}-\d+$", asa_id):
            self.logger.warning(f"Unexpected ASA ID format: {asa_id}")
            self._asa_date_cache[asa_id] = None
            return

        url = f"https://security.archlinux.org/{asa_id}/raw"
        try:
            response = http_wrapper.get(
                url,
                logger=self.logger,
                retries=3,
                backoff_in_seconds=3,
                timeout=self.timeout,
                user_agent="vunnel/1.0 (archlinux-provider; +https://github.com/anchore/vunnel)",
            )
            # Parse date from plain text format: "Date    : 2021-06-22"
            text = response.text
            match = re.search(r"^Date\s*:\s*(\d{4}-\d{2}-\d{2})", text, re.MULTILINE)
            self._asa_date_cache[asa_id] = match.group(1) if match else None
        except (requests.RequestException, http_wrapper.CircuitOpenError):
            self.logger.debug(f"Failed to fetch ASA {asa_id}, will use first-observed fallback")
            self._asa_date_cache[asa_id] = None

    def _get_cached_asa_date(self, asa_id: str) -> str | None:
        """Get ASA date from cache. Returns None if not found or fetch failed."""
        return self._asa_date_cache.get(asa_id)

    def _get_best_asa_date(self, advisories: list[str]) -> str | None:
        """Get earliest ASA date from list of advisories (cache lookup only)."""
        if not advisories:
            return None
        dates = [d for asa in advisories if (d := self._get_cached_asa_date(asa))]
        return min(dates) if dates else None

    def _prefetch_asa_dates(self, data: list[dict[str, Any]], max_workers: int = 2, batch_size: int = 10) -> None:
        """Prefetch all ASA dates with rate limiting to respect server limits.

        This must be called before processing records. After this method completes,
        all ASA dates are available via _get_cached_asa_date().
        """
        # Collect all unique ASA IDs from fixed vulnerabilities
        asa_ids: set[str] = set()
        for record in data:
            if record.get("fixed") and record.get("status") != "Not affected":
                for asa_id in record.get("advisories", []):
                    asa_ids.add(asa_id)

        if not asa_ids:
            return

        asa_id_list = sorted(asa_ids)  # Sort for deterministic ordering
        self.logger.info(f"Prefetching {len(asa_id_list)} ASA advisory dates")

        # Process in batches with delays to avoid overwhelming the server
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for i in range(0, len(asa_id_list), batch_size):
                batch = asa_id_list[i : i + batch_size]
                futures = [executor.submit(self._fetch_and_cache_asa_date, asa_id) for asa_id in batch]
                concurrent.futures.wait(futures)

                # Rate limit: pause between batches (skip delay after last batch)
                if i + batch_size < len(asa_id_list):
                    time.sleep(1.0)

    def _build_fixed_in_entries(  # noqa: PLR0913
        self,
        packages: list[str],
        fixed_version: str,
        issues: list[str],
        group_id: str,
        ecosystem: str,
        advisories: list[str],
    ) -> list[FixedIn]:
        """Build FixedIn entries for each affected package."""
        fixed_in_list: list[FixedIn] = []

        # Get ASA date once for all packages
        asa_date = self._get_best_asa_date(advisories) if fixed_version else None

        for package_name in packages:
            if not package_name:
                continue

            available: FixAvailability | None = None
            if fixed_version:
                # Use CVE ID if available, otherwise use AVG ID
                vuln_id = issues[0] if issues else group_id

                # Build candidates with ASA date if available
                candidates: list[fixdate.Result] | None = None
                if asa_date:
                    candidates = [
                        fixdate.Result(
                            date=asa_date,
                            kind="advisory",
                            accurate=True,
                        ),
                    ]

                result = self.fixdater.best(
                    vuln_id=vuln_id,
                    cpe_or_package=package_name,
                    fix_version=fixed_version,
                    ecosystem=ecosystem,
                    candidates=candidates,
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

        # Prefetch all ASA dates concurrently before processing
        self._prefetch_asa_dates(data)

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
                fixed_in_list = self._build_fixed_in_entries(packages, fixed_version, issues, group_id, ecosystem, advisories)
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
