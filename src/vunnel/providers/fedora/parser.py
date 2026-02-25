from __future__ import annotations

import copy
import glob
import logging
import os
import re
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    import datetime
    from collections.abc import Generator, Sequence
    from types import TracebackType

    from vunnel.workspace import Workspace

    from . import Config


# Severity mapping from Bodhi to Vunnel schema
SEVERITY_MAP = {
    "urgent": "Critical",
    "critical": "Critical",
    "important": "High",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
    "none": "Unknown",
    "unspecified": "Unknown",
    "": "Unknown",
}

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")

# Each Bodhi update is persisted as its own file: <alias>.json
# e.g. FEDORA-2025-21c36b3aa5.json
_UPDATE_FILE_GLOB = "FEDORA-*.json"


class Parser:
    """Parser for Fedora security updates via the Bodhi REST API."""

    def __init__(
        self,
        workspace: Workspace,
        config: Config,
        logger: logging.Logger | None = None,
        user_agent: str | None = None,
        fixdater: fixdate.Finder | None = None,
    ):
        self.workspace = workspace
        self.config = config
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.urls: list[str] = []
        self.user_agent = user_agent
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater

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

    def _fetch_page(self, page: int, release: str | None = None, extra_params: dict[str, str] | None = None) -> dict[str, Any]:
        """Fetch a single page of security updates from the Bodhi API."""
        url = f"{self.config.bodhi_url}/updates/"
        params: dict[str, str] = {
            "status": "stable",
            "type": "security",
            "rows_per_page": str(self.config.rows_per_page),
            "page": str(page),
        }
        if release:
            params["releases"] = f"F{release}"
        if extra_params:
            params.update(extra_params)

        self.urls.append(url)
        self.logger.debug(f"fetching page {page} from Bodhi API")

        resp = http.get(
            url,
            self.logger,
            timeout=self.config.request_timeout,
            user_agent=self.user_agent,
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    def _save_update(self, update: dict[str, Any]) -> str | None:
        """Persist a single Bodhi update to its own file, keyed by alias.

        Returns the file path written, or None if the update has no alias.
        """
        alias = update.get("alias")
        if not alias:
            return None
        filepath = os.path.join(self.workspace.input_path, f"{alias}.json")
        with open(filepath, "wb") as f:
            f.write(orjson.dumps(update))
        return filepath

    def _download(self) -> None:
        """Download all security updates from Bodhi (full sync).

        Clears any existing per-update input files before downloading.
        """
        os.makedirs(self.workspace.input_path, exist_ok=True)

        for filepath in glob.glob(os.path.join(self.workspace.input_path, _UPDATE_FILE_GLOB)):
            os.remove(filepath)

        releases: Sequence[str | None] = self.config.releases if self.config.releases else (None,)

        for release in releases:
            label = f"Fedora {release}" if release else "all releases"
            page = 1

            while True:
                self.logger.info(f"fetching {label} security updates page {page}")
                data = self._fetch_page(page, release=release)

                updates = data.get("updates", [])
                if not updates:
                    break

                for update in updates:
                    self._save_update(update)

                total_pages = data.get("pages", 1)
                self.logger.debug(f"page {page}/{total_pages}, updates on page: {len(updates)}")

                if page >= total_pages:
                    break
                page += 1

    def _can_update_incrementally(self, last_updated: datetime.datetime | None) -> bool:
        """Check if incremental update is possible.

        Requires both a last_updated timestamp and existing per-update input files.
        """
        if not last_updated:
            return False
        return len(self._existing_input_files()) > 0

    def _download_updates(self, last_updated: datetime.datetime) -> None:
        """Download only recently pushed security updates.

        Uses the Bodhi API's ``pushed_since`` parameter to fetch updates pushed
        to stable since the given timestamp.  Each update is written to its own
        file, overwriting any previous version of that update.
        """
        os.makedirs(self.workspace.input_path, exist_ok=True)

        releases: Sequence[str | None] = self.config.releases if self.config.releases else (None,)
        count = 0

        for release in releases:
            label = f"Fedora {release}" if release else "all releases"
            page = 1

            while True:
                self.logger.info(f"fetching {label} security updates pushed since last sync, page {page}")
                data = self._fetch_page(page, release=release, extra_params={"pushed_since": last_updated.isoformat()})

                updates = data.get("updates", [])
                if not updates:
                    break

                for update in updates:
                    if self._save_update(update):
                        count += 1

                total_pages = data.get("pages", 1)
                self.logger.debug(f"page {page}/{total_pages}, updates on page: {len(updates)}")

                if page >= total_pages:
                    break
                page += 1

        self.logger.info(f"incremental update wrote {count} update files")

    def _load_all_updates(self) -> list[dict[str, Any]]:
        """Load all per-update input files."""
        updates = []
        for filepath in self._existing_input_files():
            with open(filepath, "rb") as f:
                updates.append(orjson.loads(f.read()))
        return updates

    @staticmethod
    def _extract_cves(update: dict[str, Any]) -> list[str]:
        """Extract unique CVE IDs from a Bodhi update.

        Checks security bugs first, then falls back to display_name and title fields.
        """
        cves: list[str] = []
        seen: set[str] = set()

        for bug in update.get("bugs", []):
            if not bug.get("security", False):
                continue
            for match in _CVE_PATTERN.finditer(bug.get("title", "")):
                if match.group() not in seen:
                    seen.add(match.group())
                    cves.append(match.group())

        if not cves:
            for field in ("display_name", "title"):
                for match in _CVE_PATTERN.finditer(update.get(field, "")):
                    if match.group() not in seen:
                        seen.add(match.group())
                        cves.append(match.group())

        return cves

    @staticmethod
    def _parse_builds(update: dict[str, Any], logger: logging.Logger) -> list[dict[str, str]]:
        """Parse RPM builds from a Bodhi update into package dicts."""
        packages = []
        for build in update.get("builds", []):
            if build.get("type") != "rpm":
                continue
            nvr = build.get("nvr", "")
            epoch = build.get("epoch") or 0

            parts = nvr.rsplit("-", 2)
            if len(parts) != 3:
                logger.debug(f"skipping build with unexpected NVR format: {nvr}")
                continue

            name, version, rel = parts
            packages.append({"name": name, "version": f"{epoch}:{version}-{rel}"})

        return packages

    def _parse_update(self, update: dict[str, Any]) -> dict[str, Any] | None:
        """Parse a single Bodhi update into an advisory dict."""
        alias = update.get("alias", "")
        if not alias:
            return None

        release_info = update.get("release", {})
        release_version = release_info.get("version", "")
        if not release_version or not release_version.isdigit():
            return None

        severity = update.get("severity", "").lower()
        severity = SEVERITY_MAP.get(severity, "Unknown")

        advisory_url = update.get("url", f"{self.config.bodhi_url}/updates/{alias}")

        return {
            "advisory_id": alias,
            "release": release_version,
            "severity": severity,
            "title": update.get("display_name", alias),
            "description": update.get("notes", ""),
            "issued_date": update.get("date_submitted", ""),
            "updated_date": update.get("date_modified", "") or update.get("date_stable", ""),
            "date_stable": update.get("date_stable", ""),
            "cves": self._extract_cves(update),
            "packages": self._parse_builds(update, self.logger),
            "link": advisory_url,
        }

    def _normalize(self, advisory: dict[str, Any]) -> Generator[tuple[str, dict[str, Any]]]:
        """Normalize advisory to Vunnel vulnerability schema.

        Yields one record per CVE (or per advisory if no CVEs).
        """
        release = advisory["release"]
        namespace = f"fedora:{release}"
        packages = advisory["packages"]

        if not packages:
            return

        # Build advisory date candidate from date_stable
        date_stable = advisory.get("date_stable", "")
        candidates = []
        if date_stable:
            candidates.append(fixdate.Result(date=date_stable, kind="advisory", accurate=True))

        # Determine CVE IDs for fixdater lookups
        vuln_ids = advisory["cves"] if advisory["cves"] else [advisory["advisory_id"]]

        # Build FixedIn list
        fixed_in = []
        for pkg in packages:
            fixed_in_entry = {
                "Name": pkg["name"],
                "Version": pkg["version"],
                "VersionFormat": "rpm",
                "NamespaceName": namespace,
                "Module": "",
                "VendorAdvisory": {
                    "NoAdvisory": False,
                    "AdvisorySummary": [
                        {
                            "ID": advisory["advisory_id"],
                            "Link": advisory["link"],
                        },
                    ],
                },
            }

            # Use the first vuln_id for the fixdater lookup (all CVEs in an advisory share the same fix)
            result = self.fixdater.best(
                vuln_id=vuln_ids[0],
                cpe_or_package=pkg["name"],
                fix_version=pkg["version"],
                ecosystem=namespace,
                candidates=candidates,
            )
            if result and result.date:
                fixed_in_entry["Available"] = {
                    "Date": result.date.isoformat(),
                    "Kind": result.kind,
                }

            fixed_in.append(fixed_in_entry)

        base_record = {
            "Vulnerability": {
                "Severity": advisory["severity"],
                "NamespaceName": namespace,
                "FixedIn": fixed_in,
                "Link": advisory["link"],
                "Description": "",
                "Metadata": {
                    "Issued": advisory.get("issued_date", ""),
                    "Updated": advisory.get("updated_date", ""),
                },
                "Name": "",
                "CVSS": [],
            },
        }

        if advisory["cves"]:
            for cve_id in advisory["cves"]:
                record = copy.deepcopy(base_record)
                record["Vulnerability"]["Name"] = cve_id
                record["Vulnerability"]["Metadata"]["CVE"] = [
                    {"Name": cve_id, "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                ]
                yield (f"{namespace}/{cve_id}", record)
        else:
            vuln_id = advisory["advisory_id"]
            record = copy.deepcopy(base_record)
            record["Vulnerability"]["Name"] = vuln_id
            record["Vulnerability"]["Metadata"]["CVE"] = []
            yield (f"{namespace}/{vuln_id}", record)

    def _existing_input_files(self) -> list[str]:
        """Return previously downloaded per-update JSON files from the input directory."""
        pattern = os.path.join(self.workspace.input_path, _UPDATE_FILE_GLOB)
        return sorted(glob.glob(pattern))

    def get(self, last_updated: datetime.datetime | None = None, skip_if_exists: bool = False) -> Generator[tuple[str, dict[str, Any]]]:
        """Main entry point - download, parse, and normalize vulnerabilities.

        Args:
            last_updated: Timestamp of the last successful run, used for incremental updates.
            skip_if_exists: When True and last_updated is available, attempt incremental update.
        """
        self.fixdater.download()

        if self.config.runtime.skip_download:
            self.logger.info("skip_download set, using existing input data")
        elif skip_if_exists and last_updated and self._can_update_incrementally(last_updated):
            self.logger.info(f"incremental update: fetching updates modified since {last_updated.isoformat()}")
            self._download_updates(last_updated)
        else:
            if skip_if_exists and last_updated:
                self.logger.info("cannot update incrementally (missing input data), performing full sync")
            self._download()

        updates = self._load_all_updates()
        merged: dict[str, dict[str, Any]] = {}

        for update in updates:
            advisory = self._parse_update(update)
            if not advisory:
                continue

            for vuln_id, record in self._normalize(advisory):
                if vuln_id not in merged:
                    merged[vuln_id] = record
                else:
                    # Merge FixedIn entries from additional updates for the same CVE
                    merged[vuln_id]["Vulnerability"]["FixedIn"].extend(
                        record["Vulnerability"]["FixedIn"],
                    )

        yield from merged.items()
