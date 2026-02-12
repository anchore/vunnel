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

    def _fetch_page(self, page: int, release: str | None = None) -> dict[str, Any]:
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

    def _download(self) -> list[str]:
        """Download all security updates from Bodhi and save JSON pages to workspace.

        Returns:
            List of file paths to saved JSON pages.
        """
        os.makedirs(self.workspace.input_path, exist_ok=True)
        saved_files: list[str] = []

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

                suffix = f"-f{release}" if release else ""
                filename = f"bodhi-updates{suffix}-page-{page}.json"
                filepath = os.path.join(self.workspace.input_path, filename)

                with open(filepath, "wb") as f:
                    f.write(orjson.dumps(updates))

                saved_files.append(filepath)

                total_pages = data.get("pages", 1)
                self.logger.debug(f"page {page}/{total_pages}, updates on page: {len(updates)}")

                if page >= total_pages:
                    break
                page += 1

        return saved_files

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
        """Return previously downloaded JSON files from the input directory."""
        pattern = os.path.join(self.workspace.input_path, "bodhi-updates*.json")
        return sorted(glob.glob(pattern))

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """Main entry point - download, parse, and normalize vulnerabilities."""
        self.fixdater.download()

        if self.config.runtime.skip_download:
            self.logger.info("skip_download set, using existing input data")
            saved_files = self._existing_input_files()
        else:
            saved_files = self._download()

        emitted: set[str] = set()

        for filepath in saved_files:
            with open(filepath, "rb") as f:
                updates = orjson.loads(f.read())

            for update in updates:
                advisory = self._parse_update(update)
                if not advisory:
                    continue

                for vuln_id, record in self._normalize(advisory):
                    if vuln_id not in emitted:
                        emitted.add(vuln_id)
                        yield (vuln_id, record)
