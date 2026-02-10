from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils.vulnerability import (
    AdvisorySummary,
    FixedIn,
    VendorAdvisory,
    Vulnerability,
    build_reference_links,
)

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


PHOTON_CVE_URL_BASE = "https://packages.broadcom.com/photon/photon_cve_metadata/"
PHOTON_CVE_FILENAME = "cve_data_photon{version}.json"
PHOTON_WIKI_BASE_URL = "https://github.com/vmware/photon/wiki"

# Regex patterns for parsing advisory markdown files
# Matches both versioned IDs (PHSA-2023-4.0-0500) and short IDs (PHSA-2017-0010)
_ADVISORY_ID_RE = re.compile(r"Advisory\s+(?:Id|ID)\s*:\s*(PHSA-\d{4}-(?:\d+\.\d+-)?0*\d+)")
_ISSUE_DATE_RE = re.compile(r"(?:Issue\s+date|Issued\s+on)\s*:\s*(\d{4}-\d{2}-\d{2})")
_CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d+)")
_ADVISORY_FILENAME_RE = re.compile(r"Security-Updates?-(\d+\.\d+)-(\d+)\.md")


@dataclass
class AdvisoryInfo:
    advisory_id: str
    date: str
    url: str


# Map CVSS scores to severity levels
def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Negligible"


def parse_fixed_version(res_ver: str) -> str:
    """Extract the fixed version from the res_ver field."""
    if res_ver == "NA" or not res_ver:
        return "None"
    return res_ver


def _parse_advisory_file(filepath: str) -> tuple[str, str, str, set[str]] | None:
    """Parse a single advisory markdown file and return (advisory_id, date, version, cve_ids).

    Returns None if the file cannot be parsed.
    """
    basename = os.path.basename(filepath)
    filename_match = _ADVISORY_FILENAME_RE.match(basename)
    if not filename_match:
        return None

    version = filename_match.group(1)

    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    advisory_match = _ADVISORY_ID_RE.search(content)
    if not advisory_match:
        return None
    advisory_id = advisory_match.group(1)

    date_match = _ISSUE_DATE_RE.search(content)
    if not date_match:
        return None
    date = date_match.group(1)

    cve_ids = set(_CVE_ID_RE.findall(content))
    if not cve_ids:
        return None

    return advisory_id, date, version, cve_ids


def parse_advisories(wiki_path: str) -> dict[tuple[str, str], AdvisoryInfo]:
    """Parse all advisory files in the wiki repo and build a CVE-to-advisory mapping.

    Returns a dict mapping (photon_version, cve_id) to AdvisoryInfo. When a CVE
    appears in multiple advisories for the same version, the earliest advisory wins.
    """
    advisory_map: dict[tuple[str, str], AdvisoryInfo] = {}

    if not os.path.isdir(wiki_path):
        return advisory_map

    for filename in os.listdir(wiki_path):
        if not filename.endswith(".md"):
            continue
        if not _ADVISORY_FILENAME_RE.match(filename):
            continue

        filepath = os.path.join(wiki_path, filename)
        result = _parse_advisory_file(filepath)
        if result is None:
            continue

        advisory_id, date, version, cve_ids = result

        # Derive the wiki page URL from the filename (strip .md)
        page_name = filename[:-3]
        url = f"{PHOTON_WIKI_BASE_URL}/{page_name}"

        info = AdvisoryInfo(advisory_id=advisory_id, date=date, url=url)

        for cve_id in cve_ids:
            key = (version, cve_id)
            existing = advisory_map.get(key)
            if existing is None or date < existing.date:
                advisory_map[key] = info

    return advisory_map


class Parser:
    _wiki_dir_name = "photon.wiki"

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        download_timeout: int,
        allow_versions: list[str],
        logger: logging.Logger,
        wiki_url: str = "https://github.com/vmware/photon.wiki.git",
        fixdater: fixdate.Finder | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.allow_versions = allow_versions
        self._urls: set[str] = set()
        self.logger = logger
        self.wiki_url = wiki_url
        self._advisory_map: dict[tuple[str, str], AdvisoryInfo] = {}

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _clone_wiki(self) -> str:
        """Clone (or update) the photon wiki repository and return the checkout path."""
        dest = os.path.join(self.workspace.input_path, self._wiki_dir_name)

        if os.path.isdir(dest):
            self.logger.debug(f"removing existing wiki checkout at {dest}")
            shutil.rmtree(dest, ignore_errors=True)

        self.logger.info(f"cloning photon wiki from {self.wiki_url} to {dest}")
        cmd = f"git clone --depth 1 {self.wiki_url} {dest}"
        try:
            # S603 disable explanation: running git clone by design with controlled URL
            subprocess.check_output(shlex.split(cmd), text=True, stderr=subprocess.PIPE)  # noqa: S603
        except subprocess.CalledProcessError:
            self.logger.exception(f"failed to clone wiki from {self.wiki_url}")
            raise

        self._urls.add(self.wiki_url)
        return dest

    def _download(self) -> list[str]:
        """Download CVE JSON files for all allowed Photon versions and clone the wiki."""
        self.fixdater.download()

        wiki_path = self._clone_wiki()
        self._advisory_map = parse_advisories(wiki_path)
        self.logger.info(f"parsed {len(self._advisory_map)} CVE-to-advisory mappings from wiki")

        return [self._download_version(v) for v in self.allow_versions]

    def _download_version(self, version: str) -> str:
        """Download the CVE JSON file for a specific Photon version."""
        filename = PHOTON_CVE_FILENAME.format(version=version)
        url = f"{PHOTON_CVE_URL_BASE}{filename}"

        r = http.get(url, self.logger, timeout=self.download_timeout)
        destination = os.path.join(self.workspace.input_path, filename)

        with open(destination, "wb") as writer:
            writer.write(r.content)

        self._urls.add(url)
        return destination

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def _extract_version_from_filename(self, filepath: str) -> str:
        """Extract the Photon version from the filename."""
        # Filename format: cve_data_photonX.Y.json
        basename = os.path.basename(filepath)
        match = re.search(r"cve_data_photon(\d+\.\d+)\.json", basename)
        if match:
            return match.group(1)
        return ""

    def _build_fixed_in(self, entry: dict[str, Any], namespace: str, advisory: AdvisoryInfo | None) -> FixedIn | None:
        """Build a FixedIn entry from a single CVE entry, or None if not affected."""
        if entry.get("status") == "Not Affected":
            return None

        pkg = entry.get("pkg")
        if not pkg:
            return None

        vendor_advisory = None
        if advisory:
            vendor_advisory = VendorAdvisory(
                NoAdvisory=False,
                AdvisorySummary=[AdvisorySummary(ID=advisory.advisory_id, Link=advisory.url)],
            )

        return FixedIn(
            Name=pkg,
            NamespaceName=namespace,
            VersionFormat="rpm",
            Version=parse_fixed_version(entry.get("res_ver", "")),
            Module=None,
            VendorAdvisory=vendor_advisory,
        )

    def _parse_file(self, filepath: str) -> Generator[tuple[str, str, dict[str, Any]]]:
        """Parse a Photon CVE JSON file and yield vulnerabilities."""
        photon_version = self._extract_version_from_filename(filepath)
        if not photon_version:
            self.logger.warning(f"Could not extract version from {filepath}")
            return

        with open(filepath, "rb") as f:
            cve_data = orjson.loads(f.read())

        # Group CVEs by ID since multiple packages can be affected by the same CVE
        cve_map: dict[str, list[dict[str, Any]]] = {}
        for entry in cve_data:
            cve_id = entry.get("cve_id")
            if not cve_id:
                continue
            cve_map.setdefault(cve_id, []).append(entry)

        namespace = f"photon:{photon_version}"

        for cve_id, entries in cve_map.items():
            advisory = self._advisory_map.get((photon_version, cve_id))
            fixed_in_list = [fi for e in entries if (fi := self._build_fixed_in(e, namespace, advisory))]
            if not fixed_in_list:
                continue

            # Derive severity from the first entry with a score
            severity = "Unknown"
            for entry in entries:
                severity = cvss_to_severity(entry.get("cve_score"))
                if severity != "Unknown":
                    break

            reference_links = build_reference_links(cve_id)

            metadata: dict[str, Any] = {}
            if advisory:
                metadata["Issued"] = advisory.date

            vuln = Vulnerability(
                Name=cve_id,
                NamespaceName=namespace,
                Description="",
                Severity=severity,
                Link=reference_links[0] if reference_links else "",
                CVSS=[],
                FixedIn=fixed_in_list,
                Metadata=metadata,
            )

            yield namespace, cve_id, vuln.to_payload()

    def _patch_fix_date(self, vuln_record: dict[str, Any]) -> dict[str, Any]:
        """Annotate FixedIn entries with fix-availability dates.

        Uses advisory dates from the photon wiki when available,
        falling back to the fixdater (first-observed) otherwise.
        """
        vid = vuln_record.get("Vulnerability", {}).get("Name", "")
        if not vid:
            return vuln_record

        fixed_in_list = vuln_record.get("Vulnerability", {}).get("FixedIn", [])
        for fixedin in fixed_in_list:
            if fixedin.get("Available") and "Date" in fixedin["Available"]:
                continue
            if "Version" not in fixedin or fixedin["Version"] in ("None", "0"):
                continue

            # Look up the namespace to extract the photon version
            ns = fixedin.get("NamespaceName", "")
            photon_version = ns.split(":")[-1] if ":" in ns else ""

            advisory = self._advisory_map.get((photon_version, vid))
            if advisory:
                fixedin["Available"] = {
                    "Date": advisory.date,
                    "Kind": "advisory",
                }
                continue

            # Fall back to fixdater (first-observed)
            result = self.fixdater.best(
                vuln_id=vid,
                cpe_or_package=fixedin.get("Name", ""),
                fix_version=fixedin["Version"],
                ecosystem=ns.lower(),
            )
            if result and result.date:
                fixedin["Available"] = {
                    "Date": result.date.isoformat(),
                    "Kind": result.kind,
                }
        return vuln_record

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        """Download and parse all Photon CVE data files."""
        for filepath in self._download():
            for namespace, vuln_id, record in self._parse_file(filepath):
                yield namespace, vuln_id, self._patch_fix_date(record)
