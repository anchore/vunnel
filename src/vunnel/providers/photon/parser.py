from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils.vulnerability import FixedIn, Vulnerability, build_reference_links

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


PHOTON_CVE_URL_BASE = "https://packages.broadcom.com/photon/photon_cve_metadata/"
PHOTON_CVE_FILENAME = "cve_data_photon{version}.json"


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


class Parser:
    def __init__(
        self,
        workspace: Workspace,
        download_timeout: int,
        allow_versions: list[str],
        logger: logging.Logger,
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

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self) -> list[str]:
        """Download CVE JSON files for all allowed Photon versions."""
        self.fixdater.download()
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

    def _build_fixed_in(self, entry: dict[str, Any], namespace: str) -> FixedIn | None:
        """Build a FixedIn entry from a single CVE entry, or None if not affected."""
        if entry.get("status") == "Not Affected":
            return None

        pkg = entry.get("pkg")
        if not pkg:
            return None

        return FixedIn(
            Name=pkg,
            NamespaceName=namespace,
            VersionFormat="rpm",
            Version=parse_fixed_version(entry.get("res_ver", "")),
            Module=None,
            VendorAdvisory=None,
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
            fixed_in_list = [fi for e in entries if (fi := self._build_fixed_in(e, namespace))]
            if not fixed_in_list:
                continue

            # Derive severity from the first entry with a score
            severity = "Unknown"
            for entry in entries:
                severity = cvss_to_severity(entry.get("cve_score"))
                if severity != "Unknown":
                    break

            reference_links = build_reference_links(cve_id)

            vuln = Vulnerability(
                Name=cve_id,
                NamespaceName=namespace,
                Description="",
                Severity=severity,
                Link=reference_links[0] if reference_links else "",
                CVSS=[],
                FixedIn=fixed_in_list,
                Metadata={},
            )

            yield namespace, cve_id, vuln.to_payload()

    def _patch_fix_date(self, vuln_record: dict[str, Any]) -> dict[str, Any]:
        """Annotate FixedIn entries with fix-availability dates from the fixdater."""
        vid = vuln_record.get("Vulnerability", {}).get("Name", "")
        if not vid:
            return vuln_record

        fixed_in_list = vuln_record.get("Vulnerability", {}).get("FixedIn", [])
        for fixedin in fixed_in_list:
            if fixedin.get("Available") and "Date" in fixedin["Available"]:
                continue
            if "Version" not in fixedin or fixedin["Version"] in ("None", "0"):
                continue

            result = self.fixdater.best(
                vuln_id=vid,
                cpe_or_package=fixedin.get("Name", ""),
                fix_version=fixedin["Version"],
                ecosystem=fixedin.get("NamespaceName", "").lower(),
            )
            if result:
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
