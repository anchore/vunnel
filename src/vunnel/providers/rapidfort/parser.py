"""RapidFort security advisories parser.

Reads RapidFort advisory data and normalizes to vunnel OSSchema format.
Supports Ubuntu (dpkg) and Alpine (apk).

Supports two input formats:
1. Vuln-list format: {os}/{version}/{package}.json with package_name, distro_version, advisories
2. Source format: OS/{os}/{package}.json with package_name, advisory: {version: {CVE: ...}}
"""

from __future__ import annotations

import copy
import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import vulnerability

from .git import GitWrapper

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

namespace = "rapidfort"
default_repo_url = "https://github.com/rapidfort/security-advisories.git"
repo_branch = "main"
repo_os_path = "OS"  # OS/{osName}/{package}.json (source format)
default_supported_oses = ("ubuntu", "alpine")

# Version format per base OS
version_formats = {
    "ubuntu": "dpkg",
    "alpine": "apk",
}


def _events_to_range_pairs(events: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Convert RapidFort events into (range_str, fix_version) tuples.

    Mirrors GHSA vulnerableVersionRange semantics:
    - introduced + fixed => ">= introduced, < fixed"
    - introduced only => ">= introduced" (open-ended)
    - fixed only => "< fixed" (rare)

    Deduplicates while preserving order.
    """
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []

    for ev in events:
        if not isinstance(ev, dict):
            continue
        introduced = ev.get("introduced")
        fixed = ev.get("fixed")

        if introduced and fixed:
            range_str = f">= {introduced}, < {fixed}"
            fix_version = str(fixed)
            key = (str(introduced), str(fixed))
        elif introduced:
            range_str = f">= {introduced}"
            fix_version = "None"
            key = (str(introduced), "")
        elif fixed:
            range_str = f"< {fixed}"
            fix_version = str(fixed)
            key = ("", str(fixed))
        else:
            continue

        if key not in seen:
            seen.add(key)
            result.append((range_str, fix_version))

    return result


class Parser:
    """Parser for RapidFort security advisories."""

    def __init__(
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
        repo_url: str | None = None,
        supported_oses: tuple[str, ...] | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.workspace = workspace
        self.repo_url = repo_url or default_repo_url
        self.supported_oses = supported_oses or default_supported_oses
        self.urls = [self.repo_url]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self._checkout_dest = os.path.join(self.workspace.input_path, "rapidfort-advisories")

        self.git_wrapper = GitWrapper(
            source=self.repo_url,
            branch=repo_branch,
            checkout_dest=self._checkout_dest,
            logger=self.logger,
        )

        self.security_reference_url = "https://github.com/rapidfort/security-advisories/tree/main/OS"

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

    def _load_package_file(self, file_path: str, os_name: str) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        try:
            with open(file_path, "rb") as f:
                data = orjson.loads(f.read())
        except Exception:
            self.logger.warning("Failed to parse %s", file_path, exc_info=True)
            return

        pkg_name = data.get("package_name")
        if not pkg_name:
            self.logger.warning("Missing package_name in %s, skipping", file_path)
            return

        advisory = data.get("advisory")
        if not isinstance(advisory, dict):
            return

        for os_version, cve_map in advisory.items():
            if isinstance(cve_map, dict) and cve_map:
                yield os_name, os_version, pkg_name, cve_map

    def _load_os(self, base_dir: str, os_name: str) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        src_dir = os.path.join(base_dir, os_name)

        if not os.path.isdir(src_dir):
            self.logger.debug("RapidFort OS dir not found, skipping: %s", src_dir)
            return

        for entry in sorted(os.listdir(src_dir)):
            if not entry.endswith(".json"):
                continue

            file_path = os.path.join(src_dir, entry)
            if os.path.isfile(file_path):
                yield from self._load_package_file(file_path, os_name)

    def _load(self) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        """Yield (os_name, os_version, package_name, cve_map) from OS/{os}/{package}.json."""
        base_dir = os.path.join(self._checkout_dest, "OS")

        if not os.path.isdir(base_dir):
            self.logger.warning("RapidFort OS root not found: %s", base_dir)
            return

        for os_name in self.supported_oses:
            yield from self._load_os(base_dir, os_name)

    def _parse_vulnlist_file(
        self,
        file_path: str,
        os_name: str,
        version: str,
    ) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        """Parse vuln-list format: package_name, distro_version, advisories."""
        try:
            with open(file_path, "rb") as f:
                data = orjson.loads(f.read())
        except Exception:
            self.logger.warning("Failed to parse %s", file_path, exc_info=True)
            return

        pkg_name = data.get("package_name") or data.get("packageName")
        if not pkg_name:
            self.logger.warning("Missing package_name in %s, skipping", file_path)
            return

        advisories = data.get("advisories") or data.get("Advisories")
        if not isinstance(advisories, dict):
            return

        distro_version = data.get("distro_version") or data.get("distroVersion") or version
        yield os_name, str(distro_version), pkg_name, advisories

    def _get_valid_cve_entry(
        self,
        cve_id: str,
        cve_entry: Any,
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Return normalized CVE ID and entry if valid."""
        if not isinstance(cve_entry, dict):
            return None, None

        vid = cve_entry.get("cve_id") or cve_id
        if not vid:
            return None, None

        return str(vid), cve_entry

    def _get_or_create_vuln_record(
        self,
        vuln_dict: dict[str, dict[str, Any]],
        vid: str,
        cve_entry: dict[str, Any],
        ecosystem: str,
    ) -> dict[str, Any]:
        """Return an existing vulnerability record or create a new one."""
        if vid in vuln_dict:
            return vuln_dict[vid]

        vuln_record = copy.deepcopy(vulnerability.vulnerability_element)
        reference_links = vulnerability.build_reference_links(vid)

        vuln_record["Vulnerability"]["Name"] = vid
        vuln_record["Vulnerability"]["NamespaceName"] = ecosystem

        if reference_links:
            vuln_record["Vulnerability"]["Link"] = reference_links[0]

        vuln_record["Vulnerability"]["Severity"] = self._map_severity(
            cve_entry.get("severity"),
        )

        description = cve_entry.get("description")
        if description:
            vuln_record["Vulnerability"]["Description"] = str(description)

        vuln_dict[vid] = vuln_record
        return vuln_record

    def _get_fix_availability(
        self,
        vid: str,
        pkg_name: str,
        fix_version: str,
        ecosystem: str,
    ) -> dict[str, str] | None:
        """Return fix availability metadata for a fixed version, if known."""
        if fix_version == "None":
            return None

        result = self.fixdater.best(
            vuln_id=vid,
            cpe_or_package=pkg_name,
            fix_version=fix_version,
            ecosystem=ecosystem,
        )
        if not result:
            return None

        return {
            "Date": result.date.isoformat(),
            "Kind": result.kind,
        }

    def _build_fixed_in_elements(
        self,
        vid: str,
        pkg_name: str,
        cve_entry: dict[str, Any],
        ecosystem: str,
        version_format: str,
    ) -> list[dict[str, Any]]:
        """Build FixedIn entries from advisory events."""
        events = cve_entry.get("events") or []
        range_pairs = _events_to_range_pairs(events)

        fixed_elements: list[dict[str, Any]] = []
        for range_str, fix_version in range_pairs:
            fixed_el = {
                "Name": pkg_name,
                "NamespaceName": ecosystem,
                "VersionFormat": version_format,
                "Version": fix_version,
                "VulnerableRange": range_str,
            }

            availability = self._get_fix_availability(
                vid=vid,
                pkg_name=pkg_name,
                fix_version=fix_version,
                ecosystem=ecosystem,
            )
            if availability:
                fixed_el["Available"] = availability

            fixed_elements.append(fixed_el)

        return fixed_elements

    def _normalize(
        self,
        os_name: str,
        os_version: str,
        pkg_name: str,
        cve_map: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Convert RapidFort advisory to vunnel OSSchema vulnerability records.

        Uses grype-compatible namespace format: provider-distroType:version
        (e.g. rapidfort-ubuntu:22.04) so grype stores RF advisories under a provider-
        prefixed OS name that is isolated from standard distro scans.
        """
        vuln_dict: dict[str, dict[str, Any]] = {}
        version_format = version_formats.get(os_name.lower(), "dpkg")
        ecosystem = f"{namespace}-{os_name}:{os_version}"

        for cve_id, cve_entry in cve_map.items():
            vid, entry = self._get_valid_cve_entry(cve_id, cve_entry)
            if not vid:
                continue

            vuln_record = self._get_or_create_vuln_record(
                vuln_dict=vuln_dict,
                vid=vid,
                cve_entry=entry,
                ecosystem=ecosystem,
            )

            # Build FixedIn from events (one per introduced/fixed pair, like GHSA)
            events = cve_entry.get("events") or []
            range_pairs = _events_to_range_pairs(events)

            if not range_pairs:
                continue

            for fixed_el in self._build_fixed_in_elements(
                vid=vid,
                pkg_name=pkg_name,
                cve_entry=entry,
                ecosystem=ecosystem,
                version_format=version_format,
            ):
                vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return vuln_dict

    def _map_severity(self, severity: Any) -> str:
        """Map RapidFort severity to vunnel severity string."""
        if not severity:
            return "Unknown"
        s = str(severity).strip().upper()
        for valid in ("Critical", "High", "Medium", "Low", "Negligible"):
            if s == valid.upper():
                return valid
        return "Unknown"

    def _merge_into_namespace(
        self,
        namespace_vulns: dict[str, dict[str, dict[str, Any]]],
        ns: str,
        normalized: dict[str, dict[str, Any]],
    ) -> None:
        """Merge normalized vulnerability records into namespace_vulns.

        For the same CVE across different packages, FixedIn entries are extended.
        """
        if ns not in namespace_vulns:
            namespace_vulns[ns] = {}

        for vid, record in normalized.items():
            if vid in namespace_vulns[ns]:
                existing = namespace_vulns[ns][vid]
                existing["Vulnerability"]["FixedIn"].extend(
                    record["Vulnerability"]["FixedIn"],
                )
            else:
                namespace_vulns[ns][vid] = record

    def get(self) -> Generator[tuple[str, dict[str, dict[str, Any]]]]:
        """Clone repo, load advisories, normalize and yield (namespace, vuln_dict)."""
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()

        self.fixdater.download()

        namespace_vulns: dict[str, dict[str, dict[str, Any]]] = {}

        for os_name, version, pkg_name, cve_map in self._load():
            ns = f"{namespace}-{os_name}:{version}"
            normalized = self._normalize(os_name, version, pkg_name, cve_map)
            self._merge_into_namespace(namespace_vulns, ns, normalized)

        for ns, vuln_dict in namespace_vulns.items():
            yield ns, vuln_dict
