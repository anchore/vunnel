"""RapidFort security advisories parser.

Reads RapidFort advisory data and normalizes to vunnel OSSchema format.
Supports Ubuntu (dpkg), Debian (dpkg), Alpine (apk), and Red Hat (rpm).

Input format: OS/{os}/{package}.json with package_name, advisory: {version: {CVE: ...}}

RapidFort images mix packages from several release streams (e.g. native el9 builds, Fedora
builds, and RapidFort rebuilds inside one rapidfort-redhat:9 image). Each advisory event may
carry an `identifier` naming its stream (el9, fc43, rf, ubuntu, ...). Streams are emitted as
separate grype namespaces so their fix ranges are never merged into one constraint:

- the image's native stream (el{major} for redhat, ubuntu/unidentified for ubuntu, everything
  for alpine/debian) folds into the channel-less namespace, e.g. rapidfort-redhat:9 — so a
  package that matches no client-side routing rule degrades to sane native-stream matching
- foreign/rebuild streams get a +channel namespace, e.g. rapidfort-redhat:9+fc43 or
  rapidfort-ubuntu:20.04+rf, which grype routes to per package via version/name markers
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
default_supported_oses = ("ubuntu", "debian", "alpine", "redhat")

# Version format per base OS
version_formats = {
    "ubuntu": "dpkg",
    "debian": "dpkg",
    "alpine": "apk",
    "redhat": "rpm",
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


def _advisory_url(os_name: str, pkg_name: str) -> str:
    return f"https://github.com/rapidfort/security-advisories/tree/main/OS/{os_name}/{pkg_name}.json"


def _vendor_advisory(os_name: str, pkg_name: str) -> dict[str, Any]:
    return {
        "NoAdvisory": False,
        "AdvisorySummary": [
            {"ID": pkg_name, "Link": _advisory_url(os_name, pkg_name)},
        ],
    }


def _namespace_name(os_name: str, os_version: str, channel: str | None = None) -> str:
    ns = f"{namespace}-{os_name}:{os_version}"
    if channel:
        ns += f"+{channel}"
    return ns


# base distros whose native stream is named by the distro itself (e.g. a debian-identified event
# in the debian tree is a stock debian build). Those events fold into the channel-less namespace
# alongside the unidentified ones, which is what NATIVE_FOLD_DISTROS gates the fold-safety guard on.
NATIVE_FOLD_DISTROS = ("ubuntu", "debian")


def _channel_for(os_name: str, os_version: str, identifier: str | None) -> str | None:
    """Map an event's release-stream identifier to a namespace channel.

    None means the event belongs to the image's native (channel-less) namespace:
    - redhat events identified as el{major} are the native stream for that major
    - ubuntu/debian events identified with the distro's own name (distro-patched builds) or
      carrying no identifier (upstream/vendored builds) are both native; the fold-safety guard
      in the parser ensures those two never carry conflicting ranges for the same CVE+package
    - alpine events carry no identifiers at all

    Anything else is a foreign stream and gets a channel. Note that the native identifier must
    fold rather than pass through: a channel literally named after the base distro is one no
    client routes to, so every record in it would be unreachable.
    """
    if not identifier:
        return None
    ident = str(identifier).strip().lower()
    if not ident:
        return None
    if os_name == "redhat" and ident == f"el{os_version}":
        return None
    if os_name in NATIVE_FOLD_DISTROS and ident == os_name:
        return None
    return ident


class Parser:
    """Parser for RapidFort security advisories."""

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
        repo_url: str | None = None,
        supported_oses: tuple[str, ...] | None = None,
        timeout: int | None = None,
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
            timeout=timeout,
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
        base_dir = os.path.join(self._checkout_dest, repo_os_path)

        if not os.path.isdir(base_dir):
            self.logger.warning("RapidFort OS root not found: %s", base_dir)
            return

        for os_name in self.supported_oses:
            yield from self._load_os(base_dir, os_name)

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
        if not result or not result.date:
            return None

        return {
            "Date": result.date.isoformat(),
            "Kind": result.kind,
        }

    def _build_fixed_in_elements(  # noqa: PLR0913
        self,
        vid: str,
        os_name: str,
        pkg_name: str,
        range_pairs: list[tuple[str, str]],
        ecosystem: str,
        version_format: str,
    ) -> list[dict[str, Any]]:
        """Build FixedIn entries from pre-computed advisory event range pairs."""

        fixed_elements: list[dict[str, Any]] = []
        for range_str, fix_version in range_pairs:
            fixed_el = {
                "Name": pkg_name,
                "NamespaceName": ecosystem,
                "VersionFormat": version_format,
                "Version": fix_version,
                "VulnerableRange": range_str,
                "VendorAdvisory": _vendor_advisory(os_name, pkg_name),
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

    def _normalize_os_version(self, os_name: str, os_version: str) -> str | None:
        """Normalize an advisory's OS version key; return None (with a warning) when unusable.

        The redhat tree mostly keys on the bare numeric major ("9") but a handful of files use
        an el-prefixed form ("el4"); normalize those to the numeric major.
        """
        version = str(os_version).strip()
        if os_name == "redhat" and version.startswith("el") and version[2:].isdigit():
            version = version[2:]
        if not version or not version[0].isdigit():
            self.logger.warning("skipping advisory with unusable OS version key %r for %s", os_version, os_name)
            return None
        return version

    def _apply_fold_safety(
        self,
        os_name: str,
        vid: str,
        pkg_name: str,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Guard the native fold for distros that name their own stream (see NATIVE_FOLD_DISTROS).

        Both the distro-identified stream (distro-patched builds) and the unidentified stream
        (upstream/vendored builds) fold into the channel-less namespace. That is safe only while
        no CVE+package entry carries events from BOTH streams (verified against the full dataset:
        0 of 30,699 ubuntu entries, and 0 overlapping CVE+package pairs for debian). If the data
        ever changes, folding both would OR-merge cross-stream constraints — so degrade loudly and
        keep only the distro-patched events.
        """
        if os_name not in NATIVE_FOLD_DISTROS:
            return events

        def ident(ev: dict[str, Any]) -> str:
            return str(ev.get("identifier") or "").strip().lower()

        has_native = any(ident(ev) == os_name for ev in events if isinstance(ev, dict))
        has_unidentified = any(not ident(ev) for ev in events if isinstance(ev, dict))
        if has_native and has_unidentified:
            self.logger.warning(
                "%s/%s carries both %s-identified and unidentified events; "
                "keeping only the %s-identified events to avoid merging release streams",
                vid,
                pkg_name,
                os_name,
                os_name,
            )
            return [ev for ev in events if not isinstance(ev, dict) or ident(ev)]
        return events

    def _partition_events_by_channel(
        self,
        os_name: str,
        os_version: str,
        vid: str,
        pkg_name: str,
        events: list[dict[str, Any]],
    ) -> dict[str | None, list[dict[str, Any]]]:
        """Group events by their namespace channel (None = the native, channel-less namespace).

        Cross-el noise (e.g. an el8-identified event under the redhat 9 key — a handful of
        entries in the dataset) is dropped with a warning: it belongs to neither the native
        stream nor any stream a scanned package can be routed to within this OS version.
        """
        by_channel: dict[str | None, list[dict[str, Any]]] = {}
        for ev in events:
            if not isinstance(ev, dict):
                continue
            identifier = ev.get("identifier")
            channel = _channel_for(os_name, os_version, identifier)
            if channel is not None and os_name == "redhat" and channel.startswith("el"):
                self.logger.warning(
                    "%s/%s: dropping cross-release event identified %r under %s %s",
                    vid,
                    pkg_name,
                    identifier,
                    os_name,
                    os_version,
                )
                continue
            by_channel.setdefault(channel, []).append(ev)
        return by_channel

    def _normalize(
        self,
        os_name: str,
        os_version: str,
        pkg_name: str,
        cve_map: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Convert RapidFort advisory to vunnel OSSchema vulnerability records, keyed by namespace.

        Uses grype-compatible namespace format: provider-distroType:version[+channel]
        (e.g. rapidfort-ubuntu:22.04, rapidfort-redhat:9+fc43) so grype stores RF advisories
        under a provider-prefixed OS name isolated from standard distro scans, with one OS
        channel per release stream.
        """
        result: dict[str, dict[str, Any]] = {}
        version_format = version_formats.get(os_name.lower(), "dpkg")

        for cve_id, cve_entry in cve_map.items():
            vid, entry = self._get_valid_cve_entry(cve_id, cve_entry)
            if not vid or entry is None:
                continue

            events = self._apply_fold_safety(os_name, vid, pkg_name, entry.get("events") or [])

            for channel, channel_events in self._partition_events_by_channel(
                os_name,
                os_version,
                vid,
                pkg_name,
                events,
            ).items():
                # Build FixedIn from events (one per introduced/fixed pair, like GHSA)
                range_pairs = _events_to_range_pairs(channel_events)
                if not range_pairs:
                    continue

                ns = _namespace_name(os_name, os_version, channel)
                vuln_dict = result.setdefault(ns, {})

                vuln_record = self._get_or_create_vuln_record(
                    vuln_dict=vuln_dict,
                    vid=vid,
                    cve_entry=entry,
                    ecosystem=ns,
                )

                for fixed_el in self._build_fixed_in_elements(
                    vid=vid,
                    os_name=os_name,
                    pkg_name=pkg_name,
                    range_pairs=range_pairs,
                    ecosystem=ns,
                    version_format=version_format,
                ):
                    vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return result

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
            os_version = self._normalize_os_version(os_name, version)
            if not os_version:
                continue
            for ns, normalized in self._normalize(os_name, os_version, pkg_name, cve_map).items():
                self._merge_into_namespace(namespace_vulns, ns, normalized)

        for ns, vuln_dict in namespace_vulns.items():
            yield ns, vuln_dict
