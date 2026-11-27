"""RapidFort security advisories parser.

Reads RapidFort advisory data and normalizes to vunnel OSSchema format.
Supports Ubuntu and Debian (dpkg), Alpine (apk), and Red Hat, Rocky, Alma, Oracle and Amazon
(rpm); see base_oses.

Input format: OS/{os}/{package}.json with package_name, advisory: {version: {CVE: ...}}

RapidFort images mix packages from several release streams (e.g. native el9 builds, Fedora
builds, and RapidFort rebuilds inside one rapidfort-redhat:9 image). Each advisory event may
carry an `identifier` naming its stream (el9, fc43, rf, amzn2023, ubuntu, ...). Streams are
emitted as separate grype namespaces so their fix ranges are never merged into one constraint:

- the image's native stream (el{major} for the EL family, amzn{release} for amazon, ubuntu or
  debian for those trees) and unidentified events (all of alpine today) fold into the channel-less
  namespace, e.g. rapidfort-redhat:9, so a package that matches no client-side routing rule degrades
  to sane native-stream matching
- foreign/rebuild streams get a +channel namespace, e.g. rapidfort-redhat:9+fc43,
  rapidfort-ubuntu:20.04+rf, or rapidfort-redhat:10+el9 for an el9 build shipped in RHEL 10
  images, which grype routes to per package via version/name markers

Everything read from the archive is upstream data that ends up in namespace names, record ids and
version constraints, so it is validated as it is loaded and anything unrecognized is skipped with a
warning rather than passed through.
"""

from __future__ import annotations

import copy
import logging
import os
import re
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper, vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

logger = logging.getLogger(__name__)

namespace = "rapidfort"
default_archive_url = "https://github.com/rapidfort/security-advisories/archive/refs/heads/main.zip"
advisory_base_url = "https://github.com/rapidfort/security-advisories/blob/main"
repo_os_path = "OS"  # OS/{osName}/{package}.json (source format)

# every release stream seen upstream: EL majors, Fedora releases, Amazon releases and RapidFort rebuilds.
# grype only routes to channels it knows about, so records under any other channel would be unreachable
known_channel = re.compile(r"(el|fc|amzn)[0-9]+|rf")

# vulnerability ids upstream uses. They double as result identifiers, so nothing else gets through
vuln_id_pattern = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[0-9a-z]{4}){3}|DSA-[0-9]+-[0-9]+|DLA-[0-9]+-[0-9]+", re.IGNORECASE)

os_version_pattern = re.compile(r"[0-9]+(\.[0-9]+)*")

# characters that would change the meaning of a version constraint if interpolated into one
unsafe_version_chars = re.compile(r"[\s,<>=|]")


@dataclass(frozen=True)
class BaseOS:
    """How one OS/{name} tree of the advisory repo maps onto grype."""

    # the grype distro type the namespaces are named after (rapidfort-{distro}), which grype's
    # RapidFort identifier remaps the detected base distro to
    distro: str
    version_format: str
    # the identifier of the image's own release stream, with {version} standing for the release key
    # (e.g. "el{version}"); None for a tree whose events carry no identifiers
    native_identifier: str | None

    def native_stream(self, os_version: str) -> str | None:
        if not self.native_identifier:
            return None
        return self.native_identifier.format(version=os_version)

    @property
    def release_prefix(self) -> str:
        """The native identifier's prefix before the version (e.g. "el"), which a few release keys carry."""
        if not self.native_identifier or "{version}" not in self.native_identifier:
            return ""
        return self.native_identifier.partition("{version}")[0]


# keyed by the repo's OS/{name} directory; onboarding a base OS is one entry here plus its distro in
# grype's RapidFort identifier
base_oses = {
    "ubuntu": BaseOS(distro="ubuntu", version_format="dpkg", native_identifier="ubuntu"),
    "debian": BaseOS(distro="debian", version_format="dpkg", native_identifier="debian"),
    "alpine": BaseOS(distro="alpine", version_format="apk", native_identifier=None),
    "redhat": BaseOS(distro="redhat", version_format="rpm", native_identifier="el{version}"),
    "rocky": BaseOS(distro="rockylinux", version_format="rpm", native_identifier="el{version}"),
    "alma": BaseOS(distro="almalinux", version_format="rpm", native_identifier="el{version}"),
    "oracle": BaseOS(distro="oraclelinux", version_format="rpm", native_identifier="el{version}"),
    "amazon": BaseOS(distro="amazonlinux", version_format="rpm", native_identifier="amzn{version}"),
}


def _vuln_ids(raw: Any) -> list[str]:
    """Extract canonical vulnerability ids from an advisory's cve_id.

    Upstream occasionally packs several ids into one key ("CVE-a, CVE-b", "CVE-aCVE-b") or appends a
    note ("CVE-a follow-up"), so every id found gets its own record. GHSA ids keep their canonical
    lowercase body, everything else is uppercased.
    """
    ids: list[str] = []
    for m in vuln_id_pattern.finditer(str(raw)):
        vid = m.group(0)
        vid = "GHSA-" + vid[5:].lower() if vid[:5].upper() == "GHSA-" else vid.upper()
        if vid not in ids:
            ids.append(vid)
    return ids


def _is_plain_version(value: Any) -> bool:
    return isinstance(value, str) and not unsafe_version_chars.search(value)


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
        if any(v and not _is_plain_version(v) for v in (introduced, fixed)):
            logger.warning("skipping RapidFort event with unusable version(s): introduced=%r fixed=%r", introduced, fixed)
            continue

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
    # upstream names every advisory file {package_name}_advisory.json
    return f"{advisory_base_url}/{repo_os_path}/{os_name}/{pkg_name}_advisory.json"


def _vendor_advisory(os_name: str, pkg_name: str) -> dict[str, Any]:
    return {
        "NoAdvisory": False,
        "AdvisorySummary": [
            {"ID": pkg_name, "Link": _advisory_url(os_name, pkg_name)},
        ],
    }


def _namespace_name(os_name: str, os_version: str, channel: str | None = None) -> str:
    ns = f"{namespace}-{base_oses[os_name].distro}:{os_version}"
    if channel:
        ns += f"+{channel}"
    return ns


def _channel_for(os_name: str, os_version: str, identifier: str | None) -> str | None:
    """Map an event's release-stream identifier to a namespace channel.

    None means the event belongs to the image's native (channel-less) namespace:
    - EL-family events identified as el{release} (amazon: amzn{release}) are the native stream
    - ubuntu/debian events identified with the distro's own name (distro-patched builds) are native
    - events carrying no identifier (upstream/vendored builds, and all of alpine today) are native;
      the fold-safety guard in the parser ensures they never mix with native-stream events for the
      same CVE+package

    Anything else is a foreign stream and gets a channel, including a build for another release of
    the same family (el9 under the redhat 10 key). Note that the native identifier must fold rather
    than pass through: grype searches the channel-less namespace for native builds, so records filed
    under a channel named for the native stream would be unreachable.
    """
    if not identifier:
        return None
    ident = str(identifier).strip().lower()
    if not ident:
        return None
    base = base_oses.get(os_name)
    if base and ident == base.native_stream(os_version):
        return None
    return ident


class Parser:
    """Parser for RapidFort security advisories."""

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
        archive_url: str = default_archive_url,
        download_timeout: int = 125,
        skip_download: bool = False,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace, skip_download=skip_download)
        self.fixdater = fixdater
        self.workspace = workspace
        self.archive_url = archive_url
        self.urls = [archive_url]
        self.download_timeout = download_timeout
        self.skip_download = skip_download

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self._archive_path = os.path.join(self.workspace.input_path, "rapidfort-advisories.zip")
        # unknown release streams already warned about, so each is reported once per run
        self._unknown_channels: set[str] = set()

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
        """Download the repo's branch archive (much faster and smaller than cloning ~35k files)."""
        if self.skip_download:
            self.logger.info("skip_download is enabled, using existing archive at %s", self._archive_path)
            return
        http_wrapper.download_to_file(self.archive_url, self._archive_path, self.logger, timeout=self.download_timeout)

    def _load_package_file(
        self,
        archive: zipfile.ZipFile,
        file_path: str,
        os_name: str,
    ) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        try:
            with archive.open(file_path) as f:
                data = orjson.loads(f.read())
        except Exception:
            self.logger.warning("Failed to parse %s", file_path, exc_info=True)
            return

        if not isinstance(data, dict):
            self.logger.warning("advisory file %s is not a JSON object, skipping", file_path)
            return

        pkg_name = data.get("package_name")
        if not pkg_name or not isinstance(pkg_name, str):
            self.logger.warning("missing or invalid package_name in %s, skipping", file_path)
            return

        advisory = data.get("advisory")
        if not isinstance(advisory, dict):
            return

        for os_version, cve_map in advisory.items():
            if isinstance(cve_map, dict) and cve_map:
                yield os_name, os_version, pkg_name, cve_map

    def _load_os(
        self,
        archive: zipfile.ZipFile,
        files: dict[str, dict[str, str]],
        os_name: str,
    ) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        entries = files.get(os_name)

        if not entries:
            self.logger.debug("RapidFort OS dir not found, skipping: %s/%s", repo_os_path, os_name)
            return

        for entry in sorted(entries):
            if not entry.endswith(".json"):
                continue

            yield from self._load_package_file(archive, entries[entry], os_name)

    def _load(self) -> Generator[tuple[str, str, str, dict[str, Any]]]:
        """Yield (os_name, os_version, package_name, cve_map) from OS/{os}/{package}.json in the archive."""
        with zipfile.ZipFile(self._archive_path) as archive:
            # members look like {repo}-{branch}/OS/{os}/{package}.json; index files by os and basename
            files: dict[str, dict[str, str]] = {}
            for info in archive.infolist():
                parts = info.filename.split("/")
                if info.is_dir() or len(parts) != 4 or parts[1] != repo_os_path:
                    continue
                files.setdefault(parts[2], {})[parts[3]] = info.filename

            if not files:
                self.logger.warning("RapidFort OS root not found in archive: %s", self._archive_path)
                return

            unknown = sorted(set(files) - set(base_oses))
            if unknown:
                self.logger.warning("skipping RapidFort OS trees with no known base OS: %s", ", ".join(unknown))

            for os_name in base_oses:
                yield from self._load_os(archive, files, os_name)

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

        The EL trees mostly key on the bare numeric major ("9") but a handful of files use an
        el-prefixed form ("el4"); normalize those to the numeric major.
        """
        version = str(os_version).strip()
        prefix = base_oses[os_name].release_prefix if os_name in base_oses else ""
        if prefix and version.startswith(prefix):
            version = version[len(prefix) :]
        # the version becomes part of the namespace (and so of each result identifier): digits and dots only
        if not os_version_pattern.fullmatch(version):
            self.logger.warning("skipping advisory with unusable OS version key %r for %s", os_version, os_name)
            return None
        return version

    def _apply_fold_safety(
        self,
        os_name: str,
        os_version: str,
        vid: str,
        pkg_name: str,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Guard the native fold: never merge native-stream and unidentified events into one namespace.

        Both the native stream (el9 under redhat 9, ubuntu under ubuntu, ...) and unidentified events
        fold into the channel-less namespace. That is safe only while no CVE+package entry carries
        events from BOTH (verified against the full dataset: no tree has such an entry today). If the
        data ever changes, folding both would OR-merge cross-stream constraints, so degrade loudly
        and keep only the native-stream events.
        """
        native = base_oses[os_name].native_stream(os_version)
        if not native:
            return events

        def ident(ev: dict[str, Any]) -> str:
            return str(ev.get("identifier") or "").strip().lower()

        has_native = any(ident(ev) == native for ev in events if isinstance(ev, dict))
        has_unidentified = any(not ident(ev) for ev in events if isinstance(ev, dict))
        if has_native and has_unidentified:
            self.logger.warning(
                "%s/%s carries both %s-identified and unidentified events; keeping only the identified events to avoid merging release streams",
                vid,
                pkg_name,
                native,
            )
            return [ev for ev in events if not isinstance(ev, dict) or ident(ev)]
        return events

    def _partition_events_by_channel(
        self,
        os_name: str,
        os_version: str,
        events: list[dict[str, Any]],
    ) -> dict[str | None, list[dict[str, Any]]]:
        """Group events by their namespace channel (None = the native, channel-less namespace)."""
        by_channel: dict[str | None, list[dict[str, Any]]] = {}
        for ev in events:
            if not isinstance(ev, dict):
                continue
            channel = _channel_for(os_name, os_version, ev.get("identifier"))
            if channel is not None and not known_channel.fullmatch(channel):
                if channel not in self._unknown_channels:
                    self._unknown_channels.add(channel)
                    self.logger.warning("skipping events from unknown RapidFort release stream %r (grype has no routing for it)", channel)
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
        version_format = base_oses[os_name].version_format

        for cve_id, entry in cve_map.items():
            if not isinstance(entry, dict):
                continue

            raw_id = entry.get("cve_id") or cve_id
            vids = _vuln_ids(raw_id)
            if not vids:
                self.logger.warning("skipping %s/%s advisory with unrecognized vulnerability id %r", os_name, pkg_name, raw_id)
                continue

            events = entry.get("events") or []
            if not isinstance(events, list):
                self.logger.warning("skipping %s/%s %s: events is not a list", os_name, pkg_name, raw_id)
                continue

            events = self._apply_fold_safety(os_name, os_version, raw_id, pkg_name, events)
            by_channel = self._partition_events_by_channel(os_name, os_version, events)

            for vid in vids:
                for channel, channel_events in by_channel.items():
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

                    fixed_in = vuln_record["Vulnerability"]["FixedIn"]
                    for fixed_el in self._build_fixed_in_elements(
                        vid=vid,
                        os_name=os_name,
                        pkg_name=pkg_name,
                        range_pairs=range_pairs,
                        ecosystem=ns,
                        version_format=version_format,
                    ):
                        # a split id ("CVE-a follow-up") can repeat a range already recorded under the same id
                        if fixed_el not in fixed_in:
                            fixed_in.append(fixed_el)

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
        """Download repo archive, load advisories, normalize and yield (namespace, vuln_dict)."""
        # fixdate first: if it fails there is no point fetching the much larger advisory archive
        self.fixdater.download()

        self._download()

        namespace_vulns: dict[str, dict[str, dict[str, Any]]] = {}

        for os_name, version, pkg_name, cve_map in self._load():
            os_version = self._normalize_os_version(os_name, version)
            if not os_version:
                continue
            for ns, normalized in self._normalize(os_name, os_version, pkg_name, cve_map).items():
                self._merge_into_namespace(namespace_vulns, ns, normalized)

        for ns, vuln_dict in namespace_vulns.items():
            yield ns, vuln_dict
