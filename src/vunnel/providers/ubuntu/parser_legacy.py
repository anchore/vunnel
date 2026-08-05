"""Vendored slice of the v3 ubuntu parser for consuming normalized-cve-data.

Phase 1 of the OSV rewrite reads the existing `input/normalized-cve-data/`
cache (already on every workspace that ran the v3 provider) and emits
OS-schema envelopes for Ubuntu releases that have never appeared in
Canonical's OSV feed (precise, quantal, raring, …, mantic). Those
records are passed through `map_parsed()`, which is lifted verbatim
from v3 with everything else stripped: no `GitWrapper`, no patch-state
resolver, no rev-history walker, no `parse_cve_file` (input is already
JSON).

Phase 2 will convert normalized-cve-data into the fragment shape once
and drop this file entirely.
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vunnel.tool import fixdate


namespace = "ubuntu"
ubuntu_pkg_version_format = "dpkg"
ubuntu_cve_url = "https://ubuntu.com/security/{}"


# Per the Ubuntu README in the security tracker BZR repo:
# Maps the state name to whether it indicates a package is vulnerable.
patch_states = {
    "DNE": False,
    "needs-triage": True,
    "ignored": True,
    "not-affected": False,
    "needed": True,
    "released": True,
    "pending": True,
    "active": True,
    "deferred": True,
}

# Used to merge end-of-life records (status == "ignored" with version text matching the regex).
patch_merge_criteria = {
    "status": re.compile(r"ignored"),
    "version": re.compile(
        r"(^|.*\s+)(end[\s-]of[\s-]life|end[\s-]of[\s-]standard[\s-]support|out[\s-]of[\s-]standard[\s-]support)($|\s+|\,.*)",
    ),
}

# Codename -> version. Phase 1 keeps this hardcoded; phase 2 sources from endoflife.date.
ubuntu_version_names = {
    "precise": "12.04",
    "quantal": "12.10",
    "raring": "13.04",
    "trusty": "14.04",
    "utopic": "14.10",
    "vivid": "15.04",
    "wily": "15.10",
    "xenial": "16.04",
    "yakkety": "16.10",
    "zesty": "17.04",
    "artful": "17.10",
    "bionic": "18.04",
    "cosmic": "18.10",
    "disco": "19.04",
    "eoan": "19.10",
    "focal": "20.04",
    "groovy": "20.10",
    "hirsute": "21.04",
    "impish": "21.10",
    "jammy": "22.04",
    "kinetic": "22.10",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
    "questing": "25.10",
    "resolute": "26.04",
}


class JsonifierMixin:
    def json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in vars(self).items():
            if k.startswith("_"):
                continue
            if isinstance(v, (list, set)):
                out[k] = [x.json() if hasattr(x, "json") and callable(x.json) else x for x in v]
            elif isinstance(v, dict):
                out[k] = {x: y.json() if hasattr(y, "json") and callable(y.json) else y for x, y in v.items()}
            elif hasattr(v, "json"):
                out[k] = v.json()
            else:
                out[k] = v
        return out


class Vulnerability(JsonifierMixin):
    """v3-compatible vulnerability shape. PascalCase preserved for downstream compatibility."""

    def __init__(self) -> None:
        self.Name: str | None = None
        self.NamespaceName: str | None = None
        self.Description: str = ""
        self.Severity: Severity | None = None
        self.Metadata: dict[str, Any] | None = None
        self.Link: str | None = None
        self.FixedIn: list[FixedIn] = []


class FixedIn(JsonifierMixin):
    def __init__(self) -> None:
        self.Name: str | None = None
        self.NamespaceName: str | None = None
        self.VersionFormat: str | None = None
        self.Version: str | None = None
        self.VendorAdvisory: dict[str, Any] | None = None
        self.Available: FixAvailability | None = None


class FixAvailability(JsonifierMixin):
    def __init__(self) -> None:
        self.Date: str | None = None
        self.Kind: str | None = None


class Severity(enum.IntEnum):
    Unknown = 1
    Negligible = 2
    Low = 3
    Medium = 4
    High = 5
    Critical = 6

    def json(self) -> str:
        return self.name


@dataclass
class Patch:
    distro: str
    status: str
    version: str | None
    package: str | None = None
    priority: str | None = None


@dataclass
class CVEFile:
    name: str
    priority: str = "Unknown"
    patches: list[Patch] = field(default_factory=list)
    ignored_patches: list[Patch] = field(default_factory=list)
    git_last_processed_rev: str | None = None
    references: list[str] | None = None
    description: str | None = None

    @staticmethod
    def from_dict(d: dict[str, Any]) -> CVEFile:
        # name is required — v3 records always carry it as "name"/"Name"/"candidate"/"Candidate".
        # Coerce to str (empty if absent) so the field type matches; map_parsed treats empty as
        # invalid via the `if not parsed_cve.name` guard and returns an empty set.
        name = d.get("name") or d.get("Name") or d.get("candidate") or d.get("Candidate") or ""
        return CVEFile(
            name=name,
            priority=d.get("priority", d.get("Priority", "Unknown")),
            patches=[Patch(**p) for p in d.get("patches", [])],
            ignored_patches=[Patch(**p) for p in d.get("ignored_patches", [])],
            git_last_processed_rev=d.get("git_last_processed_rev"),
            references=d.get("references", d.get("References")),
            description=d.get("description", d.get("Description")),
        )


def check_state(state: str | None) -> bool:
    if not state:
        return False
    return bool(patch_states.get(state))


def check_merge(patch_record: Patch | None) -> bool:
    if not patch_record:
        return False
    patch_dict = asdict(patch_record)
    return all(patch_dict.get(key) and re.match(regex, patch_dict.get(key) or "") for key, regex in patch_merge_criteria.items())


def map_namespace(release_name: str) -> str | None:
    """Return `ubuntu:<version>` for a known codename, else None."""
    dist = ubuntu_version_names.get(release_name)
    if dist:
        return f"{namespace}:{dist}"
    return None


def parse_severity_from_priority(cve: CVEFile) -> Severity:
    raw = (cve.priority or "Unknown").capitalize()
    if raw == "Untriaged":
        return Severity.Unknown
    try:
        return getattr(Severity, raw)
    except AttributeError:
        return Severity.Unknown


def map_parsed(  # noqa: C901, PLR0912, PLR0915
    parsed_cve: CVEFile,
    fixdater: fixdate.Finder,
    logger: logging.Logger | None = None,
) -> set[Vulnerability]:
    """Map a parsed CVE (from normalized-cve-data) into a set of Vulnerability records, one per namespace.

    Lifted from v3 parser.map_parsed with no behavioral changes — the
    fragment-shape rewrite only changes how OSV data is handled, not
    legacy passthrough.
    """
    if not logger:
        logger = logging.getLogger(__name__)

    vulns: dict[str, Vulnerability] = {}
    if not parsed_cve.name:
        logger.error(f"could not find a Name for parsed cve: {asdict(parsed_cve)}")
        return set()

    # Build a set of (bare_codename, package) pairs where an ESM variant confirms the
    # package is not affected. This lets us downgrade "needs-triage" on the base release
    # to "not-affected" when ESM has already confirmed it.
    _esm_prefixes = ("esm-apps/", "esm-infra/", "esm-infra-legacy/")
    esm_not_affected: set[tuple[str, str | None]] = set()
    for ip in parsed_cve.ignored_patches:
        if ip.status != "not-affected":
            continue
        # Skip entries where the version field is a version string (a fix version).
        if ip.version and ip.version[:1].isdigit():
            continue
        for prefix in _esm_prefixes:
            if ip.distro.startswith(prefix):
                esm_not_affected.add((ip.distro[len(prefix) :], ip.package))
                break

    for p in parsed_cve.patches:
        namespace_name = map_namespace(p.distro)
        if not namespace_name:
            continue

        r = vulns.get(namespace_name)
        if not r:
            r = Vulnerability()
            try:
                r.Severity = parse_severity_from_priority(parsed_cve)
            except Exception:
                logger.exception(f"setting unknown severity on {parsed_cve.name}")
                r.Severity = Severity.Unknown
            r.Name = parsed_cve.name
            r.Metadata = {}
            r.Link = ubuntu_cve_url.format(r.Name)
            r.FixedIn = []
            r.NamespaceName = namespace_name
            vulns[namespace_name] = r

        # Explicit "not affected" → emit a FixedIn with version "0".
        if p.status == "not-affected":
            pkg = FixedIn()
            pkg.Name = p.package
            pkg.Version = "0"
            pkg.VendorAdvisory = {"NoAdvisory": False}
            pkg.VersionFormat = ubuntu_pkg_version_format
            pkg.NamespaceName = namespace_name
            r.FixedIn.append(pkg)
            continue

        if not (check_state(p.status) or check_merge(p)):
            continue

        # Downgrade needs-triage to not-affected when an ESM variant has confirmed it.
        if p.status == "needs-triage" and (p.distro, p.package) in esm_not_affected:
            logger.debug(
                f"emitting not-affected for {parsed_cve.name} {p.distro}/{p.package}: ESM variant confirms not-affected",
            )
            pkg = FixedIn()
            pkg.Name = p.package
            pkg.Version = "0"
            pkg.VendorAdvisory = {"NoAdvisory": False}
            pkg.VersionFormat = ubuntu_pkg_version_format
            pkg.NamespaceName = namespace_name
            r.FixedIn.append(pkg)
            continue

        pkg = FixedIn()
        pkg.Name = p.package

        if p.status == "released":
            pkg.Version = p.version
            if pkg.Version is None:
                logger.debug(
                    f"{r.Name} on {r.NamespaceName} pkg {pkg.Name}: released status but no version; omitting FixedIn",
                )
                continue
            result = fixdater.best(
                vuln_id=r.Name or "",
                cpe_or_package=pkg.Name or "",
                fix_version=pkg.Version,
                ecosystem=r.NamespaceName or "",
            )
            if result and result.date:
                fa = FixAvailability()
                fa.Date = result.date.isoformat()
                fa.Kind = result.kind
                pkg.Available = fa
        else:
            pkg.Version = "None"
            if p.status == "ignored":
                pkg.VendorAdvisory = {"NoAdvisory": True}

        if not pkg.VendorAdvisory:
            pkg.VendorAdvisory = {"NoAdvisory": False}
        pkg.VersionFormat = ubuntu_pkg_version_format
        pkg.NamespaceName = namespace_name
        r.FixedIn.append(pkg)

        # Promote severity using any per-package priority.
        if p.priority and r.Severity is not None:
            try:
                pkg_sev = getattr(Severity, p.priority.capitalize())
                r.Severity = max(pkg_sev, r.Severity)
            except AttributeError:
                pass

    return set(vulns.values())
