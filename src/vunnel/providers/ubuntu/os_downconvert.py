"""Downconvert per-record OSV envelopes into v3's OS-schema Vulnerability shape.

This is an opt-in compatibility path for consumers stuck on a grype-db build
process that pre-dates the OSV transformer. When enabled, OSV envelopes
yielded out of the per-ecosystem fragments are rewritten into the same
`{"Vulnerability": {...}}` payload the v3 ubuntu provider produced. The
normalized-cve-data legacy passthrough is left alone — it already emits OS.

The mapping mirrors v3's `map_parsed` behavior on equivalent inputs:

  OSV ecosystem        → OS NamespaceName        (Ubuntu:22.04:LTS → ubuntu:22.04)
  upstream[0]          → Vulnerability.Name      (UBUNTU-CVE-* is internal; CVE-* is what v3 emitted)
  severity[type=Ubuntu]→ Vulnerability.Severity  (Negligible/Low/Medium/High/Critical, or Unknown)
  affected[].package.name → FixedIn.Name (one FixedIn per source package per ecosystem slice)
  ranges[].events[].fixed → FixedIn.Version (the dpkg fix version)
  no fixed event + status=wont-fix → FixedIn.Version="None", VendorAdvisory.NoAdvisory=True
  no fixed event, no wont-fix      → FixedIn.Version="None", VendorAdvisory.NoAdvisory=False
  database_specific.anchore.fixes[0] → FixedIn.Available (Date/Kind)

Plain Ubuntu Pro (ESM) fragments — `Ubuntu:Pro:X.YY:LTS` — are emitted as a
distro channel: `ubuntu:X.YY+esm`, mirroring RHEL EUS's `rhel:X.Y+eus`. The
real plain-Pro fix version flows through verbatim. FIPS / FIPS-updates /
Realtime / Nvidia-BlueField still map to None (their builds diverge from base,
so their fixes can't resolve a base disclosure). The `include_esm` flag gates the
`+esm` emit; when off, plain Pro maps to None like the sub-tiers.

The base wont-fix disclosure and the `+esm` fix are a paired split: the base
`ubuntu:X.YY` record carries the `Version:"None"` wont-fix (synthesized by
`_yield_base_with_inferences` when only Pro has data), and `ubuntu:X.YY+esm`
carries the actual fix. In practice a base-fixed CVE (fix in a standard pocket)
carries no `+esm` record: plain-Pro packages are byte-identical to base while
base is supported, so no separate ESM fixed event exists until standard support
ends. That's a property of Canonical's data, not something enforced here — any
plain-Pro slice with a real fixed event yields a `+esm` record regardless.

The `+esm` channel carries fixes only: a plain-Pro slice with no fixed event
(wont-fix or still-pending on Pro) produces no `+esm` record at all. The base
`ubuntu:X.YY` wont-fix is the sole disclosure for those — an unfixed `+esm`
record would just duplicate it with `Version:"None"`.
"""

from __future__ import annotations

import re
from typing import Any

_UBUNTU_PKG_VERSION_FORMAT = "dpkg"
_UBUNTU_CVE_URL = "https://ubuntu.com/security/{}"

_BASE_ECO_RE = re.compile(r"^Ubuntu:(\d+\.\d+)(?::LTS)?$")
# plain Ubuntu Pro (ESM) only: `Ubuntu:Pro:<ver>[:LTS]`, anchored so any extra
# tier token (FIPS, FIPS-updates, Realtime, ...) or trailing segment fails to match.
_PLAIN_PRO_ECO_RE = re.compile(r"^Ubuntu:Pro:(\d+\.\d+)(?::LTS)?$")

_ESM_SUFFIX = "+esm"

# v3 severity values, mirroring parser_legacy.Severity.json() output.
_SEVERITY_NAMES = {"Negligible", "Low", "Medium", "High", "Critical", "Unknown"}


def osv_ecosystem_to_os_namespace(ecosystem: str, include_esm: bool = True) -> str | None:
    """Map an OSV ecosystem string to a v3 `ubuntu:<version>[+esm]` namespace.

    Base Ubuntu releases map to `ubuntu:<version>`. Plain Ubuntu Pro (ESM)
    maps to the `ubuntu:<version>+esm` distro channel (mirroring RHEL EUS's
    `rhel:X.Y+eus`) when `include_esm` is set. FIPS/FIPS-updates/Realtime/
    Nvidia-BlueField always return None — their builds diverge from base, so
    their fixes can't resolve a base disclosure.

      Ubuntu:22.04:LTS              -> ubuntu:22.04
      Ubuntu:24.10                  -> ubuntu:24.10
      Ubuntu:Pro:14.04:LTS          -> ubuntu:14.04+esm   (None if include_esm=False)
      Ubuntu:Pro:22.04:LTS          -> ubuntu:22.04+esm
      Ubuntu:Pro:FIPS:22.04:LTS     -> None
      Ubuntu:Nvidia-BlueField:22.04 -> None
    """
    m = _BASE_ECO_RE.match(ecosystem)
    if m is not None:
        return f"ubuntu:{m.group(1)}"
    if include_esm:
        pm = _PLAIN_PRO_ECO_RE.match(ecosystem)
        if pm is not None:
            return f"ubuntu:{pm.group(1)}+esm"
    return None


def _ubuntu_priority_to_severity(score: str) -> str:
    """Map Canonical's Ubuntu-priority severity string to v3's Severity name.

    Canonical encodes per-CVE priority as one of negligible/low/medium/high/critical
    (lowercase) in `severity[type=Ubuntu].score`. v3 uses PascalCase names from
    the Severity IntEnum. "untriaged" → Unknown matches v3's fallback.
    """
    if not score:
        return "Unknown"
    capitalized = score.strip().capitalize()
    if capitalized == "Untriaged":
        return "Unknown"
    if capitalized in _SEVERITY_NAMES:
        return capitalized
    return "Unknown"


def _extract_severity(payload: dict[str, Any]) -> str:
    """Pull v3's Severity from OSV's severity[] array (type=Ubuntu wins)."""
    for entry in payload.get("severity", []) or []:
        if entry.get("type") == "Ubuntu":
            return _ubuntu_priority_to_severity(entry.get("score", ""))
    return "Unknown"


def _is_wont_fix(aff: dict[str, Any]) -> bool:
    anchore = (aff.get("database_specific") or {}).get("anchore") or {}
    return anchore.get("status") == "wont-fix"


def _fixed_versions_for_affected(aff: dict[str, Any]) -> list[str]:
    """Return the list of `fixed` versions across all ranges of an affected entry.

    A single affected entry typically has one range with one `fixed` event;
    multi-event ranges are rare. If multiple fixed events appear, emit a
    FixedIn for each (matches what v3 would do if cve-tracker had listed
    multiple "released" patches for the same source package).
    """
    out: list[str] = []
    for r in aff.get("ranges", []) or []:
        for ev in r.get("events", []) or []:
            fv = ev.get("fixed")
            if fv:
                out.append(fv)
    return out


def _fix_available_for_version(aff: dict[str, Any], version: str) -> dict[str, Any] | None:
    """Look up `database_specific.anchore.fixes[]` for the given fix version.

    `patch_fix_date` (called at yield time) writes entries like
    `{"version": "...", "date": "YYYY-MM-DD", "kind": "..."}` per fixed
    event. We re-emit Date/Kind in v3's `Available` shape so consumers
    can use it the same way they do for normalized-cve-data records.
    """
    for r in aff.get("ranges", []) or []:
        db_spec = r.get("database_specific") or {}
        anchore = db_spec.get("anchore") or {}
        for entry in anchore.get("fixes", []) or []:
            if entry.get("version") == version and entry.get("date"):
                return {"Date": entry["date"], "Kind": entry.get("kind")}
    return None


def _fixed_in_for_affected(aff: dict[str, Any], namespace: str) -> list[dict[str, Any]]:
    """Convert one OSV affected[] entry into one or more FixedIn dicts.

    Encoding rules (mirroring v3):

      - released-with-version (one or more `fixed` events)
          -> FixedIn(Version=<v>, NoAdvisory=False, Available=<date if known>)
      - wont-fix (no fixed events, status=wont-fix from VEX overlay or
        Pro-only-fix inference)
          -> FixedIn(Version="None", NoAdvisory=True)
      - no fix yet (no fixed events, no wont-fix marker)
          -> FixedIn(Version="None", NoAdvisory=False)

    Exception: on a `+esm` channel a no-fix entry yields nothing. That channel
    carries only real Pro fixes; the unfixed disclosure already lives on the
    base `ubuntu:X.YY` record, so a `Version="None"` +esm entry would just
    duplicate it.
    """
    package_name = (aff.get("package") or {}).get("name")
    if not package_name:
        return []

    fixed_versions = _fixed_versions_for_affected(aff)
    if not fixed_versions and namespace.endswith(_ESM_SUFFIX):
        return []
    if fixed_versions:
        out = []
        for v in fixed_versions:
            entry: dict[str, Any] = {
                "Name": package_name,
                "NamespaceName": namespace,
                "VersionFormat": _UBUNTU_PKG_VERSION_FORMAT,
                "Version": v,
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": _fix_available_for_version(aff, v),
            }
            out.append(entry)
        return out

    no_advisory = _is_wont_fix(aff)
    return [
        {
            "Name": package_name,
            "NamespaceName": namespace,
            "VersionFormat": _UBUNTU_PKG_VERSION_FORMAT,
            "Version": "None",
            "VendorAdvisory": {"NoAdvisory": no_advisory},
            "Available": None,
        },
    ]


def osv_to_os(payload: dict[str, Any], include_esm: bool = True) -> dict[str, Any] | None:
    """Convert an OSV envelope payload into a v3-shape `{"Vulnerability": {...}}` dict.

    Returns None when the payload can't be downconverted:
      - no `upstream[0]` CVE id (v3 always emitted `CVE-*` names, never internal ids)
      - no affected[] entries map to a base Ubuntu namespace (Pro-only fragment, etc.)

    Caller is responsible for choosing the identifier and schema. This
    function just produces the payload.
    """
    # Withdrawn records are retractions; the OS schema has no withdrawn concept,
    # so drop them rather than emit an affected-at-all-versions record.
    if payload.get("withdrawn"):
        return None

    upstream = payload.get("upstream") or []
    if not upstream:
        return None
    cve_name = upstream[0]
    if not cve_name:
        return None

    namespace: str | None = None
    fixed_in: list[dict[str, Any]] = []
    for aff in payload.get("affected", []) or []:
        eco = (aff.get("package") or {}).get("ecosystem", "")
        ns = osv_ecosystem_to_os_namespace(eco, include_esm=include_esm)
        if ns is None:
            continue
        # By the slicing invariant, every affected[] entry in a single envelope
        # shares the same ecosystem — so we'll only see one namespace here.
        if namespace is None:
            namespace = ns
        fixed_in.extend(_fixed_in_for_affected(aff, ns))

    if namespace is None:
        return None
    # a `+esm` channel with no real fix left is pure noise — the base wont-fix
    # already disclosed it (see _fixed_in_for_affected), so emit no record.
    if namespace.endswith(_ESM_SUFFIX) and not fixed_in:
        return None

    return {
        "Vulnerability": {
            "Name": cve_name,
            "NamespaceName": namespace,
            "Description": "",
            "Severity": _extract_severity(payload),
            "Metadata": {},
            "Link": _UBUNTU_CVE_URL.format(cve_name),
            "FixedIn": fixed_in,
        },
    }


def os_identifier_for(os_payload: dict[str, Any]) -> str:
    """Build the v3-shape `{namespace}/{cve_name.lower()}` identifier for an emitted OS payload.

    Takes the payload `osv_to_os` produced (not the OSV input) so the identifier
    can't drift from the record it names — there's one construction, shared by
    the parser's yield path.
    """
    vuln = os_payload["Vulnerability"]
    return f"{vuln['NamespaceName']}/{vuln['Name'].lower()}"
