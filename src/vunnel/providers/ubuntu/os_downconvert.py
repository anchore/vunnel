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

Pro/FIPS/Realtime/BlueField fragments are skipped entirely — v3 never emitted
records for those namespaces. Pro-only-fix data still surfaces here because
`_yield_base_with_inferences` has already merged wont-fix entries into the
base ecosystem's affected[] list before this code runs.
"""

from __future__ import annotations

import re
from typing import Any

_UBUNTU_PKG_VERSION_FORMAT = "dpkg"
_UBUNTU_CVE_URL = "https://ubuntu.com/security/{}"

_BASE_ECO_RE = re.compile(r"^Ubuntu:(\d+\.\d+)(?::LTS)?$")

# v3 severity values, mirroring parser_legacy.Severity.json() output.
_SEVERITY_NAMES = {"Negligible", "Low", "Medium", "High", "Critical", "Unknown"}


def osv_ecosystem_to_os_namespace(ecosystem: str) -> str | None:
    """Map an OSV ecosystem string to v3's `ubuntu:<version>` namespace.

    Only base Ubuntu releases qualify. Pro/FIPS/Realtime/BlueField return
    None and are skipped by downconversion — v3 never emitted records for
    those namespaces, and Pro-only-fix inference already layers wont-fix
    entries onto the base ecosystem's affected[] list upstream.

      Ubuntu:22.04:LTS              -> ubuntu:22.04
      Ubuntu:24.10                  -> ubuntu:24.10
      Ubuntu:Pro:14.04:LTS          -> None
      Ubuntu:Pro:FIPS:22.04:LTS     -> None
      Ubuntu:Nvidia-BlueField:22.04 -> None
    """
    m = _BASE_ECO_RE.match(ecosystem)
    if m is None:
        return None
    return f"ubuntu:{m.group(1)}"


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
    """
    package_name = (aff.get("package") or {}).get("name")
    if not package_name:
        return []

    fixed_versions = _fixed_versions_for_affected(aff)
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


def osv_to_os(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Convert an OSV envelope payload into a v3-shape `{"Vulnerability": {...}}` dict.

    Returns None when the payload can't be downconverted:
      - no `upstream[0]` CVE id (v3 always emitted `CVE-*` names, never internal ids)
      - no affected[] entries map to a base Ubuntu namespace (Pro-only fragment, etc.)

    Caller is responsible for choosing the identifier and schema. This
    function just produces the payload.
    """
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
        ns = osv_ecosystem_to_os_namespace(eco)
        if ns is None:
            continue
        # By the slicing invariant, every affected[] entry in a single envelope
        # shares the same ecosystem — so we'll only see one namespace here.
        if namespace is None:
            namespace = ns
        fixed_in.extend(_fixed_in_for_affected(aff, ns))

    if namespace is None:
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


def os_identifier_for(payload: dict[str, Any]) -> str | None:
    """Build the v3-shape `{namespace}/{cve_name.lower()}` identifier for a downconverted record."""
    upstream = payload.get("upstream") or []
    if not upstream or not upstream[0]:
        return None
    for aff in payload.get("affected", []) or []:
        eco = (aff.get("package") or {}).get("ecosystem", "")
        ns = osv_ecosystem_to_os_namespace(eco)
        if ns is not None:
            return f"{ns}/{upstream[0].lower()}"
    return None
