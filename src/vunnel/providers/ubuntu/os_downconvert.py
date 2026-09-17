"""The v3 OS-schema record this provider emits, and the rules that decide each FixedIn.

Every record leaves here in the same `{"Vulnerability": {...}}` shape the v3
ubuntu provider produced, whichever source decided it. The emit path assembles
one CVE from three sources at once — the OSV feed, the OpenVEX feed and the
frozen tracker snapshot — and two of them can speak about a package the OSV
record does not carry, so there is no per-release OSV envelope to convert: the
disposition is assembled directly and the encoding rules live here.

The encoding, for one source package on one namespace:

  not-affected                     → FixedIn.Version="0", VendorAdvisory.NoAdvisory=False
  one or more fix versions         → one FixedIn per version, plus its fix date
  no fix, won't fix                → FixedIn.Version="None", VendorAdvisory.NoAdvisory=True
  no fix, not stated as won't fix  → FixedIn.Version="None", VendorAdvisory.NoAdvisory=False

  upstream CVE          → Vulnerability.Name    (Canonical's `UBUNTU-CVE-*` is internal)
  severity[type=Ubuntu] → Vulnerability.Severity (Negligible/Low/Medium/High/Critical, or Unknown)

Plain Ubuntu Pro (ESM) is emitted as a distro channel, `ubuntu:X.YY+esm`,
mirroring RHEL EUS's `rhel:X.Y+eus`, and carries the real Pro fix version
verbatim. FIPS / FIPS-updates / Realtime / Nvidia-BlueField map to no namespace:
their builds diverge from base, so their fixes cannot resolve a base disclosure.
The `include_esm` flag gates the `+esm` emit; when off, plain Pro maps to None
like the sub-tiers.

The `+esm` channel carries fixes only. A plain-Pro package with no fix version
produces no `+esm` FixedIn, and a clearance is the base release's to state, so
that produces none either: the base `ubuntu:X.YY` record is the sole disclosure
for both, and an unfixed or cleared `+esm` entry would only duplicate it. A
`+esm` record with nothing left is not emitted at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

UBUNTU_PKG_VERSION_FORMAT = "dpkg"
_UBUNTU_CVE_URL = "https://ubuntu.com/security/{}"

_BASE_ECO_RE = re.compile(r"^Ubuntu:(\d+\.\d+)(?::LTS)?$")
# plain Ubuntu Pro (ESM) only: `Ubuntu:Pro:<ver>[:LTS]`, anchored so any extra
# tier token (FIPS, FIPS-updates, Realtime, ...) or trailing segment fails to match.
_PLAIN_PRO_ECO_RE = re.compile(r"^Ubuntu:Pro:(\d+\.\d+)(?::LTS)?$")

_ESM_SUFFIX = "+esm"

# What "this package is not vulnerable" is spelled as in the OS schema, and the
# reason it is spelled exactly this way: the consumer treats a package group
# whose every FixedIn version is the single character `0` as an unaffected
# package that cancels findings from other sources, and falls back to a
# `< 0` version constraint the moment one entry in the group is anything else.
# So a `"0"` has to be the only FixedIn its package has in a record, with no
# whitespace and no epoch.
NOT_AFFECTED_VERSION = "0"

# v3 severity values, mirroring parser_legacy.Severity.json() output.
_SEVERITY_NAMES = {"Negligible", "Low", "Medium", "High", "Critical", "Unknown"}


@dataclass
class PackageState:
    """What one namespace's record says about one source package, before it is encoded.

    Four sources can put a package here — the release's own OSV entries, the
    Pro-to-base inference, a VEX statement at any token of the release, and the
    frozen tracker snapshot — and each of them sets one of these fields. The
    encoding into FixedIn entries is `fixed_in_for` and nothing else reads it.

    `ecosystem` is the OSV ecosystem string the fix-date lookup and the USN
    overlay are keyed by, which is the spelling the feed used for an entry that
    came from OSV and the release's canonical spelling for one that did not.

    `cleared` and `fixed` are mutually exclusive by construction: a package
    cannot be both researched as not carrying the vulnerability and fixed at a
    version, and a group mixing a `"0"` with a real version stops being read as
    a clearance at all. Whatever sets `cleared` clears `fixed` with it.
    """

    package: str
    ecosystem: str
    cleared: bool = False
    wont_fix: bool = False
    # True while nothing but the Pro-to-base inference has spoken about this
    # package. The inference reads an omission and guesses; a real statement
    # from the vendor is evidence, and evidence outranks a guess. Without this
    # flag the two are indistinguishable once written, so the steps after the
    # inference cannot tell whether deferring to what they hold would be
    # correcting a guess or overwriting a fact, and they defer to neither.
    inferred: bool = False
    fixed: list[str] = field(default_factory=list)
    # fix version -> {"Date": ..., "Kind": ...}, filled in by whoever resolved the date
    available: dict[str, dict[str, Any]] = field(default_factory=dict)

    def clear(self) -> None:
        """State that the vendor researched this package and found the vulnerable code absent.

        The fix versions go with it for the reason on the class: a clearance and
        a fix version in one group cancel each other out downstream.
        """
        self.cleared = True
        self.wont_fix = False
        self.fixed = []
        self.available = {}


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
            return f"ubuntu:{pm.group(1)}{_ESM_SUFFIX}"
    return None


def is_esm_namespace(namespace: str) -> bool:
    return namespace.endswith(_ESM_SUFFIX)


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


def severity_of(severity: list[dict[str, Any]] | None) -> str:
    """Pull v3's Severity from OSV's severity[] array (type=Ubuntu wins).

    A CVE no OSV record carries has no severity[] to read and is emitted
    `Unknown`, which is what the provider has always emitted for an untriaged
    record.
    """
    for entry in severity or []:
        if entry.get("type") == "Ubuntu":
            return _ubuntu_priority_to_severity(entry.get("score", ""))
    return "Unknown"


# How Canonical passes on the CVE program's own rejected-record text. Every
# record carrying either prefix in the feed is REJECTED at the CVE program;
# checked against every prefix-matched record in the feed, with zero
# exceptions in either direction. A third prefix, "** disputed **", was
# matched here previously: every record carrying it is a published, live CVE,
# not a rejection, so it suppressed real findings and was removed. Matched
# case-insensitively with leading whitespace tolerated, so a reformatting
# upstream does not silently re-admit rejected records.
_REJECTION_PREFIXES: tuple[str, ...] = (
    "** reject **",
    "rejected reason:",
)


def is_cve_program_rejection(payload: dict[str, Any]) -> bool:
    """Has the CVE program determined this is not a security issue?

    A rejected CVE would be a knowingly false finding, so it is not emitted.
    This is the one class of withdrawn record that is a genuine retraction —
    Canonical otherwise sets `withdrawn` to mean "this record will not be
    regenerated again", not "this finding was wrong" — and the `details` prose
    is the only signal published that separates the two. It is a proxy for the
    CVE program's own record state, not that state itself: it matches
    Canonical's re-rendering of a rejected record's `details` text, so a
    rejection Canonical never re-rendered into `details` is missed.

    Not every rejected record is withdrawn: the `Rejected reason:` form appears
    on records carrying no `withdrawn` timestamp at all. A record carrying
    `** DISPUTED **` is not matched here: it is a live, published CVE.

    It is read once, as the archive streams past, and carried on the CVE's row
    as a boolean. A rejection is a fact about the CVE and not about any release
    the record happens to name, and the releases it names are only the ones the
    vendor was still publishing for when the rejection landed — so a release the
    record does not name has to inherit it, and the VEX statements it would
    otherwise be rebuilt from carry no `details` to be asked.
    """
    details = payload.get("details")
    if not isinstance(details, str):
        return False
    return details.lstrip().lower().startswith(_REJECTION_PREFIXES)


def fixed_in_for(state: PackageState, namespace: str) -> list[dict[str, Any]]:
    """Encode one package's disposition as zero or more FixedIn entries.

    The clearance is read before the fix versions on purpose. Canonical's OSV
    generator re-encodes a tracker `not-affected (<version>)` row as a range
    fixed at that version, byte-identical to the encoding of a real fix, so an
    entry can arrive carrying both — and the clearance is the one that says what
    the vulnerable code does. Reading the versions first let the encoding win and
    put the package back below a boundary it was never under.
    """
    esm = is_esm_namespace(namespace)

    if state.cleared:
        if esm:
            # the channel carries fix versions only; the clearance belongs to the
            # base release's record
            return []
        return [
            {
                "Name": state.package,
                "NamespaceName": namespace,
                "VersionFormat": UBUNTU_PKG_VERSION_FORMAT,
                "Version": NOT_AFFECTED_VERSION,
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": None,
            },
        ]

    if state.fixed:
        return [
            {
                "Name": state.package,
                "NamespaceName": namespace,
                "VersionFormat": UBUNTU_PKG_VERSION_FORMAT,
                "Version": version,
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": state.available.get(version),
            }
            for version in state.fixed
        ]

    if esm:
        return []
    return [
        {
            "Name": state.package,
            "NamespaceName": namespace,
            "VersionFormat": UBUNTU_PKG_VERSION_FORMAT,
            "Version": "None",
            "VendorAdvisory": {"NoAdvisory": state.wont_fix},
            "Available": None,
        },
    ]


def os_record(cve: str, namespace: str, severity: str, fixed_in: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble the v3-shape `{"Vulnerability": {...}}` payload."""
    return {
        "Vulnerability": {
            "Name": cve,
            "NamespaceName": namespace,
            "Description": "",
            "Severity": severity,
            "Metadata": {},
            "Link": _UBUNTU_CVE_URL.format(cve),
            "FixedIn": fixed_in,
        },
    }


def os_identifier_for(os_payload: dict[str, Any]) -> str:
    """Build the v3-shape `{namespace}/{cve_name.lower()}` identifier for an emitted OS payload.

    Takes the payload `os_record` produced (not the inputs it was built from) so
    the identifier can't drift from the record it names — there's one
    construction, shared by the parser's yield path.
    """
    vuln = os_payload["Vulnerability"]
    return f"{vuln['NamespaceName']}/{vuln['Name'].lower()}"
