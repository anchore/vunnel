from __future__ import annotations

import datetime
import functools
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

from packageurl import PackageURL

from vunnel.tool import fixdate
from vunnel.utils import rpm
from vunnel.utils.vulnerability import CVSS, AdvisorySummary, FixAvailability, FixedIn, VendorAdvisory
from vunnel.utils.vulnerability import Vulnerability as OSVulnerability

from .csaf_advisory_client import AdvisoryDates
from .parser import PARSER_CONFIG
from .parser import Parser as OVALParser

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

    from vunnel.utils.csaf_types import CSAFDoc, ProductTree, Vulnerability

namespace = "sles"

# Scope is plain + LTSS SUSE Linux Enterprise Server only, matched by CPE rather than
# display name -- SUSE spells the same platform inconsistently across documents. See
# README.md for the rationale and the corpus survey behind it.
_NAME_SCOPE_RE = re.compile(r"^SUSE Linux Enterprise Server \d")
_CPE_RE = re.compile(
    r"^cpe:/o:suse:(?P<product>[a-z0-9_-]+):(?P<major>\d+)"
    r"(?:"
    r":sp(?P<sp>\d+)"  # SP-numbered releases, e.g. cpe:/o:suse:sles:12:sp4
    r"|:(?P=major)\.(?P<minor>\d+):server"  # SLES 16+ dotted releases, e.g. cpe:/o:suse:sles:16:16.0:server
    r")?$",
    re.IGNORECASE,
)

_PLAIN_CPE_PRODUCTS = frozenset({"sles", "suse_sles"})
_LTSS_CPE_PRODUCTS = frozenset({"sles-ltss", "suse_sles_ltss"})
# longer-tail LTSS sub-tiers, out of scope for now -- see README.md
_EXCLUDED_LTSS_CPE_PRODUCTS = frozenset({"sles-ltss-extended-security", "suse_sles_ltss-extreme-core"})

# SUSE flattens every advisory's product_ids into one vendor_fix entry, so a remediation
# can't be attributed to a specific advisory; we surface every advisory the document
# references instead.
_ADVISORY_REFERENCE_RE = re.compile(r"^Advisory link for (?P<notice_id>.+)$")

# categories carrying a fix version, in preference order
_FIX_STATUS_CATEGORIES = ("recommended", "first_fixed", "fixed")

# SUSE puts the CVE description in a document-level note; the per-vulnerability copy,
# where one exists at all, is category "general" under this title.
_CVE_DESCRIPTION_NOTE_TITLE = "CVE description"

# MITRE's rejection boilerplates, as SUSE mirrors them verbatim into the description --
# lowercased for comparison. CSAF has no field for a rejected CVE ID, so this is a prose
# match; see README.md, "Withdrawn (rejected) CVEs".
_REJECTED_CVE_MARKERS = (
    "do not use this candidate number",
    "do not use this cve record",
    "** reject **",
    # the modern CNA wording, cut short so both spellings SUSE ships match
    "has been rejected or withdrawn",
)


def namespace_and_channel_for_platform(
    platform_name: str,
    cpe: str | None,
    allow_versions: set[str] | None = None,
) -> str | None:
    """Map a CSAF platform to a vunnel sles namespace (`sles:X.Y` or `sles:X.Y+ltss`),
    or None if out of scope."""
    # name backstops where CPE alone can't discriminate: "Server for Raspberry Pi" and
    # some Teradata platforms carry a CPE identical to plain SLES's.
    if not cpe or not _NAME_SCOPE_RE.match(platform_name) or "teradata" in platform_name.lower():
        return None

    m = _CPE_RE.match(cpe)
    if not m or m.group("product").lower() in _EXCLUDED_LTSS_CPE_PRODUCTS:
        return None
    product = m.group("product").lower()

    major = m.group("major")
    if allow_versions is not None and major not in allow_versions:
        return None

    version = major
    if m.group("sp"):
        version = f"{major}.{m.group('sp')}"
    elif m.group("minor"):
        version = f"{major}.{m.group('minor')}"

    if product in _PLAIN_CPE_PRODUCTS:
        return f"{namespace}:{version}"
    if product in _LTSS_CPE_PRODUCTS:
        return f"{namespace}:{version}+ltss"
    return None


class _Assertion(NamedTuple):
    """One statement the document makes about a package on an in-scope platform."""

    namespace: str
    package: str
    version: str
    advisory: VendorAdvisory | None
    available: FixAvailability | None = None


def _as_date(day: str | None) -> datetime.date | None:
    """'2024-02-22' -> date(2024, 2, 22). The advisory index stores YYYY-MM-DD strings;
    anything else can't date a fix, and the finder discards a dateless candidate anyway.
    """
    if not day:
        return None
    try:
        return datetime.date.fromisoformat(day)
    except ValueError:
        return None


class FixDates:
    """Resolves FixedIn.Available for a fixed package.

    The VEX feed dates nothing: `remediations[].date` is empty throughout, and the
    document-level tracking dates describe SUSE's CVE page, not a shipped fix. So the
    date comes from vunnel's fixdate.Finder, optionally given a real advisory release
    date as a candidate -- see SLESCSAFAdvisoryClient, which indexes those by (CVE, NEVR).
    """

    def __init__(self, fixdater: fixdate.Finder, advisory_dates: AdvisoryDates | None = None):
        self.fixdater = fixdater
        self.advisory_dates = advisory_dates or AdvisoryDates()

    def attests(self, cve_id: str, nevr: str) -> bool:
        """Whether a SUSE advisory actually shipped this build **for this CVE**.

        The CVE-keyed index only, never the NEVR fallback `available_for` uses: a build
        that shipped under some *other* CVE is exactly the pre-fix GA build the rule
        exists to catch. See "Choosing among the fix categories" in README.md.
        """
        return (cve_id.upper(), nevr) in self.advisory_dates.by_cve_nevr

    def available_for(self, cve_id: str, namespace: str, package: str, nevr: str, version: str) -> FixAvailability | None:
        candidates = []
        # the CVE-keyed date first; failing that, the day this exact build shipped under
        # any CVE. Availability is a property of the build, so the looser key still
        # answers "when could you install this version" -- it just can't say the fix was
        # attributed to this CVE that day. See README.md, "Fix dates".
        shipped = _as_date(self.advisory_dates.by_cve_nevr.get((cve_id.upper(), nevr))) or _as_date(
            self.advisory_dates.by_nevr.get(nevr),
        )
        if shipped:
            candidates.append(fixdate.Result(date=shipped, kind="advisory", version=version))

        result = self.fixdater.best(
            vuln_id=cve_id,
            cpe_or_package=package,
            fix_version=version,
            # look the fix up under the plain namespace: `sles:X.Y+ltss` is new here, so
            # no historical first-observed data is filed under it, and the finder matches
            # the ecosystem exactly. The plain track carries the same fix at the same
            # version for 93% of LTSS fixed records (the OVAL feed these dates came from
            # folded the two tracks together), so this recovers a real date instead of
            # stamping today. Where the tracks genuinely diverge the finder also matches
            # on fix_version, so a differing LTSS build simply misses rather than
            # inheriting plain's date.
            ecosystem=namespace.removesuffix("+ltss"),
            candidates=candidates,
        )
        if not result or not result.date:
            return None
        return FixAvailability(Date=result.date.isoformat(), Kind=result.kind)


@dataclass(frozen=True)
class _ScopedProduct:
    """An in-scope product_id, resolved out of the product tree."""

    namespace: str
    # product_reference verbatim, NOT the purl's name: SUSE's purl for a version-less
    # branch mistakes part of the RPM name for a version, e.g.
    # "libjavascriptcoregtk-4_0-18" -> "pkg:rpm/suse/libjavascriptcoregtk@4_0-18".
    package: str
    purl: str | None


def _in_scope_platform_namespaces(product_tree: ProductTree, allow_set: set[str] | None) -> dict[str, str]:
    """Map each in-scope platform's product_id to its vunnel namespace."""
    namespaces = {}
    for branch in product_tree.product_branches():
        pid = branch.product_id()
        if not pid:
            continue
        ns = namespace_and_channel_for_platform(pid, branch.cpe(), allow_set)
        if ns:
            namespaces[pid] = ns
    return namespaces


@dataclass(frozen=True)
class _DocumentScope:
    """The part of a document's product tree this provider cares about."""

    # in-scope platform product_id -> namespace
    platforms: dict[str, str]
    # product_id, as product_status and remediations spell it -> resolved package
    products: dict[str, _ScopedProduct]


def _in_scope(product_tree: ProductTree, allow_set: set[str] | None) -> _DocumentScope:
    """Resolve every product_id this provider cares about: in-scope platforms, then the
    packages related to them. product_status and remediations are lookups against this."""
    platforms = _in_scope_platform_namespaces(product_tree, allow_set)
    if not platforms:
        return _DocumentScope(platforms={}, products={})

    products = {}
    for rel in product_tree.relationships:
        ns = platforms.get(rel.relates_to_product_reference)
        if ns is None:
            continue
        products[rel.full_product_name.product_id] = _ScopedProduct(
            namespace=ns,
            package=rel.product_reference,
            purl=product_tree.purl_for_product_id(rel.product_reference),
        )
    return _DocumentScope(platforms=platforms, products=products)


def _fix_from_purl(purl: str | None) -> tuple[str, str] | None:
    """(package name, epoch-prefixed version) from a product_tree purl, or None."""
    if not purl:
        return None
    parsed = PackageURL.from_string(purl)
    epoch = parsed.qualifiers.get("epoch", "0") if isinstance(parsed.qualifiers, dict) else "0"
    return parsed.name, f"{epoch}:{parsed.version}"


_SRC_RPM_SUFFIX = ".src.rpm"


def _source_rpm_name(purl: str | None) -> str | None:
    """The source RPM's name, from a product_tree purl's `upstream=` qualifier.

    `pkg:rpm/suse/libpcre1@8.39-8.3.1?upstream=pcre-8.39-8.3.1.src.rpm` -> "pcre".

    Only version-bearing (fix) purls are worth asking: SUSE's version-less branches
    often carry no `upstream=` at all (`pkg:rpm/suse/webkit2gtk3@`), which is exactly
    why _affected_assertions reads source names off the *fixed* products instead.
    """
    if not purl:
        return None
    parsed = PackageURL.from_string(purl)
    qualifiers = parsed.qualifiers if isinstance(parsed.qualifiers, dict) else {}
    upstream = qualifiers.get("upstream")
    if not upstream or not upstream.endswith(_SRC_RPM_SUFFIX):
        return None
    nvr = upstream[: -len(_SRC_RPM_SUFFIX)]
    # "pcre-8.39-8.3.1" -> "pcre"; a bare "pcre.src.rpm" has no version to strip
    name, _, release = nvr.rpartition("-")
    name, _, version = name.rpartition("-")
    if name and release and version[:1].isdigit():
        return name
    return nvr


def _vendor_advisories(doc: CSAFDoc) -> list[AdvisorySummary]:
    summaries = []
    for ref in doc.document.references:
        m = _ADVISORY_REFERENCE_RE.match(ref.summary)
        if m:
            summaries.append(AdvisorySummary(ID=m.group("notice_id"), Link=ref.url))
    return summaries


def _link_for_cve(doc: CSAFDoc, cve_id: str) -> str:
    for ref in doc.document.references:
        if ref.summary == cve_id:
            return ref.url
    return f"https://www.suse.com/security/cve/{cve_id}"


def _description_for(doc: CSAFDoc, vuln: Vulnerability | None = None) -> str:
    """The CVE description, which SUSE spells at the document level.

    Every document carries it as `document.notes` with category "description"; only some
    also repeat it under the vulnerability, where it is category "general" titled "CVE
    description" -- so reading `vuln.notes` for category "description" matches nothing.
    """
    for note in doc.document.notes:
        if note.category == "description":
            return note.text.strip()
    for note in vuln.notes if vuln else []:
        if note.title == _CVE_DESCRIPTION_NOTE_TITLE:
            return note.text.strip()
    return ""


def _is_rejected_cve(description: str) -> bool:
    """Whether the description says MITRE has rejected/withdrawn this CVE ID."""
    lowered = description.lower()
    return any(marker in lowered for marker in _REJECTED_CVE_MARKERS)


def _severity_for(doc: CSAFDoc) -> str:
    if doc.document.aggregate_severity:
        mapped = PARSER_CONFIG.severity_map.get(doc.document.aggregate_severity.text.lower())
        if mapped:
            return mapped
    return "Unknown"


def _cvss_list(vuln: Vulnerability, cve_id: str, logger: logging.Logger) -> list[CVSS]:
    vectors = []
    seen = set()
    for score in vuln.scores:
        if score.cvss_v3 and score.cvss_v3.vector_string not in seen:
            seen.add(score.cvss_v3.vector_string)
            vectors.append(score.cvss_v3.vector_string)

    cvss_list = []
    for vector in vectors:
        cvss_obj = OVALParser._make_cvss(vector, cve_id)  # noqa: SLF001
        if cvss_obj:
            cvss_list.append(cvss_obj)
    if not cvss_list and vectors:
        logger.debug(f"{cve_id}: found CVSS v3 vectors but none parsed successfully: {vectors}")
    return cvss_list


class _FixCandidate(NamedTuple):
    """One fixed version a fix category claims for a (namespace, package)."""

    category: str
    version: str
    nevr: str


def _version_cmp(a: _FixCandidate, b: _FixCandidate) -> int:
    return rpm.compare_versions(a.version, b.version)


_by_version = functools.cmp_to_key(_version_cmp)


def _choose_fix(candidates: list[_FixCandidate], cve_id: str, fix_dates: FixDates | None) -> _FixCandidate:
    """Pick one fixed version out of everything the fix categories claim about one
    (namespace, package).

    Lowest version wins. `FixedIn.Version` is a boundary -- "installed below this is
    vulnerable" -- so among versions all claimed to fix the CVE the earliest is the true
    boundary, and a higher one reports already-patched installs as vulnerable.

    One exception, and only where the candidates disagree *across* categories: a
    candidate no SUSE advisory ever shipped for this CVE, standing beside one that was
    shipped, is a pre-fix build SUSE listed anyway, so it drops out before the comparison.
    See "Choosing among the fix categories" in README.md.
    """
    pool = candidates
    if fix_dates is not None and len({c.category for c in candidates}) > 1:
        attested = [c for c in candidates if fix_dates.attests(cve_id, c.nevr)]
        # all-or-nothing attestation discriminates nothing: either every candidate
        # shipped, or the index has no entry for this CVE at all.
        if attested and len(attested) != len(candidates):
            pool = attested
    return min(pool, key=_by_version)


def _fix_assertions(  # noqa: PLR0913
    vuln: Vulnerability,
    scope: _DocumentScope,
    advisories: list[AdvisorySummary],
    cve_id: str,
    logger: logging.Logger,
    fix_dates: FixDates | None = None,
) -> tuple[list[_Assertion], dict[str, str]]:
    """One fixed-version assertion per (namespace, package), across
    recommended/first_fixed/fixed.

    The categories are gathered rather than ranked, because SUSE's data doesn't support
    ranking them -- `_choose_fix` decides, which needs every candidate in hand: the
    categories can name the same package at different versions, and `recommended` alone
    can name one package twice.

    Returns the assertions plus a package name -> source RPM name map for everything it
    resolved, which is what _drop_stale_source_records needs. The map is document-wide
    because a binary's source RPM doesn't vary by service pack.
    """
    candidates: dict[tuple[str, str], list[_FixCandidate]] = {}
    package_sources: dict[str, str] = {}
    for category in _FIX_STATUS_CATEGORIES:
        ids = getattr(vuln.product_status, category, None) if vuln.product_status else None
        for pid in ids or []:
            scoped = scope.products.get(pid)
            if scoped is None:
                # an in-scope platform with no relationship to this id is a gap in the
                # document; anything else is just a product line we don't cover.
                if pid.partition(":")[0] in scope.platforms:
                    logger.debug(f"{cve_id}: could not resolve {category} id {pid!r}, skipping")
                continue
            fix = _fix_from_purl(scoped.purl)
            if fix is None:
                logger.debug(f"{cve_id}: could not resolve {category} id {pid!r}, skipping")
                continue
            package, version = fix
            source = _source_rpm_name(scoped.purl)
            if source:
                package_sources[package] = source
            candidates.setdefault((scoped.namespace, package), []).append(_FixCandidate(category, version, scoped.package))

    assertions: list[_Assertion] = []
    for (ns, package), for_package in candidates.items():
        chosen = _choose_fix(for_package, cve_id, fix_dates)
        available = fix_dates.available_for(cve_id, ns, package, chosen.nevr, chosen.version) if fix_dates else None
        assertions.append(
            _Assertion(
                ns,
                package,
                chosen.version,
                VendorAdvisory(NoAdvisory=False, AdvisorySummary=advisories),
                available,
            ),
        )
    return assertions, package_sources


def _not_affected_assertions(vuln: Vulnerability, scope: _DocumentScope) -> Iterator[_Assertion]:
    not_affected_ids = vuln.product_status.known_not_affected if vuln.product_status else []
    for pid in not_affected_ids:
        scoped = scope.products.get(pid)
        if scoped is None:
            continue
        yield _Assertion(scoped.namespace, scoped.package, "0", None)


def _affected_assertions(
    vuln: Vulnerability,
    scope: _DocumentScope,
    advisories: list[AdvisorySummary],
) -> Iterator[_Assertion]:
    """known_affected with no fix: vunnel's Version "None" ("vulnerable, no fix
    available yet"), matching ubuntu/os_downconvert.py.

    A no_fix_planned remediation only decides NoAdvisory -- whether this is a *declared*
    won't-fix or a fix that may still be coming. It never justifies a record on its own,
    because SUSE sweeps no_fix_planned across sub-packages it never assessed as affected;
    only known_affected can put a package here. See README.md.

    Entries that name a source package whose binaries end up fixed are retired later, by
    _drop_stale_source_records -- after borrowing, so borrowed fixes count too."""
    known_affected_ids = vuln.product_status.known_affected if vuln.product_status else []
    if not known_affected_ids:
        return

    no_fix_planned_ids: set[str] = set()
    for remediation in vuln.remediations:
        if remediation.category != "no_fix_planned":
            continue
        no_fix_planned_ids.update(remediation.product_ids)

    for pid in known_affected_ids:
        scoped = scope.products.get(pid)
        if scoped is None:
            continue
        advisory = VendorAdvisory(NoAdvisory=pid in no_fix_planned_ids, AdvisorySummary=advisories)
        yield _Assertion(scoped.namespace, scoped.package, "None", advisory)


def _assertions(  # noqa: PLR0913
    vuln: Vulnerability,
    scope: _DocumentScope,
    advisories: list[AdvisorySummary],
    cve_id: str,
    logger: logging.Logger,
    fix_dates: FixDates | None = None,
) -> tuple[list[_Assertion], dict[str, str]]:
    """Everything the document asserts about packages on in-scope platforms.

    Yield order is precedence: for a given (namespace, package) the first assertion
    wins, so a real fixed version is never downgraded to the not-affected ("0") or
    vulnerable ("None") convention by a later, weaker statement about the same package.

    Precedence only resolves *between* these three groups; competing fixed versions for
    one (namespace, package) are settled inside `_fix_assertions`, which yields one
    assertion per package."""
    fixes, package_sources = _fix_assertions(vuln, scope, advisories, cve_id, logger, fix_dates)
    assertions = [
        *fixes,
        *_not_affected_assertions(vuln, scope),
        *_affected_assertions(vuln, scope, advisories),
    ]
    return assertions, package_sources


def _borrow_ltss_fixes_into_plain(fixed_by_namespace: dict[str, dict[str, FixedIn]]) -> None:
    """Copy an LTSS fix into the plain namespace when the plain track has nothing better
    to say about that package for this CVE -- either no entry at all, or a bare
    "vulnerable, no fix" ("None").

    LTSS is the same package lineage continued longer, not a fork, and SUSE's own
    plain-CPE container images demonstrably ship LTSS-track builds -- so an LTSS-only fix
    would otherwise be unreachable by the scan that needs it. One-directional, and only
    for real fixed versions.

    A plain "None" does not outrank the fix: once a SP leaves general support SUSE stops
    publishing plain-track fixes but leaves the known_affected line standing, so that
    "None" describes which channel ships the RPM, not whether the code is fixed. A plain
    "0" (known_not_affected) *does* outrank it: that is a real determination, and
    overwriting it would start matching every version below the borrowed one. See
    README.md."""
    for ltss_ns in [ns for ns in fixed_by_namespace if ns.endswith("+ltss")]:
        plain_ns = ltss_ns.removesuffix("+ltss")
        plain_bucket = fixed_by_namespace.setdefault(plain_ns, {})
        for package, fixed_in in fixed_by_namespace[ltss_ns].items():
            if fixed_in.Version in ("0", "None"):
                continue
            existing = plain_bucket.get(package)
            if existing is not None and existing.Version != "None":
                continue
            plain_bucket[package] = FixedIn(
                Name=fixed_in.Name,
                NamespaceName=plain_ns,
                VersionFormat=fixed_in.VersionFormat,
                Version=fixed_in.Version,
                Module=fixed_in.Module,
                VendorAdvisory=fixed_in.VendorAdvisory,
                Available=fixed_in.Available,
            )


def _drop_stale_source_records(
    fixed_by_namespace: dict[str, dict[str, FixedIn]],
    package_sources: dict[str, str],
) -> None:
    """Retire a "None" record that names a source package whose binaries this namespace
    ends up fixing.

    SUSE's known_affected list mixes granularities -- it names the source RPM alongside
    the binaries built from it -- and leaves the source-level claim standing after
    shipping the fix. Fix-first precedence masks the per-binary contradictions, but a
    source-named entry has no same-named fix to mask it.

    That record is the widest kind of false positive available: "None" carries no version
    to compare, and grype resolves an installed binary to its source RPM and searches
    under that name too, so one such record matches every binary that source builds, at
    every version.

    Runs after borrowing, so a fix inherited from the LTSS track retires the stale source
    record just as the plain track's own fix would.

    A *declared* won't-fix is never retired this way: `NoAdvisory=True` means a
    no_fix_planned remediation names this exact product, which is how SUSE says "this
    flavor stays vulnerable, use the other one" (CVE-2023-47627 declares python-aiohttp
    won't-fix on SLES 15 SP4 while its sibling python311-aiohttp, same source RPM, is
    fixed). See README.md."""
    for bucket in fixed_by_namespace.values():
        fixed_sources = {
            source for name, fixed_in in bucket.items() if fixed_in.Version not in ("0", "None") and (source := package_sources.get(name))
        }
        stale = [
            name
            for name, fixed_in in bucket.items()
            if fixed_in.Version == "None" and name in fixed_sources and not (fixed_in.VendorAdvisory and fixed_in.VendorAdvisory.NoAdvisory)
        ]
        for name in stale:
            del bucket[name]


def _downconvert_vulnerability(
    vuln: Vulnerability,
    doc: CSAFDoc,
    scope: _DocumentScope,
    logger: logging.Logger,
    fix_dates: FixDates | None = None,
) -> list[OSVulnerability]:
    cve_id = vuln.cve
    if not cve_id:
        return []

    # namespace -> package name -> FixedIn
    fixed_by_namespace: dict[str, dict[str, FixedIn]] = {}
    advisories = _vendor_advisories(doc)

    assertions, package_sources = _assertions(vuln, scope, advisories, cve_id, logger, fix_dates)
    for ns, package, version, advisory, available in assertions:
        bucket = fixed_by_namespace.setdefault(ns, {})
        if package not in bucket:
            bucket[package] = FixedIn(
                Name=package,
                NamespaceName=ns,
                VersionFormat="rpm",
                Version=version,
                Module=None,
                VendorAdvisory=advisory,
                Available=available,
            )

    _borrow_ltss_fixes_into_plain(fixed_by_namespace)
    _drop_stale_source_records(fixed_by_namespace, package_sources)

    if not fixed_by_namespace:
        return []

    description = _description_for(doc, vuln)
    severity = _severity_for(doc)
    link = _link_for_cve(doc, cve_id)
    cvss_list = _cvss_list(vuln, cve_id, logger)

    return [
        OSVulnerability(
            Name=cve_id,
            NamespaceName=ns,
            Description=description,
            Severity=severity,
            Link=link,
            CVSS=cvss_list,
            FixedIn=sorted(packages.values(), key=lambda f: f.Name),
        )
        for ns, packages in fixed_by_namespace.items()
    ]


def downconvert(
    doc: CSAFDoc,
    allow_versions: list[str] | None = None,
    logger: logging.Logger | None = None,
    fix_dates: FixDates | None = None,
) -> list[OSVulnerability]:
    """Convert a SUSE CSAF VEX document into OS-schema Vulnerability records, one per
    (namespace, CVE) with at least one FixedIn entry.

    ``allow_versions`` restricts output to those major versions, so "15" keeps
    "sles:15.1".

    Documents for a CVE ID MITRE has rejected emit nothing -- see README.md,
    "Withdrawn (rejected) CVEs"."""
    if not logger:
        logger = logging.getLogger(__name__)

    if doc.product_tree is None or not doc.vulnerabilities:
        return []

    # one VEX document is one CVE, so a rejected description retires the whole document.
    # Checked before any scope work, since the answer is "emit nothing" regardless.
    description = _description_for(doc)
    if _is_rejected_cve(description):
        logger.debug(f"{doc.document.tracking.id}: skipping withdrawn (rejected) CVE")
        return []

    allow_set = {str(v) for v in allow_versions} if allow_versions is not None else None

    scope = _in_scope(doc.product_tree, allow_set)
    if not scope.products:
        return []

    results = []
    for vuln in doc.vulnerabilities:
        results.extend(_downconvert_vulnerability(vuln, doc, scope, logger, fix_dates))
    return results


def downconvert_docs(
    docs: Generator[tuple[str, CSAFDoc]],
    allow_versions: list[str] | None = None,
    logger: logging.Logger | None = None,
    fix_dates: FixDates | None = None,
) -> Generator[tuple[str, str, dict[str, object]]]:
    """Given (cve_id, doc) pairs (as yielded by SLESCSAFClient.iter_docs), yield
    (namespace, cve_id, payload) tuples ready for the results writer."""
    for _cve_id, doc in docs:
        for vuln in downconvert(doc, allow_versions=allow_versions, logger=logger, fix_dates=fix_dates):
            yield vuln.NamespaceName, vuln.Name, vuln.to_payload()
