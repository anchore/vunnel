from __future__ import annotations

import datetime
import logging
import operator
import os
import re
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable
    from types import TracebackType

    from vunnel.workspace import Workspace


# CPANSA is keyed by distribution, not module, and the names are case sensitive and used verbatim
ECOSYSTEM = "CPAN"

OSV_SCHEMA_VERSION = "1.6.1"

# vutil.h: components are clamped rather than erroring, so two absurdly large versions can compare equal
VERSION_MAX = 0x7FFFFFFF

# the lax version grammar, from lib/version/regex.pm (version-0.9934), which perl core ships
# identically. real CPAN data is lax, not strict.
_LAX_VERSION = re.compile(
    r"""
    ^(?:
        v [0-9]+ (?: (?: \.[0-9]+ )+ (?: _[0-9]+ )? )?   # v-string
      | [0-9]* (?: \.[0-9]+ ){2,} (?: _[0-9]+ )?         # dotted-decimal without the v
      | [0-9]+ (?: \.[0-9]+ | \. )? (?: _[0-9]+ )?       # decimal, trailing '.' allowed
      | \.[0-9]+ (?: _[0-9]+ )?                          # decimal with a leading '.'
    )$
    """,
    re.VERBOSE,
)

# CPAN::Audit::Version::in_range's own regex, plus a '=' arm it does not have (see _OPERATORS)
_RANGE_CLAUSE = re.compile(r"^(<=|<|>=|>|==|!=|=)?\s*(\S+)$")

_OPERATORS = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
    # upstream's regex has no single-equals alternative, so its 59 '=N' entries fall through and the
    # comparison bails. handle it explicitly as equality, which is plainly what the data means.
    "=": operator.eq,
}


def perl_version_key(raw: str) -> tuple[int, ...]:
    """Sort key ordering perl versions the way perl itself does (Perl_vcmp in vutil.c).

    Comparing two of these tuples is equivalent to Perl_vcmp: vcmp compares the shared prefix and
    then requires every remaining component of the longer side to be zero for equality, which is the
    same as comparing both vectors with their trailing zeros removed. So v1.2 == v1.2.0 == v1.2.0.0.

    The ordering this produces contradicts every other ecosystem, and those results are correct:
    1.2 > 1.10, 1.23 > 1.2.3, 1.23 == 1.230, 5.008001 == 5.8.1, and 1.23_01 > 1.23. The underscore
    alpha flag does not participate in comparison at all; 1.23_01 sorts high because its digits fold
    into the numeric groups, not because of any pre-release rule.

    Raises ValueError on anything the lax grammar rejects, so bad data is reported, not guessed at.
    """
    s = str(raw).strip()

    # $LAX in lib/version/regex.pm includes an `undef` alternative, and version->parse("undef")
    # really does yield version 0. ExtUtils::MM->parse_version returns the literal string when it
    # cannot find a $VERSION, so it reaches consumers. The Go port agrees on this.
    if s == "undef":
        return ()

    if not _LAX_VERSION.match(s):
        raise ValueError(f"not a parseable perl version: {raw!r}")
    if "_" in s and "." not in s:
        # Perl_prescan_version: "alpha without decimal", which is why 1_2 fails
        raise ValueError(f"not a parseable perl version (alpha without decimal): {raw!r}")

    if s.startswith("v") or s.count(".") > 1:
        # a leading v, or a second '.', promotes the whole string to dotted-decimal, which is
        # ordinary componentwise integers
        components = [int(p) if p else 0 for p in s.lstrip("v").replace("_", "").split(".")]
    else:
        # decimal: the fractional part is chopped into three-digit groups with place values
        # 100/10/1, so a short final group is left-aligned (0.90380906 -> [0, 903, 809, 60])
        head, _, fraction = s.partition(".")
        fraction = fraction.replace("_", "")
        components = [int(head) if head else 0]
        fraction += "0" * (-len(fraction) % 3)
        components += [int(fraction[i : i + 3]) for i in range(0, len(fraction), 3)]

    components = [min(c, VERSION_MAX) for c in components]
    while components and components[-1] == 0:
        components.pop()
    return tuple(components)


def in_range(version: str, range_expr: str) -> bool:
    """Whether a version satisfies one CPANSA range entry, e.g. ">=1.19_01,<=1.22_04" or "1.23".

    Comma separated clauses are ANDed, and a clause with no operator means ">=", not "==", matching
    CPAN::Audit::Version::in_range. 616 of CPANSA's 1850 advisories carry that bare shape, so
    reading it as equality drops nearly all of them.
    """
    left = perl_version_key(version)
    clauses = [c.strip() for c in str(range_expr).split(",") if c.strip()]
    if not clauses:
        raise ValueError(f"empty range expression: {range_expr!r}")

    for clause in clauses:
        match = _RANGE_CLAUSE.match(clause)
        if not match:
            raise ValueError(f"unparseable range clause {clause!r} in {range_expr!r}")
        op, rhs = match.groups()
        if not _OPERATORS[op or ">="](left, perl_version_key(rhs)):
            return False
    return True


def _includes(ranges: Iterable[Any], version: str) -> bool:
    return any(in_range(version, r) for r in ranges)


def resolve_affected(advisory: dict[str, Any], released: list[str]) -> list[str]:
    """The released versions this advisory applies to, in the order given.

    CPAN::Audit::Query::advisories_for does not do a plain range test: it walks the distribution's
    known released versions, keeps those inside affected_versions, and subtracts those inside
    fixed_versions. fixed_versions is usually absent (only 498 of 1850 advisories have one), which
    means "nothing is subtracted", not "nothing is affected".
    """
    affected = advisory.get("affected_versions") or []
    fixed = advisory.get("fixed_versions") or []
    return [v for v in released if _includes(affected, v) and not _includes(fixed, v)]


def normalize_severity(raw: str | None) -> str | None:
    """CPANSA severity is freeform and unnormalized: medium and moderate coexist, as do low and minor.

    A third of advisories have no severity and no CVSS vector to derive one from, so those emit
    nothing rather than a fabricated default; downstream recovers severity from the linked CVE.
    """
    if not raw:
        return None
    value = str(raw).strip().lower()
    return {"moderate": "medium", "minor": "low"}.get(value, value) or None


def _main_module_alias(dist_name: str, dist: dict[str, Any]) -> str | None:
    """The packlist-shaped name a scanner reports for this distribution, when it differs from it.

    A CPAN.pm install lands at auto/<path>/.packlist, where the path comes from the builder's NAME
    (ExtUtils::MakeMaker) or module_name (Module::Build), and both of those are the main module
    rather than the distribution. libwww-perl's main module is LWP, so it installs to
    auto/LWP/.packlist and is reported as `LWP`, which matches no CPANSA advisory at all since
    CPANSA is keyed by distribution. main_module is precisely the field that predicts that name,
    and the aliased name is an extra affected package on the same advisory, so it always carries
    the distribution's own resolved ranges.

    That is sound only because every version reported for a CPAN package is a DISTRIBUTION version:
    EUMM's $(VERSION), whether it arrives via perllocal.pod or via VERSION_FROM, is the distribution
    version, so the ranges are compared against the right numbers. It becomes unsound the day
    module-level packages are reported at module-level versions, because the ranges would then be
    compared against module versions instead. Revisit this if that ever happens.

    Only main_module is used. module2dist maps every module to its distribution and would produce
    names no installer ever emits (module2dist["URI::Escape"] == "URI", so `URI-Escape`), which
    multiplies entries and widens the name collision surface without covering one more real install.
    """
    main_module = dist.get("main_module")
    if not main_module:
        # 3 of 409 distributions carry an empty main_module. no alias, and none is guessed from the
        # distribution name: the whole point is that the two spellings are not derivable from each other
        return None
    alias = str(main_module).strip().replace("::", "-")
    return alias if alias and alias != dist_name else None


def _version_string(value: Any) -> str:
    # 21 distributions carry their versions as JSON floats rather than strings (Data-FormValidator
    # is one). coercing loses trailing zeros, which is harmless under perl decimal rules since 4.80
    # and 4.8 are the same version.
    if isinstance(value, float) and value == int(value):
        return str(int(value))
    return str(value)


class Parser:
    # the generated file, not the per-advisory cpansa/*.yml tree it is built from: those carry only
    # affected_versions, cves, description, fixed_versions, id, references and reported, so they have
    # neither the release history that resolves a range nor the main_module that names an install
    _source_url_ = "https://raw.githubusercontent.com/briandfoy/cpan-security-advisory/master/cpan-security-advisory.json"

    def __init__(  # noqa: PLR0913
        self,
        ws: Workspace,
        url: str | None = None,
        download_timeout: int = 125,
        skip_download: bool = False,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.url = url or self._source_url_
        self.download_timeout = download_timeout
        self.skip_download = skip_download
        self.urls = [self.url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.file_path = os.path.join(self.workspace.input_path, "cpan-security-advisory.json")

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self.logger.info(f"downloading CPAN security advisories from {self.url}")
        r = http.get(self.url, self.logger, timeout=self.download_timeout)
        with open(self.file_path, "wb") as fp:
            fp.write(r.content)

    def _load(self) -> dict[str, Any]:
        with open(self.file_path, "rb") as f:
            return orjson.loads(f.read())

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        if self.skip_download:
            self.logger.info(f"skipping download; using existing data at {self.file_path}")
        else:
            self._download()

        db = self._load()
        meta = db.get("meta") or {}
        commit = meta.get("commit")
        generated = meta.get("date")
        if not commit or not generated:
            # upstream is one maintainer plus a bot; if the generated file ever loses its provenance
            # we want a failed run, not a silently stale database
            raise ValueError(f"CPANSA data is missing generation metadata (commit={commit!r} date={generated!r})")
        self.logger.info(f"CPANSA generated {generated} at commit {commit}")

        modified = _rfc3339(generated, "%a %b %d %H:%M:%S %Y")
        if not modified:
            raise ValueError(f"CPANSA generation date is not in the expected format: {generated!r}")

        self.fixdater.download()

        upstream = {"cpansa_commit": commit, "cpansa_generated": generated, "modified": modified}

        # a handful of ids appear under two distributions at once (CPANSA-ExtUtils-ParseXS-2016-1238
        # is filed against both ExtUtils-ParseXS and perl), so records are keyed by id across the
        # whole database and each distribution becomes one more entry in `affected`
        records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        for dist_name, dist in sorted(db.get("dists", {}).items()):
            for record in self._records_for_dist(dist_name, dist, upstream):
                existing = records.get(record["id"])
                if existing:
                    existing["affected"] += record["affected"]
                    existing["aliases"] += [a for a in record["aliases"] if a not in existing["aliases"]]
                    existing["references"] += [r for r in record["references"] if r not in existing["references"]]
                else:
                    records[record["id"]] = record

        for vuln_id, record in records.items():
            osv.patch_fix_date(record, self.fixdater)
            yield vuln_id, record

    def _released_versions(self, dist_name: str, dist: dict[str, Any]) -> list[str]:
        """Known releases of a distribution in perl version order, dropping any that will not parse."""
        versions = []
        for entry in dist.get("versions") or []:
            raw = _version_string(entry.get("version"))
            try:
                perl_version_key(raw)
            except ValueError as e:
                self.logger.warning(f"{dist_name}: skipping unparseable released version: {e}")
                continue
            versions.append(raw)
        return sorted(set(versions), key=perl_version_key)

    def _records_for_dist(self, dist_name: str, dist: dict[str, Any], upstream: dict[str, str]) -> Generator[dict[str, Any]]:
        released = self._released_versions(dist_name, dist)
        alias = _main_module_alias(dist_name, dist)

        # one CPANSA id can appear many times, each entry carrying one slice of the affected range
        # (CPANSA-DBD-SQLite-2018-8740-sqlite is 65 entries). group by id and union the slices, or
        # the database gets one advisory per slice.
        groups: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        for advisory in dist.get("advisories") or []:
            vuln_id = advisory.get("id")
            if not vuln_id:
                self.logger.warning(f"{dist_name}: skipping advisory with no id")
                continue
            groups.setdefault(vuln_id, []).append(advisory)

        for vuln_id, entries in groups.items():
            affected: set[str] = set()
            for entry in entries:
                try:
                    affected.update(resolve_affected(entry, released))
                except ValueError as e:
                    self.logger.warning(f"{vuln_id}: skipping unresolvable range entry: {e}")

            if not affected:
                self.logger.warning(f"{vuln_id}: no released version of {dist_name} resolved as affected")

            yield _record(dist_name, vuln_id, entries, _ranges(released, affected), upstream, alias)


def _record(  # noqa: PLR0913
    dist_name: str,
    vuln_id: str,
    entries: list[dict[str, Any]],
    ranges: list[dict[str, Any]],
    upstream: dict[str, str],
    alias: str | None = None,
) -> dict[str, Any]:
    cves: list[str] = []
    references: list[str] = []
    details = ""
    severity = None
    published = None
    for entry in entries:
        for cve in entry.get("cves") or []:
            if cve not in cves:
                cves.append(cve)
        for ref in entry.get("references") or []:
            if ref not in references:
                references.append(ref)
        details = details or (entry.get("description") or "").strip()
        severity = severity or normalize_severity(entry.get("severity"))
        published = published or _rfc3339(entry.get("reported"), "%Y-%m-%d")

    database_specific: dict[str, Any] = {
        "cpansa_commit": upstream["cpansa_commit"],
        "cpansa_generated": upstream["cpansa_generated"],
    }
    if severity:
        database_specific["severity"] = severity

    record: dict[str, Any] = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": vuln_id,
        "modified": upstream["modified"],
        "aliases": cves,
        "details": details,
        # the main-module alias is one more affected package on this advisory, not a second advisory
        # sharing its id: same ranges, same references, only the package name differs, since it is the
        # same distribution under the spelling an installed packlist gives it
        "affected": [
            {
                "package": {"ecosystem": ECOSYSTEM, "name": name},
                "ranges": ranges,
            }
            for name in [dist_name, *([alias] if alias else [])]
        ],
        "references": [{"type": "WEB", "url": url} for url in references],
        "database_specific": database_specific,
    }
    if published:
        record["published"] = published
    return record


def _ranges(released: list[str], affected: set[str]) -> list[dict[str, Any]]:
    """Compress a resolved affected set into OSV events over the version-ordered release list."""
    events: list[dict[str, str]] = []
    in_run = False
    for idx, version in enumerate(released):
        if version in affected and not in_run:
            # a run starting at the earliest known release is left open below it, since CPANSA's
            # release history is not necessarily complete at the bottom
            events.append({"introduced": "0" if idx == 0 else version})
            in_run = True
        elif version not in affected and in_run:
            events.append({"fixed": version})
            in_run = False

    if not events:
        return []
    return [{"type": "ECOSYSTEM", "events": events}]


def _rfc3339(value: str | None, fmt: str) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.datetime.strptime(str(value).strip(), fmt).replace(tzinfo=datetime.UTC)
    except ValueError:
        return None
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
