from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable

    from vunnel import workspace

ADVISORIES_REPO = "https://github.com/cleanstart-dev/cleanstart-security-advisories.git"
ADVISORIES_DIR = "advisories"

# The advisory feed spells the OSV ecosystem both ways. Normalizing here keeps a
# single spelling in the emitted records so downstream consumers don't each have
# to know about the variant.
CANONICAL_ECOSYSTEM = "CleanStart"
ECOSYSTEM_ALIASES = frozenset({"cleanstart", "clnstrt"})

# Identifiers the feed points at live in `upstream` (OSV 1.7). Some are emitted
# fully lower-cased, which does not match the canonical form used everywhere
# else ("GHSA-hr2v-4r36-88hr", "CVE-2026-1111") and so fails to line up with the
# same vulnerability coming from another provider. Only the prefix is
# case-folded: a GHSA id's suffix is lower-case by construction, so upper-casing
# the whole string would corrupt it.
_ID_PREFIX_RE = re.compile(r"^(ghsa|cve|gms|pysec|go|rustsec|osv)-", re.IGNORECASE)

# Leading "<major>.<minor>" of an apk version such as "8.0.4-r0" or "3.194.1-r1".
_BRANCH_RE = re.compile(r"^(\d+)\.(\d+)")


def normalize_ecosystem(ecosystem: str) -> str:
    """Map any accepted CleanStart ecosystem spelling onto the canonical one.

    Ecosystems may carry a ":<version>" suffix; the suffix is preserved as-is.
    Ecosystems belonging to some other distro are returned untouched.
    """
    name, sep, version = ecosystem.partition(":")
    if name.strip().lower() not in ECOSYSTEM_ALIASES:
        return ecosystem
    return CANONICAL_ECOSYSTEM + sep + version


def normalize_identifier(identifier: str) -> str:
    """Upper-case a known vulnerability-id prefix, leaving the suffix alone."""
    match = _ID_PREFIX_RE.match(identifier)
    if not match:
        return identifier
    prefix = match.group(1)
    return identifier[: match.start(1)] + prefix.upper() + identifier[match.end(1) :]


def _branch_of(version: str) -> tuple[int, int] | None:
    """The maintenance branch a fix version belongs to, or None if unparseable."""
    m = _BRANCH_RE.match(version)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _apk_sort_key(version: str) -> tuple:
    """Ordering for apk versions, used only to pick the earliest fix within a branch.

    Every component is wrapped so numeric and non-numeric parts stay mutually
    comparable; the feed contains versions like "2.5.4-1" (no "r" on the
    revision) that would otherwise mix ints and strs in the same tuple.
    """
    head, _, rev = version.partition("-r")
    parts = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"[.\-_]", head))
    return (parts, int(rev) if rev.isdigit() else 0)


def derive_branch_windows(fixes: list[str]) -> dict[str, str] | None:
    """Map each fix version to the `introduced` bound implied by its branch.

    CleanStart advisories come from APKBUILD `secfixes:`, which records only
    "CVE fixed in version X" — there is no `introduced` to copy. When one CVE is
    backported to several maintenance branches the feed emits one entry per
    branch, each with `introduced: "0"`, so the highest fix claims every version
    below it and swallows the lower branches. A package on an older but fully
    patched branch then matches forever: redis 8.0.4-r0 is not < 8.0.4-r0, but
    it is < 8.2.2-r0.

    The branch structure is recoverable from the fix versions themselves. A CVE
    listed as fixed in both 8.0.4-r0 and 8.2.2-r0 can only mean two branches, so
    each fix is bounded below by its own branch. The lowest keeps "0" so
    anything below the oldest supported branch still matches.

    Returns None if any version cannot be parsed, so the caller can leave the
    record exactly as the feed produced it rather than guess.
    """
    branches: dict[tuple[int, int], list[str]] = {}
    for f in fixes:
        b = _branch_of(f)
        if b is None:
            return None
        branches.setdefault(b, []).append(f)

    windows: dict[str, str] = {}
    for i, b in enumerate(sorted(branches)):
        # earliest version in the branch is the first one carrying the patch;
        # any later fix listed for the same branch is redundant
        earliest = min(branches[b], key=_apk_sort_key)
        windows[earliest] = "0" if i == 0 else f"{b[0]}.{b[1]}.0"
    return windows


def collect_branches(records: Iterable[dict[str, Any]]) -> dict[str, set[tuple[int, int]]]:
    """Every maintenance branch each package is known to ship.

    Built from the union of fix versions across the whole feed, because a single
    advisory only names the branches *it* fixed. Knowing the rest is what makes
    the gap check below possible.
    """
    branches: dict[str, set[tuple[int, int]]] = {}
    for record in records:
        for affected in _affected_entries(record):
            name = (affected.get("package") or {}).get("name")
            for rng in affected.get("ranges") or []:
                fixed = _fixed_version(rng)
                b = _branch_of(fixed) if fixed else None
                if b is not None:
                    branches.setdefault(name, set()).add(b)
    return branches


def _has_gap(fix_branches: set[tuple[int, int]], known: set[tuple[int, int]]) -> bool:
    """True if a shipped branch sits between the fixed ones with no fix of its own.

    Deriving `introduced` turns one wide window into one window per branch. That
    is only safe when the branches are the whole story: a shipped branch with no
    fix listed would fall between the new windows and stop being reported, and
    nothing in the feed says whether it was ever affected.

    harbor-fips is the case this guards. An advisory fixing 2.10, 2.12 and 2.13
    leaves 2.11 — which is shipped — covered by nothing, so that record is left
    exactly as the feed produced it.
    """
    low, high = min(fix_branches), max(fix_branches)
    return any(low < b < high and b not in fix_branches for b in known)


def _affected_entries(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [a for a in (record.get("affected") or []) if isinstance(a, dict)]


def _fixed_version(rng: dict[str, Any]) -> str | None:
    return next((e["fixed"] for e in (rng.get("events") or []) if e.get("fixed")), None)


def _windows_by_package(
    record: dict[str, Any],
    known_branches: dict[str, set[tuple[int, int]]],
) -> dict[str, dict[str, str]]:
    """Derive per-package branch windows, skipping any package it isn't safe for."""
    fixes: dict[str, set[str]] = {}
    for affected in _affected_entries(record):
        name = (affected.get("package") or {}).get("name")
        for rng in affected.get("ranges") or []:
            fixed = _fixed_version(rng)
            if fixed:
                fixes.setdefault(name, set()).add(fixed)

    out = {}
    for name, versions in fixes.items():
        if len(versions) < 2:
            continue  # a lone fix already gives an unambiguous "< fix"
        windows = derive_branch_windows(sorted(versions))
        if windows is None:
            continue  # unparseable version: leave the record alone
        fix_branches = {b for b in (_branch_of(v) for v in versions) if b is not None}
        if _has_gap(fix_branches, known_branches.get(name, set())):
            continue  # a shipped branch would fall through the new windows
        out[name] = windows
    return out


def _rebind(affected: dict[str, Any], windows: dict[str, str]) -> bool:
    """Bound each range below by its branch. False if the entry is superseded."""
    for rng in affected.get("ranges") or []:
        fixed = _fixed_version(rng)
        if fixed is None:
            continue
        if fixed not in windows:
            return False  # a later fix on a branch that already has an earlier one
        rng["events"] = [{"introduced": windows[fixed]}, {"fixed": fixed}]
    return True


def _bound_affected_ranges(
    record: dict[str, Any],
    known_branches: dict[str, set[tuple[int, int]]],
) -> None:
    """Add derived `introduced` bounds to multi-branch backports, in place."""
    windows_by_package = _windows_by_package(record, known_branches)
    if not windows_by_package:
        return

    kept = []
    for affected in record.get("affected") or []:
        windows = None
        if isinstance(affected, dict):
            windows = windows_by_package.get((affected.get("package") or {}).get("name"))
        if windows is None or _rebind(affected, windows):
            kept.append(affected)
    record["affected"] = kept


def normalize_record(
    record: dict[str, Any],
    known_branches: dict[str, set[tuple[int, int]]] | None = None,
) -> dict[str, Any]:
    """Apply the feed-level fixups the CleanStart advisories need.

    Mutates and returns the record. Three things are corrected:

      * ecosystem spelling, so every emitted record uses "CleanStart"
      * vulnerability-id casing in `upstream`, `aliases` and `related`
      * `introduced` bounds on multi-branch backports, but only where every
        shipped branch of the package is accounted for (see derive_branch_windows
        and _has_gap). Without `known_branches` this step is skipped entirely.
    """
    for field in ("upstream", "aliases", "related"):
        values = record.get(field)
        if isinstance(values, list):
            record[field] = [normalize_identifier(v) if isinstance(v, str) else v for v in values]

    for affected in _affected_entries(record):
        package = affected.get("package")
        if isinstance(package, dict) and isinstance(package.get("ecosystem"), str):
            package["ecosystem"] = normalize_ecosystem(package["ecosystem"])

    if known_branches:
        _bound_affected_ranges(record, known_branches)

    return record


class Parser:
    def __init__(self, ws: workspace.Workspace, logger: logging.Logger | None = None):
        self.workspace = ws
        self.urls = [ADVISORIES_REPO]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        yield from self._fetch_and_parse()

    def _sync_repo(self, clone_dir: str) -> None:
        # S603/S607 disable explanation: running git against a constant,
        # in-repo URL by design — same approach as the alma and bitnami
        # providers.
        if os.path.exists(clone_dir):
            self.logger.info("updating existing advisory repo")
            subprocess.run(["git", "-C", clone_dir, "pull"], check=True, capture_output=True)  # noqa: S603, S607
        else:
            self.logger.info(f"cloning advisory repo from {ADVISORIES_REPO}")
            subprocess.run(["git", "clone", "--depth=1", ADVISORIES_REPO, clone_dir], check=True, capture_output=True)  # noqa: S603, S607

    def _fetch_and_parse(self) -> Generator[tuple[str, dict[str, Any]]]:
        clone_dir = os.path.join(self.workspace.input_path, "cleanstart-security-advisories")
        self._sync_repo(clone_dir)

        advisories_path = os.path.join(clone_dir, ADVISORIES_DIR)

        # walk all subdirectories (e.g. 2025/, 2026/), sorted so a run emits
        # records in a stable order regardless of filesystem iteration order
        json_files = []
        for root, dirs, files in os.walk(advisories_path):
            dirs.sort()
            for filename in sorted(files):
                if filename.endswith(".json"):
                    json_files.append(os.path.join(root, filename))

        self.logger.info(f"found {len(json_files)} advisories")

        # First pass: learn which branches each package ships. A single advisory
        # only names the branches it fixed, so the gap check needs the whole feed.
        known_branches = collect_branches(self._read_all(json_files))
        self.logger.info(f"indexed branches for {len(known_branches)} packages")

        for filepath in json_files:
            try:
                with open(filepath, encoding="utf-8") as f:
                    record = orjson.loads(f.read())
                vuln_id = record["id"]
                yield vuln_id, normalize_record(record, known_branches)
            except Exception as e:
                self.logger.warning(f"skipping {filepath}: {e}")

    def _read_all(self, paths: list[str]) -> Generator[dict[str, Any]]:
        """Yield each advisory, skipping any that will not parse."""
        for filepath in paths:
            try:
                with open(filepath, encoding="utf-8") as f:
                    yield orjson.loads(f.read())
            except Exception as e:
                self.logger.warning(f"skipping {filepath} while indexing branches: {e}")
