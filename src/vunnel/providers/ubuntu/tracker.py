"""Read the frozen security-tracker snapshot as the emit path's third source.

Why the snapshot is a source at all
-----------------------------------
`input/normalized-cve-data/` is what the pre-OSV provider emitted from: one
JSON file per CVE, holding the security team's own status for every package on
every release. It stopped being updated when this provider switched to the OSV
feed, so it is a photograph rather than a feed.

It still holds things neither current feed states. Canonical's OSV feed lists a
package under a release only while it means to keep tracking it there, and when
it stops, the fix version goes with it: 3,727 `(release, CVE, package)`
combinations lost a real fix version that way, and 1,197 records were left
naming no fix at all. The snapshot holds the same version for every one of
them, byte for byte. It also holds won't-fix rows for CVEs the OSV feed never
carried.

Fix versions are historical facts — the version that fixed a CVE in focal in
2019 is still that version — so a June snapshot does not go stale for them. The
non-fix dispositions are staler, which is why they are read only where neither
current feed mentions the combination at all.

Why there is no index
---------------------
The snapshot is already one file per CVE, which is the key the emit pass walks,
so the file is opened when that CVE comes round and closed again. Transposing
it into per-release fragments only makes sense for a release-major walk.

`DNE` rows say the release never shipped the package, which is 16.9 million of
the 20.7 million rows and means nothing to emit, so they are dropped on the way
in rather than carried and skipped later.
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING, Any

import orjson

from . import parser_legacy, vex_cache
from .vex_overlay import NO_FIX, NOT_AFFECTED, WONT_FIX

if TYPE_CHECKING:
    import logging

# The tracker statuses this reads, spelled as the snapshot spells them. The
# remaining ones (`needs-triage`, `needed`, `pending`, `deferred`, `active`) all
# mean the same thing to the output and are not named individually.
STATUS_DNE = "DNE"
STATUS_RELEASED = "released"
STATUS_IGNORED = "ignored"
STATUS_NOT_AFFECTED = "not-affected"

# Only files named for a CVE are read; the snapshot directory holds nothing else
# today, and a stray file should not become a row.
CVE_FILENAME_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")


def disposition_of_status(status: str) -> str | None:
    """What a tracker status means to the emit path, or None if it means nothing.

    This is `map_parsed`'s own mapping, tied to it by construction rather than
    by a comment promising they are kept in step: the legacy passthrough still
    emits from these same files for releases the OSV feed does not cover, both
    paths run on the releases they overlap on, and the two disagreeing means the
    same row produces a finding down one path and nothing down the other.

    `not-affected` is the `"0"` row, `ignored` is won't-fix, `DNE` is nothing at
    all, and a status in `patch_states` beyond those is the security team saying
    the package is vulnerable with no fix yet. A status in neither mapping —
    `in-progress` is the live example — means nothing here because it means
    nothing to `map_parsed`, which drops the row through `check_state`. That is a
    pre-existing gap in `patch_states` and fixing it belongs there, where it
    changes both paths deliberately instead of one of them by accident.

    `released` is not here: it is a fix at a version, and a version is not a
    disposition.
    """
    if status == STATUS_DNE:
        return None
    if status == STATUS_NOT_AFFECTED:
        return NOT_AFFECTED
    if status == STATUS_IGNORED:
        return WONT_FIX
    if status not in parser_legacy.patch_states:
        return None
    return NO_FIX


def snapshot_keys(snapshot_dir: str) -> set[str]:
    """Every CVE the snapshot holds a file for."""
    if not os.path.isdir(snapshot_dir):
        return set()
    return {name for name in os.listdir(snapshot_dir) if CVE_FILENAME_RE.match(name)}


def load(snapshot_dir: str, cve: str, logger: logging.Logger) -> parser_legacy.CVEFile | None:
    """One CVE's snapshot file, parsed, or None when there is none or it is unreadable."""
    path = os.path.join(snapshot_dir, cve)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as handle:
            record: dict[str, Any] = orjson.loads(handle.read())
    except Exception:
        logger.exception(f"failed to load normalized cve {path}")
        return None
    return parser_legacy.CVEFile.from_dict(record)


def esm_clearances(cve_file: parser_legacy.CVEFile) -> set[tuple[str, str]]:
    """The `(codename, source package)` pairs an extended-support pocket has cleared.

    The rule the pre-OSV provider implemented: a base release row that is an
    absence of research — `needs-triage` — standing next to an ESM pocket that
    researched the same source package and concluded the vulnerable code is not
    there is not a contradiction, and the research wins. It is the same claim
    about the same rebuild that a `not_affected` VEX statement at that pocket
    makes, read out of Canonical's other file for the combinations where there
    is no statement to read it out of at all.

    Which pockets count is `vex_cache`'s answer and not a second list kept here,
    since it is the same claim. That is wider than the three prefixes
    `parser_legacy` hardcodes — it also reaches the `-legacy` spellings and
    `<codename>/esm` — and narrower in the way that matters, because `upstream`
    and `devel` sit in `ignored_patches` too and name no release.

    A row whose `version` looks like a version is a fix and not a clearance,
    which is `parser_legacy`'s own test and is kept identical to it.
    """
    out: set[tuple[str, str]] = set()
    for ignored in cve_file.ignored_patches:
        if not ignored.package or not ignored.distro or ignored.status != STATUS_NOT_AFFECTED:
            continue
        if ignored.version and ignored.version[:1].isdigit():
            continue
        pocket = vex_cache.pocket_of_token(ignored.distro)
        if pocket == vex_cache.BASE_POCKET or not vex_cache.token_asserts(ignored.distro):
            continue
        out.add((vex_cache.codename_of_token(ignored.distro), ignored.package))
    return out
