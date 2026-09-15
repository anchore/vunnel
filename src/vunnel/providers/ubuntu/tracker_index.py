"""Index the frozen security-tracker snapshot so the emit path can read it per release.

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

Why an index
------------
The snapshot is 69,870 files keyed by CVE, and the emit path walks one release
at a time. Reading every file per release is the wrong shape, so it is
transposed once into one fragment per codename, written by the same writer and
read by the same reader as the OSV and VEX fragments, and joined per release
exactly as they are.

The source is frozen, so the index is built when it is missing and never again.
A completion marker records that the build finished, so an interrupted build is
resumed rather than half-trusted.

`DNE` rows are not indexed. They say the release never shipped the package,
which is 16.9 million of the 20.7 million rows and means nothing to emit.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import result, schema

from . import parser_legacy, vex_cache
from .vex_overlay import NO_FIX, NOT_AFFECTED, WONT_FIX

if TYPE_CHECKING:
    import logging
    from collections.abc import Iterator

    from vunnel.workspace import Workspace

FRAGMENTS_SUBDIR = "tracker-index"

# Written once, after the build completes without error. Its absence is what
# makes a run build the index; see `TrackerSnapshotIndex.build`.
#
# The name carries a version because the snapshot being frozen is what lets the
# build skip itself, and that reasoning covers the source and not this file. When
# `distill` starts reading something it did not read before, every index already
# on disk is missing rows and nothing about the marker would say so. Bumping the
# suffix is what makes those rebuild; the old marker is left where it is.
INDEX_MARKER = ".index-complete-v2"

# The tracker statuses this reads, spelled as the snapshot spells them. The
# remaining ones (`needs-triage`, `needed`, `pending`, `deferred`, `active`) all
# mean the same thing to the output and are not named individually.
STATUS_DNE = "DNE"
STATUS_RELEASED = "released"
STATUS_IGNORED = "ignored"
STATUS_NOT_AFFECTED = "not-affected"

# Only files named for a CVE are read; the snapshot directory holds nothing else
# today, and a stray file should not become a row.
_CVE_FILENAME_PREFIX = "CVE-"


def disposition_of_status(status: str) -> str | None:
    """What a tracker status means to the emit path, or None if it means nothing.

    This is `map_parsed`'s own mapping, kept in step with it deliberately: the
    legacy passthrough still emits from these same files for releases the OSV
    feed does not cover, and the two must not disagree about what a status
    means. `not-affected` is the `"0"` row, `ignored` is won't-fix, `DNE` is
    nothing at all, and every remaining status is the security team saying the
    package is vulnerable with no fix yet.

    `released` is not here: it is a fix at a version, and a version is not a
    disposition.
    """
    if status == STATUS_DNE:
        return None
    if status == STATUS_NOT_AFFECTED:
        return NOT_AFFECTED
    if status == STATUS_IGNORED:
        return WONT_FIX
    return NO_FIX


@dataclass(frozen=True)
class TrackerRow:
    """What the snapshot says about one source package on one release.

    `pocket` is empty for the release's own archive, which is every row read out
    of `patches`, and names an extended-support pocket for the clearances read
    out of `ignored_patches`. The two are kept in one fragment and told apart by
    this field rather than split into two, because they are the same sentence
    about the same package and only differ in who researched it.
    """

    codename: str
    cve: str
    package: str
    status: str
    version: str | None = None
    pocket: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "codename": self.codename,
            "cve": self.cve,
            "package": self.package,
            "status": self.status,
            "version": self.version,
            "pocket": self.pocket,
        }

    @classmethod
    def from_payload(cls, payload: Any) -> TrackerRow | None:
        if not isinstance(payload, dict):
            return None
        codename, cve, package, status = (payload.get(k) for k in ("codename", "cve", "package", "status"))
        if not (codename and cve and package and status):
            return None
        version = payload.get("version")
        # a codename, a status and a package name each repeat across millions of
        # rows, and a CVE across every package it names; interning keeps one copy
        # of each rather than one per row
        return cls(
            codename=sys.intern(str(codename)),
            cve=sys.intern(str(cve)),
            package=sys.intern(str(package)),
            status=sys.intern(str(status)),
            version=str(version) if version else None,
            pocket=sys.intern(str(payload.get("pocket") or "")),
        )

    @property
    def identifier(self) -> str:
        """Unique per row, which means the pocket has to be in it.

        A base row and a pocket clearance describe the same package on the same
        release for the same CVE, so without the pocket the second one written
        replaces the first and the release loses whichever lost the race.
        """
        base = f"{self.codename}/{self.cve.lower()}/{self.package}"
        return f"{base}@{self.pocket}" if self.pocket else base


def distill(record: dict[str, Any]) -> Iterator[TrackerRow]:
    """Reduce one snapshot file to the rows worth indexing.

    Both lists are read, for different things. `patches` holds one row per
    release under its bare codename and supplies every disposition and fix
    version. `ignored_patches` holds upstream, `devel` and the extended-support
    pockets, and the only thing taken from it is a pocket's `not-affected`,
    which is a clearance the base release's own row usually does not carry.

    That clearance is the rule the pre-OSV provider implemented in `3032ece`:
    a base `needs-triage` with an ESM pocket saying `not-affected` is an absence
    of research standing next to research, and the research wins. Reading only
    `patches` reimplements half of it, which is how `nasm` on focal came back as
    a false positive the legacy provider had suppressed for months.
    """
    parsed = parser_legacy.CVEFile.from_dict(record)
    if not parsed.name:
        return
    for patch in parsed.patches:
        if not patch.package or not patch.distro or not patch.status:
            continue
        if patch.status == STATUS_DNE:
            continue
        yield TrackerRow(
            codename=patch.distro,
            cve=parsed.name,
            package=patch.package,
            status=patch.status,
            version=patch.version,
        )
    yield from _pocket_clearances(parsed)


def _pocket_clearances(parsed: parser_legacy.CVEFile) -> Iterator[TrackerRow]:
    """The `not-affected` rows an extended-support pocket states, as clearances.

    Which pockets count is `vex_cache`'s answer and not a second list kept here:
    the same set that may assert a clearance out of a VEX statement asserts one
    out of a tracker row, since it is the same claim about the same rebuild.
    That is wider than the three prefixes `parser_legacy` hardcodes — it also
    reaches the `-legacy` spellings and `<codename>/esm` — and narrower in the
    way that matters, because `upstream` and `devel` sit in this list too and
    name no release.

    A row whose `version` looks like a version is a fix and not a clearance,
    which is `parser_legacy`'s own test and is kept identical to it.
    """
    for ip in parsed.ignored_patches:
        if not ip.package or not ip.distro or ip.status != STATUS_NOT_AFFECTED:
            continue
        if ip.version and ip.version[:1].isdigit():
            continue
        pocket = vex_cache.pocket_of_token(ip.distro)
        if pocket == vex_cache.BASE_POCKET or not vex_cache.token_asserts(ip.distro):
            continue
        yield TrackerRow(
            codename=vex_cache.codename_of_token(ip.distro),
            cve=parsed.name,
            package=ip.package,
            status=ip.status,
            version=None,
            pocket=pocket,
        )


class TrackerSnapshotIndex:
    """The per-codename fragments under `input/tracker-index/`.

    One `results.db` per codename, holding one envelope per
    (codename, CVE, source package), written by the same writer and read by the
    same reader as the other two caches so all three join the same way.
    """

    def __init__(self, workspace: Workspace, logger: logging.Logger):
        self.workspace = workspace
        self.logger = logger
        self.directory = os.path.join(workspace.input_path, FRAGMENTS_SUBDIR)
        # one release's fragment at a time; see `_load`
        self._loaded: tuple[str, dict[tuple[str, str], TrackerRow], dict[tuple[str, str], TrackerRow]] | None = None

    def path_for(self, codename: str) -> str:
        return os.path.join(self.directory, f"{codename}.db")

    @property
    def marker_path(self) -> str:
        return os.path.join(self.directory, INDEX_MARKER)

    @property
    def built(self) -> bool:
        return os.path.exists(self.marker_path)

    def _open_writer(self, codename: str) -> result.Writer:
        os.makedirs(self.directory, exist_ok=True)
        writer = result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=self.path_for(codename),
            logger=self.logger,
        )
        return writer.__enter__()

    def build(self, snapshot_dir: str) -> None:
        """Transpose the snapshot into per-codename fragments, once.

        Does nothing when the marker is there, because the source cannot change:
        nothing writes to `normalized-cve-data/` any more. A build that raises
        leaves no marker, so the next run does it again from the start rather
        than reading half an index.
        """
        if self.built:
            return
        if not os.path.isdir(snapshot_dir):
            self.logger.warning(f"no tracker snapshot at {snapshot_dir}; the third source will be absent")
            return

        started = time.monotonic()
        self.logger.info(f"indexing the tracker snapshot at {snapshot_dir}; this happens once")
        writers: dict[str, result.Writer] = {}
        rows = 0
        exc: BaseException | None = None
        try:
            for filename in sorted(os.listdir(snapshot_dir)):
                if not filename.startswith(_CVE_FILENAME_PREFIX):
                    continue
                path = os.path.join(snapshot_dir, filename)
                try:
                    with open(path, "rb") as fh:
                        record = orjson.loads(fh.read())
                except Exception:
                    self.logger.exception(f"failed to read tracker snapshot file {path}")
                    continue
                for row in distill(record):
                    writer = writers.get(row.codename)
                    if writer is None:
                        writer = writers[row.codename] = self._open_writer(row.codename)
                    writer.write(
                        identifier=row.identifier,
                        schema=schema.OSSchema(),
                        payload=row.to_payload(),
                    )
                    rows += 1
        except BaseException as e:
            exc = e
            raise
        finally:
            for writer in writers.values():
                writer.__exit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)

        self._record_built()
        self.logger.info(f"tracker snapshot indexed: {rows} rows over {len(writers)} releases in {time.monotonic() - started:.1f}s")

    def _record_built(self) -> None:
        os.makedirs(self.directory, exist_ok=True)
        with open(self.marker_path, "wb"):
            pass

    def codenames_on_disk(self) -> list[str]:
        if not os.path.isdir(self.directory):
            return []
        return sorted(f[: -len(".db")] for f in os.listdir(self.directory) if f.endswith(".db"))

    def rows_for(self, codename: str) -> dict[tuple[str, str], TrackerRow]:
        """The release's own archive rows, keyed by (CVE, source package)."""
        return self._load(codename)[0]

    def clearances_for(self, codename: str) -> dict[tuple[str, str], TrackerRow]:
        """The release's extended-support clearances, keyed the same way.

        Separate from `rows_for` because they key the same way and mean
        different things: a base row says what the release's own archive states
        and a clearance says what the pocket researched. Merged into one dict
        they would collide, and whichever was read second would win.
        """
        return self._load(codename)[1]

    def _load(self, codename: str) -> tuple[dict[tuple[str, str], TrackerRow], dict[tuple[str, str], TrackerRow]]:
        """Read one release's fragment, split into archive rows and pocket clearances.

        Read when the release is assembled and dropped when it is done, for the
        same reason the VEX statements are: what is asked of them is only ever
        asked while one release is in hand. The result is held for exactly one
        codename, so the two callers in a release's assembly read the fragment
        once between them rather than once each.
        """
        if self._loaded is not None and self._loaded[0] == codename:
            return self._loaded[1], self._loaded[2]

        rows: dict[tuple[str, str], TrackerRow] = {}
        clearances: dict[tuple[str, str], TrackerRow] = {}
        path = self.path_for(codename)
        if os.path.isfile(path):
            try:
                with result.SQLiteReader(path) as reader:
                    for envelope in reader.each():
                        row = TrackerRow.from_payload(envelope.item)
                        if row is None:
                            continue
                        target = clearances if row.pocket else rows
                        target[(row.cve, row.package)] = row
            except Exception as e:  # a corrupt fragment must not take down the run
                self.logger.warning(f"could not read the tracker index at {path}: {e}")

        self._loaded = (codename, rows, clearances)
        return rows, clearances
