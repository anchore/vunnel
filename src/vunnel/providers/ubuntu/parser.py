from __future__ import annotations

import datetime
import logging
import os
import re
import tarfile
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import result, schema
from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv, silent_remove

from . import eol_calendar, parser_legacy, tracker_index, vex_cache
from .os_downconvert import (
    ANCHORE_STATUS_NOT_AFFECTED,
    ANCHORE_STATUS_WONT_FIX,
    _is_not_affected,
    is_cve_program_rejection,
    os_identifier_for,
    osv_to_os,
)
from .usn_fixdate_overlay import USNFixDateOverlay, usn_extra_candidates
from .vex_overlay import (
    CLEARANCES,
    NO_FIX,
    NOT_AFFECTED,
    NOT_PRESENT,
    WONT_FIX,
    VEXOverlay,
    distro_label_from_purl,
    source_package_from_purl,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from vunnel.workspace import Workspace


_CVE_FILENAME_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")


_SCHEMA_VERSION_RE = re.compile(r"/schema-([0-9]+(?:\.[0-9]+){1,2})\.json$")


def ecosystem_to_slug(ecosystem: str) -> str:
    """Map an OSV ecosystem string to a filesystem-safe slug.

    Lowercase and replace `:` with `-`. The mapping is reversible by
    splitting on `-` against the known ecosystem set, but we don't rely
    on that — the slug is opaque to callers.
    """
    return ecosystem.lower().replace(":", "-")


_VERSION_RE = re.compile(r"^\d+\.\d+$")

# One Ubuntu release is published under two ecosystem strings over its life:
# Canonical appends the `:LTS` segment when the release reaches general
# availability, so records written before GA name `Ubuntu:26.04` and records
# written after it name `Ubuntu:26.04:LTS`. `_BASE_ECO_RE` and
# `_PLAIN_PRO_ECO_RE` in os_downconvert.py already encode that alias with an
# optional `(?::LTS)?` group; this is the same shape generalized over the
# channel segments (Pro, Pro:FIPS, Nvidia-BlueField, ...) that sit between
# `Ubuntu` and the version.
#
# Ecosystem strings that don't fit the shape — Canonical also publishes a
# handful of malformed ones such as `Ubuntu:22.04:LTS:for:NVIDIA:BlueField` —
# get no identity and keep their literal spelling everywhere.
_ECOSYSTEM_RE = re.compile(r"^(?P<channel>Ubuntu(?::[A-Za-z][^:]*)*):(?P<version>\d+\.\d+)(?::LTS)?$")

# Canonical's own id for a CVE record is the CVE id with this in front of it, in
# every record the feed publishes. It is what makes an envelope for a CVE the OSV
# fragment does not carry addressable at the identifier a real one would use.
_OSV_ID_PREFIX = "UBUNTU-"

# The channel of a release's own archive; every other channel is an extended
# support build (`Ubuntu:Pro`, `Ubuntu:Pro:FIPS`, `Ubuntu:Nvidia-BlueField`, ...).
_BASE_CHANNEL = "Ubuntu"


def _version_is_lts(version: str) -> bool:
    """Is this Ubuntu release version an LTS release?

    Canonical ships an LTS every two years, in April of an even-numbered year,
    and has done so without exception since 8.04. The `:LTS` segment on the
    ecosystem string can't answer this on its own: it is absent from every
    record written before the release reached general availability, and those
    are exactly the records canonicalisation has to fold in.

    This decides the spelling of a release's identity and nothing else. Whether
    a release is still being updated is a calendar question, answered by
    `eol_calendar` from the published `version` column, never from here.
    """
    year, _, month = version.partition(".")
    if month != "04" or not year.isdigit():
        return False
    return int(year) % 2 == 0


@dataclass(frozen=True)
class ReleaseIdentity:
    """The release an OSV ecosystem string names, independent of its spelling.

    `channel` is everything the string says other than the release version:
    `Ubuntu` for a base release, `Ubuntu:Pro`, `Ubuntu:Pro:FIPS-updates`,
    `Ubuntu:Nvidia-BlueField` and so on. Distinct channels are distinct
    identities and keep separate fragments, including the ones that map to no
    output namespace at all (FIPS, Realtime, BlueField): they are separate
    builds, not spellings of one thing.

    `version` is the base release the channel derives from, which is what the
    end-of-life calendar and the known-husk list are keyed on.
    """

    channel: str
    version: str

    @property
    def is_lts(self) -> bool:
        return _version_is_lts(self.version)

    @property
    def ecosystem(self) -> str:
        """The canonical spelling: the current one, carrying `:LTS` when the release is one."""
        return f"{self.channel}:{self.version}:LTS" if self.is_lts else f"{self.channel}:{self.version}"

    @property
    def slug(self) -> str:
        return ecosystem_to_slug(self.ecosystem)


def release_identity(ecosystem: str) -> ReleaseIdentity | None:
    """Resolve an OSV ecosystem string to the release it names, or None if unrecognized."""
    m = _ECOSYSTEM_RE.match(ecosystem)
    if m is None:
        return None
    return ReleaseIdentity(channel=m.group("channel"), version=m.group("version"))


def canonical_ecosystem(ecosystem: str) -> str:
    """Fold an ecosystem string onto the canonical spelling of the release it names.

    An unrecognized string is its own canonical form, so nothing is ever merged
    on a guess.
    """
    identity = release_identity(ecosystem)
    return identity.ecosystem if identity is not None else ecosystem


def canonical_slug(ecosystem: str) -> str:
    """The fragment file stem for an ecosystem, one per release identity."""
    return ecosystem_to_slug(canonical_ecosystem(ecosystem))


# Releases whose fragment was written from Canonical's post-sweep residue before
# the calendar rule existed. The freeze rule protects a cache from a sweep but
# cannot repair one that has already been overwritten, so these two are retired
# once and served from the tracker cache in `input/normalized-cve-data/`
# instead. The list is a fact, not a heuristic: nothing in the data separates a
# husk from a healthy fragment for a release that is merely past its end of life,
# and the freeze rule fires before any future sweep can add to the list.
_KNOWN_HUSK_RELEASES = frozenset(
    {
        # oracular, swept 2025-07-11. The feed carries 157 records for it, 153 of
        # them withdrawn, and the fragment on disk was written from exactly that.
        "24.10",
        # plucky, swept 2026-01-20. Same shape: 184 records, 181 withdrawn. The
        # tracker cache is a good substitute — compared against the last
        # plucky-intact upstream commit over 115,253 (CVE, source package) pairs
        # it agrees on 99.8% of verdicts, 99.4% of the 36,791 actionable ones,
        # and on 8,966 of 8,966 fix versions byte for byte.
        "25.04",
    },
)

# Fallback for a fragment whose contents cannot be read: `ubuntu-25.04.db` and
# `ubuntu-26.04-lts.db` both name a base release in their file name.
_BASE_FRAGMENT_NAME_RE = re.compile(r"^ubuntu-(\d+\.\d+)(?:-lts)?\.db$")


def pro_to_base_ecosystem(ecosystem: str) -> str | None:
    """Map a plain Ubuntu Pro (ESM) ecosystem to its base Ubuntu form.

    Only the plain ESM tier qualifies. Sub-tiers (FIPS, FIPS-updates,
    FIPS-preview, Realtime) and adjacent product lines (Nvidia-BlueField)
    are intentionally excluded:

      - FIPS / FIPS-updates / FIPS-preview rebuild specific packages
        (kernel, openssl, libgcrypt, ...) against FIPS 140-validated
        cryptographic modules. The crypto code paths differ from base.
        A CVE in the FIPS-rebuilt binary may or may not exist in the
        mainline binary depending on whether the bug is in the
        FIPS-modified code; inference would be unreliable.

      - Realtime is the PREEMPT_RT kernel — locking, scheduling, and
        concurrency paths are materially different. RT-specific CVEs
        and non-RT-specific CVEs both exist.

      - Nvidia-BlueField is a separate SmartNIC/DPU OS product line
        with its own package set.

    Plain Ubuntu Pro packages are byte-identical to base packages while
    base is supported, then diverge only via ESM-backported security
    patches. A CVE on Pro means the same vulnerable code shipped on base
    — that's the inference this enables.

      Ubuntu:Pro:20.04:LTS              -> Ubuntu:20.04:LTS    (plain ESM, inferable)
      Ubuntu:Pro:14.04:LTS              -> Ubuntu:14.04:LTS
      Ubuntu:Pro:FIPS:20.04:LTS         -> None                (different build)
      Ubuntu:Pro:FIPS-updates:22.04:LTS -> None                (different build)
      Ubuntu:Pro:Realtime:24.04:LTS     -> None                (PREEMPT_RT kernel)
      Ubuntu:Nvidia-BlueField:22.04:LTS -> None                (separate product)
      Ubuntu:20.04:LTS                  -> None                (already base)
    """
    parts = ecosystem.split(":")
    # plain Pro shape: Ubuntu:Pro:<version>[:LTS], 3 or 4 segments, nothing between Pro and version
    if len(parts) not in (3, 4):
        return None
    if parts[0] != "Ubuntu" or parts[1] != "Pro":
        return None
    if not _VERSION_RE.match(parts[2]):
        return None
    if len(parts) == 4 and parts[3] != "LTS":
        return None
    return ":".join(["Ubuntu", *parts[2:]])


# Version -> codename, inverted from the table the legacy passthrough already
# carries. VEX names a release by codename and OSV by version, and a synthesized
# base entry has only the version.
_CODENAMES_BY_VERSION = {version: codename for codename, version in parser_legacy.ubuntu_version_names.items()}


def _codename_for_version(version: str) -> str | None:
    return _CODENAMES_BY_VERSION.get(version)


def _affected_package_names(payload: dict[str, Any]) -> set[str]:
    """Return the set of source-package names in a record's affected[]."""
    out: set[str] = set()
    for a in payload.get("affected", []):
        pkg = a.get("package", {}).get("name")
        if pkg:
            out.add(pkg)
    return out


def _synthesize_missing(
    pro_affs: list[dict[str, Any]],
    existing_pkgs: set[str],
    base_eco: str,
    pro_eco: str | None,
) -> list[dict[str, Any]]:
    """For each Pro affected[] entry whose source-package isn't already in the
    base envelope, produce a synthesized base affected[] entry tagged with the
    inference provenance.
    """
    new_affs: list[dict[str, Any]] = []
    for aff in pro_affs:
        pkg = aff.get("package", {}).get("name")
        if not pkg or pkg in existing_pkgs:
            continue
        existing_pkgs.add(pkg)
        synth = _build_synthetic_base_affected(aff, base_eco)
        synth["database_specific"]["anchore"]["inference"] = {
            "kind": "pro-only-fix",
            "source_ecosystems": [pro_eco] if pro_eco else [],
        }
        new_affs.append(synth)
    return new_affs


def _build_synthetic_base_affected(template: dict[str, Any], base_eco: str) -> dict[str, Any]:
    """Build a single synthetic affected[] entry for the base ecosystem.

    Inherits source package name and binary list from the Pro template (binaries
    on Pro ESM are byte-identical to base while base was supported; carrying
    them lets binary→source resolution still work downstream). Drops `purl`
    since its `distro=` qualifier points at a Pro codename (e.g. `esm-infra/jammy`).
    """
    src_pkg = dict(template.get("package", {}))
    src_pkg["ecosystem"] = base_eco
    src_pkg.pop("purl", None)

    eco_specific: dict[str, Any] = {}
    if "binaries" in template.get("ecosystem_specific", {}):
        eco_specific["binaries"] = template["ecosystem_specific"]["binaries"]

    return {
        "package": src_pkg,
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": eco_specific,
        "database_specific": {
            "anchore": {
                "status": ANCHORE_STATUS_WONT_FIX,
                # `inference.source_ecosystems` filled in by the caller — the same
                # base (CVE, source-pkg) may have inferences from multiple Pro slices
                # (though restriction to plain Pro makes this rare in practice).
            },
        },
    }


def slice_by_ecosystem(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Group a record's affected[] entries by the release their ecosystem names.

    Returns a mapping {canonical ecosystem -> sliced_record}. Each sliced
    record has the original top-level fields and an affected[] containing only
    the entries for that release. Records with no affected[] entries yield an
    empty mapping.

    Grouping is by canonical identity, not by the literal ecosystem string, so
    a record naming a release both with and without the `:LTS` suffix produces
    one slice. The affected[] entries keep whatever spelling upstream gave
    them; only the key is canonical.
    """
    by_eco: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for aff in record.get("affected", []):
        eco = aff.get("package", {}).get("ecosystem")
        if not eco:
            continue
        by_eco[canonical_ecosystem(eco)].append(aff)

    if not by_eco:
        return {}

    top = {k: v for k, v in record.items() if k != "affected"}
    return {eco: {**top, "affected": entries} for eco, entries in by_eco.items()}


def _schema_from_envelope_url(url: str) -> schema.Schema:
    """Reconstruct a Schema object from an envelope's schema URL."""
    m = _SCHEMA_VERSION_RE.search(url)
    version = m.group(1) if m else "0.0.0"
    return schema.Schema(version=version, url=url)


def _iter_cve_records(tar: tarfile.TarFile) -> Iterator[dict[str, Any]]:
    """Yield parsed CVE records from a streaming tar (osv/cve/**/*.json only)."""
    for member in tar:
        if not member.isfile():
            continue
        if not (member.name.startswith("osv/cve/") and member.name.endswith(".json")):
            continue
        fh = tar.extractfile(member)
        if fh is None:
            continue
        yield orjson.loads(fh.read())


def _stamp_anchore_status(aff: dict[str, Any], status: str) -> None:
    """Set `database_specific.anchore.status` on one affected[] entry, keeping its other keys."""
    db_spec = aff.get("database_specific") or {}
    anchore = db_spec.get("anchore") or {}
    anchore["status"] = status
    db_spec["anchore"] = anchore
    aff["database_specific"] = db_spec


def _is_base_ecosystem(ecosystem: str) -> bool:
    """Does this ecosystem string name a release's own archive rather than a channel?"""
    identity = release_identity(ecosystem)
    return identity is not None and identity.channel == _BASE_CHANNEL


def _stamp_vex_provenance(aff: dict[str, Any], token: str, disposition: str) -> None:
    """Record which statement decided an entry that was already there."""
    db_spec = aff.setdefault("database_specific", {})
    anchore = db_spec.setdefault("anchore", {})
    anchore["vex"] = {"token": token, "disposition": disposition}


def _stamp_tracker_provenance(aff: dict[str, Any], codename: str, pocket: str, status: str) -> None:
    """Record which snapshot row decided an entry that was already there.

    The mirror of `_stamp_vex_provenance`, and it names the pocket because that
    is the whole claim: the base release said one thing and the team maintaining
    its extended-support build researched another.
    """
    db_spec = aff.setdefault("database_specific", {})
    anchore = db_spec.setdefault("anchore", {})
    anchore["tracker"] = {"codename": codename, "pocket": pocket, "status": status}


def _mark_not_affected(aff: dict[str, Any]) -> None:
    """Turn an affected[] entry into the vendor's statement that the package is not vulnerable.

    The entry is replaced rather than removed. Removing it emits nothing, and
    nothing is what the consumer already believes; the assertion is only worth
    holding if it is stated, as a `FixedIn` version of exactly `"0"` that
    cancels findings other sources report for the same package. That is also why
    the fix events go: a package cannot be both cleared and fixed at a version,
    and a group mixing a `"0"` with a real version stops being read as a
    clearance at all.
    """
    aff["ranges"] = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
    _stamp_anchore_status(aff, ANCHORE_STATUS_NOT_AFFECTED)


# The `anchore.status` marker each VEX disposition stamps, where it stamps one.
# A no-fix disposition has no marker: an entry with no fix event and no status is
# already what "vulnerable, no fix" looks like everywhere else in this payload.
_ANCHORE_STATUS_BY_DISPOSITION = {
    NOT_AFFECTED: ANCHORE_STATUS_NOT_AFFECTED,
    WONT_FIX: ANCHORE_STATUS_WONT_FIX,
}


def _build_asserted_affected(
    package: str,
    base_eco: str,
    disposition: str,
    source: str,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    """Build an affected[] entry for a package the OSV record does not carry.

    Shaped like `_build_synthetic_base_affected`, which does the same job for
    the Pro-to-base inference: no `purl`, since the entry is not a record the
    feed published, and a range carrying no `fixed` event. A fix version, where
    one is known, is added to that range afterwards by whoever knows it.

    The provenance is recorded for the same reason the inference records its
    own — four different mechanisms can now put an entry on a base record, and
    which one did is not otherwise recoverable.
    """
    anchore: dict[str, Any] = {source: provenance}
    marker = _ANCHORE_STATUS_BY_DISPOSITION.get(disposition)
    if marker is not None:
        anchore["status"] = marker
    return {
        "package": {"ecosystem": base_eco, "name": package},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": {},
        "database_specific": {"anchore": anchore},
    }


def _affected_by_package(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The entry's affected[] entries by source package, built once and kept on it."""
    by_package = entry.get("packages")
    if by_package is None:
        by_package = entry["packages"] = {
            name: aff for aff in entry["payload"].get("affected", []) if (name := (aff.get("package") or {}).get("name"))
        }
    return by_package


def _fixed_versions(aff: dict[str, Any]) -> list[str]:
    return [ev["fixed"] for r in aff.get("ranges") or [] for ev in r.get("events") or [] if ev.get("fixed")]


def _add_fixed_event(aff: dict[str, Any], version: str) -> None:
    """Record a fix version on an entry that has none, in the shape the feed uses."""
    ranges = aff.setdefault("ranges", [])
    if not ranges:
        ranges.append({"type": "ECOSYSTEM", "events": [{"introduced": "0"}]})
    ranges[0].setdefault("events", []).append({"fixed": version})


def _annotate_wont_fix(
    sliced: dict[str, dict[str, Any]],
    original: dict[str, Any],
    overlay: VEXOverlay,
) -> None:
    """Stamp `affected[].database_specific.anchore.status = "wont-fix"` for slices
    Canonical's VEX feed marks as won't-fix.

    Join key is (upstream CVE, PURL distro label, source package). The
    upstream CVE comes from the OSV record's `upstream[0]` (UBUNTU-CVE-* is
    Canonical's internal id; users and VEX use the upstream CVE). Distro
    label + source package come from each per-package PURL inside the slice.
    """
    upstream = original.get("upstream") or []
    if not upstream:
        return
    cve_id = upstream[0]

    for sliced_record in sliced.values():
        for aff in sliced_record.get("affected", []):
            purl = (aff.get("package") or {}).get("purl") or ""
            distro = distro_label_from_purl(purl)
            pkg = source_package_from_purl(purl)
            if not distro or not pkg:
                continue
            if not overlay.is_wont_fix(cve_id, distro, pkg):
                continue
            _stamp_anchore_status(aff, ANCHORE_STATUS_WONT_FIX)


class Parser:
    _osv_url_ = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
    _vex_url_ = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
    # Ubuntu's release calendar, as shipped by the distro-info-data package. Read
    # from the Debian salsa mirror, which answered when launchpad did not.
    _calendar_url_ = eol_calendar.CALENDAR_URL
    _archive_filename_ = "osv-all.tar.xz"
    _vex_archive_filename_ = "vex-all.tar.xz"
    _fragments_subdir_ = "fragments"
    _normalized_subdir_ = "normalized-cve-data"

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        downconvert_osv_to_os: bool = False,
        downconvert_emit_esm: bool = True,
    ):
        self.workspace = workspace
        self.fixdater = fixdater if fixdater is not None else fixdate.default_finder(workspace)
        self.download_timeout = download_timeout
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        # Opt-in compatibility: rewrite OSV fragments into v3 OS-schema records as they
        # are yielded. The legacy normalized-cve-data passthrough already emits OS shape,
        # so when this is enabled every yielded record is OS.
        self.downconvert_osv_to_os = downconvert_osv_to_os
        # When downconverting, also emit `ubuntu:X.YY+esm` channel records for plain Pro
        # (ESM). Default on; the frozen-v5 lane sets this off to take base records only.
        self.downconvert_emit_esm = downconvert_emit_esm

        self.archive_path = os.path.join(workspace.input_path, self._archive_filename_)
        self.vex_archive_path = os.path.join(workspace.input_path, self._vex_archive_filename_)
        self.fragments_dir = os.path.join(workspace.input_path, self._fragments_subdir_)
        self.normalized_cve_dir = os.path.join(workspace.input_path, self._normalized_subdir_)
        self.vex_store = vex_cache.VEXFragmentStore(workspace, self.logger)
        self.tracker_index = tracker_index.TrackerSnapshotIndex(workspace, self.logger)
        self.urls = [self._osv_url_, self._vex_url_, self._calendar_url_]
        # USN fix-date overlay built lazily in get(); _iter_envelopes_with_fixdate reads it.
        self._usn_overlay: USNFixDateOverlay | None = None
        # VEX index built lazily in get() from the cached statements; the yield path reads it.
        self._vex_overlay: VEXOverlay | None = None
        # The release calendar, kept from get() because the yield path resolves a
        # VEX token's codename to a release through it.
        self._calendar: eol_calendar.ReleaseCalendar | None = None
        # Upstream CVEs seen to be CVE-program rejections while reading fragments.
        # The VEX statements carry no `details`, so a rejection is only knowable
        # from the OSV side and has to be remembered across the run.
        self._rejected_cves: set[str] = set()

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

    def _download_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._osv_url_, self.archive_path)

    def _download_vex_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._vex_url_, self.vex_archive_path)

    def _download_calendar(self, url: str, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._stream_to_disk(url, path)

    def _load_calendar(self) -> eol_calendar.ReleaseCalendar:
        """Fetch (or fall back to) the release calendar the freeze rule reads."""
        return eol_calendar.load(
            self.workspace.input_path,
            self._download_calendar,
            self.logger,
            url=self._calendar_url_,
        )

    def _stream_to_disk(self, url: str, path: str) -> None:
        self.logger.info(f"downloading {url}")
        with (
            http.get(url, self.logger, stream=True, timeout=self.download_timeout) as r,
            open(path, "wb") as fh,
        ):
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)

    def _record_schema(self, record: dict[str, Any]) -> schema.Schema:
        return schema.OSVSchema(version=record.get("schema_version", schema.OSV_SCHEMA_VERSION))

    def _open_fragment_writer(self, ecosystem: str) -> result.Writer:
        """Open a writer for a single release's fragment.

        Uses DELETE_BEFORE_WRITE so a live release's fragment is replaced
        wholesale by what the feed says today: a record upstream has removed is
        removed here, which is the property that makes the cache mean "what
        Canonical published today" rather than "everything Canonical has ever
        published".

        A frozen release never gets a writer, so DELETE_BEFORE_WRITE never
        reaches its fragment and the file stays exactly as the last live run
        left it. See `_write_fragments` for which releases those are.
        """
        os.makedirs(self.fragments_dir, exist_ok=True)
        path = os.path.join(self.fragments_dir, f"{canonical_slug(ecosystem)}.db")
        writer = result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=path,
            logger=self.logger,
        )
        return writer.__enter__()

    def _write_fragments(
        self,
        calendar: eol_calendar.ReleaseCalendar | None = None,
        now: datetime.datetime | None = None,
    ) -> None:
        """Stream the tarball, slice records by release, write per-release fragments.

        A live release's fragment is wiped (via DELETE_BEFORE_WRITE) and
        rewritten from today's tarball. A frozen release gets no writer at all
        and its records are discarded here: additions, changes and removals
        alike, without reading anything about them.

        Which releases are frozen is decided once, before the tarball is
        opened, from the release calendar and a single reading of the clock —
        never from the archive, the fragment on disk, or a record's contents.
        Canonical sweeps a dead release out of the feed and leaves a husk of
        never-regenerated records behind, and a provider that trusts the feed
        for a dead release overwrites good data with that husk.

        The one thing read out of a record here rather than written is whether
        the CVE program rejected it. That is a fact about the CVE and not about
        any release, and the record carrying it names only the releases the
        vendor happened to still be publishing when the rejection landed — so
        reading it per release means a release the record does not name never
        learns of it, and rebuilds the CVE from its own VEX statements, which
        carry no `details` and cannot be asked. Every record in the day's
        tarball is checked, including records for releases nothing is written
        for, because upstream never deletes a rejected record.

        NOTE: `patch_fix_date` is intentionally NOT called here. Fix-date
        annotations are applied at yield time (in _iter_fragments) so that
        improvements to the fixdate cache flow through to frozen fragments
        on the next run without rewriting them. Fix disposition is applied at
        yield time for the same reason: a frozen fragment can never be
        rewritten, so anything baked into it is fixed forever.
        """
        frozen_versions = self._frozen_versions(calendar, now)
        self._log_approaching_eol(calendar, now)

        writers: dict[str, result.Writer] = {}
        skipped: dict[str, int] = defaultdict(int)
        exc: BaseException | None = None
        try:
            with tarfile.open(self.archive_path, mode="r:xz") as tar:
                for record in _iter_cve_records(tar):
                    if is_cve_program_rejection(record):
                        self._record_rejection(record)
                    self._dispatch_record_to_fragments(record, writers, frozen_versions, skipped)
        except BaseException as e:
            exc = e
            raise
        finally:
            for writer in writers.values():
                writer.__exit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)
            for eco, count in sorted(skipped.items()):
                self.logger.info(f"{eco} is past its end of life; skipped {count} records still in the feed")

    def _frozen_versions(self, calendar: eol_calendar.ReleaseCalendar | None, now: datetime.datetime | None) -> set[str]:
        """The release versions today's feed is not allowed to write, computed once.

        `now` is sampled once per run rather than per record, so a run that
        crosses midnight uses one decision throughout.
        """
        if calendar is None:
            self.logger.warning("no release calendar available; every release will be treated as live")
            return set()
        return calendar.frozen_versions(now if now is not None else datetime.datetime.now(datetime.UTC))

    def _log_approaching_eol(self, calendar: eol_calendar.ReleaseCalendar | None, now: datetime.datetime | None) -> None:
        if calendar is None:
            return
        for release in calendar.approaching_eol(now if now is not None else datetime.datetime.now(datetime.UTC)):
            self.logger.info(f"ubuntu {release.version} ({release.series}) freezes at {release.eol_instant.isoformat()}")

    def _dispatch_record_to_fragments(
        self,
        record: dict[str, Any],
        writers: dict[str, result.Writer],
        frozen_versions: set[str] | None = None,
        skipped: dict[str, int] | None = None,
    ) -> None:
        sliced = slice_by_ecosystem(record)
        if not sliced:
            return
        rec_schema = self._record_schema(record)
        cve_id = record["id"].lower()
        for eco, sliced_record in sliced.items():
            if eco not in writers:
                if self._is_frozen(eco, frozen_versions):
                    if skipped is not None:
                        skipped[eco] += 1
                    continue
                writers[eco] = self._open_fragment_writer(eco)
            identifier = f"{canonical_slug(eco)}/{cve_id}"
            writers[eco].write(identifier=identifier, schema=rec_schema, payload=sliced_record)

    @staticmethod
    def _is_frozen(ecosystem: str, frozen_versions: set[str] | None) -> bool:
        if not frozen_versions:
            return False
        identity = release_identity(ecosystem)
        # An ecosystem string the identity doesn't recognize names no release the
        # calendar knows, and an unknown release is live.
        return identity is not None and identity.version in frozen_versions

    def _iter_fragments(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Yield (identifier, schema, payload) for every release the caches hold.

        Everything here happens at yield time so that improvements to the
        upstream feeds and to the fixdate cache flow through to frozen fragments
        on the next run without rewriting them:

          1. Real envelopes from each fragment are yielded (with fix-date
             patching, won't-fix labelling and the negative assertions applied).
          2. For each base Ubuntu ecosystem with sibling plain-Pro (ESM)
             fragments, any (CVE, source-pkg) tuple Pro has and base does
             NOT have produces a synthesized base wont-fix envelope. This
             reconstructs the signal Canonical encodes by *omission* of the
             base entry when a CVE will only be fixed in Pro.
          3. For each base release, the VEX statements cached for its own
             archive are merged in, so what is emitted is the union of both
             feeds per (CVE, source package) rather than the OSV feed alone.
             OSV lists only what is affected, so a package the vendor has
             cleared is absent from it and a package it has not fixed is
             indistinguishable from one it never triaged.

        Releases are walked in codename order so that every fragment of one
        release — its own, its Pro sibling, its FIPS and Realtime tiers — is
        read while that release's VEX statements are loaded, and those are
        dropped before the next release loads its own.
        """
        if not os.path.isdir(self.fragments_dir):
            return

        # NB: the rejected set is not cleared here. It is filled by the write pass
        # from the whole tarball and added to by every fragment read below, and it
        # has to still hold a CVE learned from one release when a later release's
        # statements are read.
        base_paths, pro_paths, unclassified = self._group_fragments_by_base()

        # Yield unclassifiable fragments verbatim (test fixtures with empty affected[],
        # future shapes we don't recognize, etc.) — never apply inference to them.
        # Their identifiers are remembered so that a synthesized envelope can never
        # replace one of them downstream: an unpairable base fragment lands here, and
        # the synthetic pass runs last, so under INSERT OR REPLACE a stub would win.
        real_identifiers: set[str] = set()
        for path in unclassified:
            for identifier, sch, payload in self._iter_envelopes_with_fixdate(path):
                real_identifiers.add(identifier)
                yield identifier, sch, payload

        assertion_tokens = self._assertion_tokens_by_ecosystem()
        seen_pro_paths: set[str] = set()
        codename_loaded: str | None = None
        for codename, base_eco in self._release_groups(base_paths, pro_paths):
            if codename != codename_loaded:
                self._release_vex_statements()
                codename_loaded = codename

            # Pro fragments are yielded verbatim; the inference from them happens
            # during the base pass below.
            for path in pro_paths.get(base_eco, []):
                if path in seen_pro_paths:
                    continue
                seen_pro_paths.add(path)
                yield from self._iter_envelopes_with_fixdate(path)

            # An inferred or asserted base entry shares the (base_eco, cve_id) key —
            # and therefore the envelope identifier — with any real base entry for the
            # same CVE. They must be merged INTO the real envelope before it is
            # yielded; emitting a separate envelope would collide under
            # INSERT OR REPLACE and the partial one would overwrite the real data.
            yield from self._yield_base_with_inferences(
                base_eco,
                base_path=base_paths.get(base_eco),
                pro_paths=pro_paths.get(base_eco, []),
                real_identifiers=real_identifiers,
                tokens=assertion_tokens.get(base_eco, []),
                codename=codename or None,
            )
        self._release_vex_statements()

    def _release_groups(self, base_paths: dict[str, str], pro_paths: dict[str, list[str]]) -> list[tuple[str, str]]:
        """Every base ecosystem to walk, as (codename, ecosystem), ordered by release."""
        groups = []
        for eco in set(base_paths) | set(pro_paths):
            identity = release_identity(eco)
            codename = self._codename_for_release(identity.version) if identity else None
            groups.append((codename or "", eco))
        return sorted(groups)

    def _release_vex_statements(self) -> None:
        """Drop the VEX statements loaded for the release just finished."""
        if self._vex_overlay is not None:
            self._vex_overlay.release()

    def _codename_for_release(self, version: str) -> str | None:
        """The codename VEX names a release by, from the calendar's series column."""
        if self._calendar is not None:
            release = self._calendar.get(version)
            if release is not None:
                return release.series
        return _codename_for_version(version)

    def _version_for_codename(self, codename: str) -> str | None:
        """The release version a codename names, from the calendar's series column."""
        if self._calendar is not None:
            release = self._calendar.get(codename)
            if release is not None:
                return release.version
        return parser_legacy.ubuntu_version_names.get(codename)

    def _assertion_tokens_by_ecosystem(self) -> dict[str, list[str]]:
        """Which cached VEX tokens speak for which base ecosystem, in precedence order.

        Whether a token speaks for a release at all is `vex_cache.token_asserts`,
        which is the one place that rule lives. A token that may speak resolves
        through the calendar's series column to a release version and so to that
        release's base ecosystem; a codename the calendar does not know resolves
        to nothing and is silent.
        """
        by_eco: dict[str, list[str]] = defaultdict(list)
        for token in self.vex_store.fragment_paths():
            eco = self._assertion_ecosystem_for_token(token)
            if eco is not None:
                by_eco[eco].append(token)
        for tokens in by_eco.values():
            # the release's own archive first; a pocket only fills what it leaves unsaid
            tokens.sort(key=lambda token: (vex_cache.pocket_of_token(token), token))
        return by_eco

    def _assertion_ecosystem_for_token(self, token: str) -> str | None:
        if not vex_cache.token_asserts(token):
            return None
        version = self._version_for_codename(vex_cache.codename_of_token(token))
        if version is None:
            return None
        return ReleaseIdentity(channel=_BASE_CHANNEL, version=version).ecosystem

    def _yield_base_with_inferences(  # noqa: PLR0913
        self,
        base_eco: str,
        base_path: str | None,
        pro_paths: list[str],
        real_identifiers: set[str] | None = None,
        tokens: list[str] | None = None,
        codename: str | None = None,
    ) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        # Collect real envelopes by cve, keyed so inferences and assertions merge in.
        by_cve: dict[str, dict[str, Any]] = {}
        cve_order: list[str] = []

        if base_path is not None:
            for env in self._iter_envelopes_with_fixdate(base_path):
                identifier, sch, payload = env
                cve = payload.get("id", "")
                if cve not in by_cve:
                    cve_order.append(cve)
                by_cve[cve] = {
                    "identifier": identifier,
                    "schema": sch,
                    "payload": payload,
                    "had_real": True,
                }

        if pro_paths:
            self._merge_inferred_into(by_cve, cve_order, pro_paths, base_eco)

        if tokens:
            self._merge_vex_assertions(by_cve, cve_order, base_eco, tokens)

        if codename and _is_base_ecosystem(base_eco):
            self._merge_tracker_rows(by_cve, cve_order, base_eco, codename, tokens or [])
            # last, because a clearance outranks everything the others put down,
            # including the `needs-triage` row `_merge_tracker_rows` just read
            # out of the same file
            self._merge_tracker_clearances(by_cve, codename, tokens or [])

        for cve in cve_order:
            entry = by_cve[cve]
            # A wholly synthesized envelope is an inference about a base release
            # that has no readable fragment. If some other fragment already
            # emitted that identifier, the fragment is the real record and the
            # inference is a stub built on a pairing that failed; drop it rather
            # than let it replace real data.
            if not entry["had_real"] and real_identifiers is not None and entry["identifier"] in real_identifiers:
                self.logger.warning(f"not replacing {entry['identifier']} with an inferred record; its fragment could not be paired")
                continue
            yield entry["identifier"], entry["schema"], entry["payload"]

    def _merge_vex_assertions(
        self,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        base_eco: str,
        tokens: list[str],
    ) -> None:
        """Add what the release's cached VEX statements say and its OSV records do not.

        This is the half of the union the OSV feed cannot express. A package the
        vendor has cleared is absent from `affected[]`, and so is a package it
        has looked at and not fixed where no OSV record exists for the release at
        all, so enumerating the OSV entries alone drops every statement of the
        first kind and a long tail of the second.

        A clearance overrides whatever is already there — an OSV fix event, an
        OSV entry, the release's own `affected` statement, an inferred entry —
        because it is the vendor's researched answer about the package and the
        rest is either an encoding of something else or an absence of research.
        It is also the one thing a pocket may say about the base release: a
        clearance travels because the code either carries the vulnerability or
        does not, while a finding does not travel, since a pocket states what is
        true of its own rebuild. Everything else is only added where nothing has
        spoken about the package at all.
        """
        overlay = self._vex_overlay
        if overlay is None:
            return
        by_upstream = self._index_by_upstream(by_cve)
        for token in tokens:
            speaks_findings = vex_cache.token_asserts_findings(token)
            # sorted so that what a record holds does not depend on the order rows
            # happen to sit in a fragment
            for (cve, package), disposition in sorted(overlay.dispositions(token).items()):
                if disposition == NOT_PRESENT:
                    # the release does not ship the package, so there is nothing
                    # for a record to be about; the entry it contradicts is
                    # dropped where it is read rather than replaced here
                    continue
                if disposition != NOT_AFFECTED and not speaks_findings:
                    continue
                entry = by_upstream.get(cve)
                if entry is None:
                    if cve in self._rejected_cves:
                        continue
                    entry = self._add_vex_envelope(by_cve, by_upstream, cve_order, base_eco, cve)
                entries = _affected_by_package(entry)
                existing = entries.get(package)
                if existing is not None:
                    if disposition == NOT_AFFECTED:
                        _mark_not_affected(existing)
                        _stamp_vex_provenance(existing, token, disposition)
                    continue
                aff = _build_asserted_affected(package, base_eco, disposition, "vex", {"token": token, "disposition": disposition})
                entries[package] = aff
                entry["payload"].setdefault("affected", []).append(aff)

    def _merge_tracker_rows(
        self,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        base_eco: str,
        codename: str,
        tokens: list[str],
    ) -> None:
        """Fill from the frozen tracker snapshot what neither current feed states.

        Two different jobs, and the precedence between them is the whole point.

        A fix version is a historical fact and the snapshot holds thousands the
        OSV feed has stopped carrying, because Canonical drops a package from a
        release's `affected[]` when it stops tracking it there and the version
        goes with it. So a combination either feed mentions, carrying no fix
        version, takes the snapshot's `released` version. OSV's own `fixed`
        event always wins where it has one.

        A disposition from the snapshot is older news, so it is read only where
        neither feed mentions the combination at all: a `released` row becomes a
        fix, `ignored` a won't-fix finding, `not-affected` the `"0"` row, and
        every other triage state a finding with no fix. `DNE` is not indexed.
        A statement always outranks a row, including the two clearances. One of
        those states that the release does not ship the package, which leaves
        no entry behind for a row to attach to, so it has to be asked about
        rather than looked for: without that, a row saying the package was
        fixed at a version would put back the package the vendor says was never
        there.
        """
        rows = self.tracker_index.rows_for(codename)
        if not rows:
            return
        by_upstream = self._index_by_upstream(by_cve)
        patched: list[dict[str, Any]] = []
        # sorted so that what a record holds does not depend on the order rows
        # happen to sit in a fragment
        for (cve, package), row in sorted(rows.items()):
            if self._vex_says_absent(cve, package, tokens):
                continue
            entry = by_upstream.get(cve)
            if entry is None:
                if cve in self._rejected_cves:
                    continue
                entry = self._add_tracker_envelope(row, base_eco, codename, by_cve, by_upstream, cve_order)
                if entry is not None:
                    patched.append(entry)
            elif self._apply_tracker_row(entry, row, package, base_eco, codename):
                patched.append(entry)

        for entry in patched:
            self._patch_fix_dates(entry["payload"])

    def _merge_tracker_clearances(self, by_cve: dict[str, dict[str, Any]], codename: str, tokens: list[str]) -> None:
        """Apply the clearances the snapshot holds in `ignored_patches` and VEX does not state.

        The other half of the pre-OSV provider's `3032ece`: an extended-support
        pocket saying `not-affected` clears the package for the base release,
        because the base release's own row is an absence of research standing
        next to research. `clearance-outranks-everything` already decided that a
        researched clearance outranks a base-token `affected`, an OSV `fixed`
        event and a tracker row alike; this is the same rule reading the same
        conclusion out of Canonical's other file, for the combinations where
        there is no VEX statement to read it out of at all.

        It overrides and never creates. `3032ece` downgraded a row that was
        already there and invented no record, and unlike the VEX clearances —
        whose population is measured, at 395,504 — this one is not. A package
        nothing has spoken about is left alone.

        A `component_not_present` statement still wins: per
        `component-not-present-is-absence` the release does not ship the package
        at all, so there is nothing for a `"0"` row to be about.
        """
        clearances = self.tracker_index.clearances_for(codename)
        if not clearances:
            return
        by_upstream = self._index_by_upstream(by_cve)
        # sorted so that what a record holds does not depend on the order rows
        # happen to sit in a fragment
        for (cve, package), row in sorted(clearances.items()):
            entry = by_upstream.get(cve)
            if entry is None:
                continue
            existing = _affected_by_package(entry).get(package)
            if existing is None or _is_not_affected(existing):
                continue
            if self._vex_says_absent(cve, package, tokens):
                continue
            _mark_not_affected(existing)
            _stamp_tracker_provenance(existing, codename, row.pocket, row.status)

    def _vex_says_absent(self, cve: str, package: str, tokens: list[str]) -> bool:
        """Does a current statement say this release does not ship the package at all?

        Asked of the release's own archive only. A pocket saying it does not
        carry a package says nothing about what the release shipped, and reading
        it that way would silence a snapshot row for a package that is there.
        """
        overlay = self._vex_overlay
        if overlay is None:
            return False
        return any(overlay.disposition(cve, token, package) == NOT_PRESENT for token in tokens if vex_cache.token_asserts_findings(token))

    def _apply_tracker_row(
        self,
        entry: dict[str, Any],
        row: tracker_index.TrackerRow,
        package: str,
        base_eco: str,
        codename: str,
    ) -> bool:
        """Merge one snapshot row into an envelope that already exists. True if it gained a fix."""
        entries = _affected_by_package(entry)
        aff = entries.get(package)
        if aff is None:
            new_aff = self._tracker_only_affected(row, base_eco, codename)
            if new_aff is None:
                return False
            entries[package] = new_aff
            entry["payload"].setdefault("affected", []).append(new_aff)
            return True

        # the feeds have spoken about this package, so the row may still supply
        # the fix version they left out and nothing else
        if row.status != tracker_index.STATUS_RELEASED or not row.version:
            return False
        if _is_not_affected(aff) or _fixed_versions(aff):
            return False
        _add_fixed_event(aff, row.version)
        return True

    def _add_tracker_envelope(  # noqa: PLR0913
        self,
        row: tracker_index.TrackerRow,
        base_eco: str,
        codename: str,
        by_cve: dict[str, dict[str, Any]],
        by_upstream: dict[str, dict[str, Any]],
        cve_order: list[str],
    ) -> dict[str, Any] | None:
        """Start an envelope for a CVE neither feed carries for this release."""
        aff = self._tracker_only_affected(row, base_eco, codename)
        if aff is None:
            return None
        entry = self._add_vex_envelope(by_cve, by_upstream, cve_order, base_eco, row.cve)
        _affected_by_package(entry)[row.package] = aff
        entry["payload"].setdefault("affected", []).append(aff)
        return entry

    def _tracker_only_affected(self, row: tracker_index.TrackerRow, base_eco: str, codename: str) -> dict[str, Any] | None:
        """An affected[] entry for a combination only the snapshot names, or None for nothing to say."""
        provenance = {"codename": codename, "status": row.status}
        if row.status == tracker_index.STATUS_RELEASED:
            if not row.version:
                # the legacy path omits a released row with no version, and so does this
                return None
            aff = _build_asserted_affected(row.package, base_eco, NO_FIX, "tracker", provenance)
            aff["database_specific"]["anchore"].pop("status", None)
            _add_fixed_event(aff, row.version)
            return aff
        disposition = tracker_index.disposition_of_status(row.status)
        if disposition is None:
            return None
        return _build_asserted_affected(row.package, base_eco, disposition, "tracker", provenance)

    def _patch_fix_dates(self, payload: dict[str, Any]) -> None:
        """Re-run the fix-date annotation over an envelope that gained a fix version.

        A tracker-sourced version is a fix like any other and gets its date the
        same way. The annotation rewrites each range's entry wholesale, so
        running it again over an envelope that already has one changes nothing
        else.
        """
        upstream = payload.get("upstream") or []
        osv.patch_fix_date(
            payload,
            self.fixdater,
            vuln_id_override=upstream[0] if upstream else None,
            extra_candidates=usn_extra_candidates(self._usn_overlay),
        )

    @staticmethod
    def _index_by_upstream(by_cve: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """The same envelopes, keyed by the upstream CVE the VEX statements name them by."""
        out: dict[str, dict[str, Any]] = {}
        for entry in by_cve.values():
            upstream = entry["payload"].get("upstream") or []
            if upstream:
                out[upstream[0]] = entry
        return out

    def _add_vex_envelope(
        self,
        by_cve: dict[str, dict[str, Any]],
        by_upstream: dict[str, dict[str, Any]],
        cve_order: list[str],
        base_eco: str,
        cve: str,
    ) -> dict[str, Any]:
        """Start an envelope for a CVE the release's OSV fragment does not carry.

        Canonical's OSV id for a CVE is the CVE id with `UBUNTU-` in front, so
        the identifier and the upstream alias are both derivable and a record
        this builds lands on the same identifier as a real one would if the feed
        starts carrying it tomorrow.
        """
        osv_id = f"{_OSV_ID_PREFIX}{cve}"
        entry = {
            "identifier": f"{canonical_slug(base_eco)}/{osv_id.lower()}",
            "schema": schema.OSVSchema(),
            "payload": {
                "schema_version": schema.OSV_SCHEMA_VERSION,
                "id": osv_id,
                "upstream": [cve],
                "affected": [],
            },
            "had_real": False,
            "packages": {},
        }
        by_cve[osv_id] = entry
        by_upstream[cve] = entry
        cve_order.append(osv_id)
        return entry

    def _merge_inferred_into(
        self,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        pro_paths: list[str],
        base_eco: str,
    ) -> None:
        """Walk sibling Pro fragments. For each Pro envelope, append synthesized
        base entries to the real envelope (if one exists) or create a new
        envelope. Records the inference provenance.
        """
        for pro_path in pro_paths:
            with result.SQLiteReader(pro_path) as reader:
                for envelope in reader.each():
                    self._merge_pro_envelope(envelope, by_cve, cve_order, base_eco)

    def _merge_pro_envelope(
        self,
        envelope: result.Envelope,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        base_eco: str,
    ) -> None:
        payload = envelope.item
        cve = payload.get("id", "")
        if not cve:
            return
        # `_add_synthetic_envelope` copies `details` verbatim onto the base entry
        # it synthesizes, so a rejected Pro record would otherwise produce a
        # rejected base record on a path that never sees the OSV-native check.
        if is_cve_program_rejection(payload):
            self._record_rejection(payload)
            return
        pro_affs = payload.get("affected", [])
        pro_eco = pro_affs[0].get("package", {}).get("ecosystem") if pro_affs else None
        target = by_cve.get(cve)
        existing_pkgs = _affected_package_names(target["payload"]) if target else set()
        new_affs = _synthesize_missing(pro_affs, existing_pkgs, base_eco, pro_eco)
        new_affs = self._replace_not_affected_inferences(new_affs, payload, base_eco)
        if not new_affs:
            return
        if target is None:
            self._add_synthetic_envelope(by_cve, cve_order, envelope, new_affs, base_eco)
        else:
            target["payload"].setdefault("affected", []).extend(new_affs)

    def _replace_not_affected_inferences(
        self,
        new_affs: list[dict[str, Any]],
        payload: dict[str, Any],
        base_eco: str,
    ) -> list[dict[str, Any]]:
        """Restate inferred base entries Canonical says are not vulnerable.

        The inference reads an omission: Pro carries the package, base does not,
        so base is presumed vulnerable. A `not_affected` statement is a positive
        claim about that package in that release, and it wins — where VEX can
        speak to an inferred entry at all it agrees with the inference about
        98.5% of the time, so deferring on the rest is consistent rather than a
        reversal.

        The entry is restated rather than dropped where the vendor concluded the
        vulnerable code is not there. Dropping it leaves the base record saying
        nothing about a package the vendor has explicitly cleared, which is the
        same thing it says about a package nobody has looked at. Where the vendor
        says the release does not ship the package at all, the inference was
        simply wrong and the entry goes.

        This has to be an explicit lookup. A synthesized entry deliberately
        carries no `purl`, since the Pro one names a Pro pocket, and the join key
        is derived from a purl — so a pass written the natural way cannot reach
        these entries and would appear to work while doing nothing.
        """
        overlay = self._vex_overlay
        if overlay is None or not new_affs:
            return new_affs
        upstream = payload.get("upstream") or []
        if not upstream:
            return new_affs
        identity = release_identity(base_eco)
        codename = self._codename_for_release(identity.version) if identity else None
        if codename is None:
            return new_affs
        kept = []
        for aff in new_affs:
            name = (aff.get("package") or {}).get("name", "")
            disposition = overlay.disposition(upstream[0], codename, name) if name else None
            if disposition == NOT_AFFECTED:
                _mark_not_affected(aff)
            elif disposition == NOT_PRESENT:
                # base does not ship the package at all, so the inference read the
                # omission it was built on backwards
                continue
            kept.append(aff)
        return kept

    def _add_synthetic_envelope(
        self,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        envelope: result.Envelope,
        new_affs: list[dict[str, Any]],
        base_eco: str,
    ) -> None:
        template = envelope.item
        cve = template["id"]
        synth_payload: dict[str, Any] = {k: v for k, v in template.items() if k != "affected"}
        synth_payload["affected"] = new_affs
        upstream = synth_payload.get("upstream") or []
        osv.patch_fix_date(
            synth_payload,
            self.fixdater,
            vuln_id_override=upstream[0] if upstream else None,
            extra_candidates=usn_extra_candidates(self._usn_overlay),
        )
        by_cve[cve] = {
            "identifier": f"{canonical_slug(base_eco)}/{cve.lower()}",
            "schema": _schema_from_envelope_url(envelope.schema),
            "payload": synth_payload,
            "had_real": False,
        }
        cve_order.append(cve)

    def _iter_envelopes_with_fixdate(
        self,
        fragment_path: str,
    ) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Read a fragment file, apply yield-time fix-date patching, yield envelopes."""
        extra_candidates = usn_extra_candidates(self._usn_overlay)
        with result.SQLiteReader(fragment_path) as reader:
            for envelope in reader.each():
                payload = envelope.item
                # patch_fix_date keys the lookup by vuln_id. The OSV record's `id` is
                # the Canonical-internal `UBUNTU-CVE-*`; the fix-date cache keys by the
                # upstream `CVE-*`. Pass the upstream override so the lookup hits.
                upstream = payload.get("upstream") or []
                osv.patch_fix_date(
                    payload,
                    self.fixdater,
                    vuln_id_override=upstream[0] if upstream else None,
                    extra_candidates=extra_candidates,
                )
                if is_cve_program_rejection(payload):
                    self._record_rejection(payload)
                    continue
                if not self._apply_vex(payload):
                    continue
                yield (
                    envelope.identifier,
                    _schema_from_envelope_url(envelope.schema),
                    payload,
                )

    def _apply_vex(self, payload: dict[str, Any]) -> bool:
        """Apply the cached VEX statements to one envelope on the way out.

        Returns False when nothing is left to emit for it.

        Both judgements happen here rather than at write time. A fragment frozen
        at end of life can never be written again, so a disposition baked into
        it is fixed forever with no upstream left to refill from; read at yield
        against the VEX fragments, which freeze alongside, both stay revisable.
        Labelling only ever adds a label, so one an earlier build baked into a
        fragment is preserved.
        """
        if self._vex_overlay is None:
            return True
        _annotate_wont_fix({payload.get("id", ""): payload}, payload, self._vex_overlay)
        return self._apply_not_affected(payload)

    def _apply_not_affected(self, payload: dict[str, Any]) -> bool:
        """Act on what Canonical says is not vulnerable. Returns False if nothing is left to emit.

        This is the one judgement OSV cannot express: its `affected[]` lists what
        is affected, and a package Canonical has cleared is simply absent, which
        is indistinguishable from one nobody has looked at.

        What replaces the entry depends on why it was cleared. A conclusion that
        the vulnerable code is not in the package is worth stating, so on a
        release's own archive the entry is restated as a `FixedIn` version of
        `"0"` and the consumer can cancel what another source reports for that
        package. A statement that the release does not ship the package at all is
        the tracker's `DNE`, which the provider has never emitted anything for,
        so the entry simply goes.

        On an extended-support pocket a cleared entry always goes, because that
        channel carries fix versions only and has no way to state a clearance:
        the disclosure and the clearance both belong to the base release.

        `under_investigation` is not touched here and must never be. It means
        "not yet determined", which this provider has emitted as
        vulnerable-with-no-fix since long before the OSV feed, and treating it
        as a clearance would drop tens of thousands of real findings.
        """
        overlay = self._vex_overlay
        if overlay is None:
            return True
        upstream = payload.get("upstream") or []
        if not upstream:
            return True
        cve_id = upstream[0]
        affected = payload.get("affected") or []
        kept = []
        for aff in affected:
            package = aff.get("package") or {}
            purl = package.get("purl") or ""
            token = distro_label_from_purl(purl)
            pkg = source_package_from_purl(purl)
            disposition = overlay.disposition(cve_id, token, pkg) if token and pkg else None
            if disposition not in CLEARANCES:
                kept.append(aff)
                continue
            if disposition == NOT_AFFECTED and _is_base_ecosystem(package.get("ecosystem") or ""):
                _mark_not_affected(aff)
                kept.append(aff)
        if len(kept) == len(affected):
            return True
        payload["affected"] = kept
        return bool(kept)

    def _record_rejection(self, payload: dict[str, Any]) -> None:
        """Remember a CVE the CVE program has rejected, so no later pass reinstates it.

        The VEX statements carry no `details` and so cannot be asked whether a
        CVE was rejected. Without this, a rejected record dropped while reading
        one release's fragment would be built again from that release's
        statements, which is the class of knowingly-false finding the rejection
        check exists to keep out.

        The set is per run and never per release. A rejection is a fact about
        the CVE, and the record stating it names only the releases the vendor
        was still publishing for at the time, so a release it does not name has
        to inherit the fact from wherever it was seen. The write pass reads it
        off the whole tarball; this is also called for every fragment envelope,
        which is what answers the question on a run whose download failed.
        """
        upstream = payload.get("upstream") or []
        if upstream:
            self._rejected_cves.add(upstream[0])

    def _group_fragments_by_base(self) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
        """Index fragments by their ecosystem.

        Returns (base_paths, pro_paths, unclassified_paths):
          - base_paths[base_eco]      → path to that base ecosystem's fragment, if present
          - pro_paths[base_eco]       → paths to plain-Pro sibling fragments of base_eco
          - unclassified_paths        → paths whose ecosystem couldn't be read (e.g. a
                                         hand-crafted test fragment or a future shape we
                                         don't recognize); yielded verbatim, no inference.

        Sub-tier fragments (FIPS / Realtime / Nvidia-BlueField) end up in base_paths
        keyed by their own ecosystem — they're yielded verbatim, with no inference
        applied (pro_to_base_ecosystem returns None for them).

        Fragment ecosystem is read from the first envelope's
        `affected[0].package.ecosystem` to avoid reverse-engineering the
        slug; every envelope in a fragment names the same release by the
        slicing invariant, though not necessarily under the same spelling, so
        both sides of the base/Pro comparison are canonicalised. Comparing raw
        strings here would unpair a base fragment whose peeked envelope
        happened to carry the pre-GA spelling, and an unpaired base is the
        destructive case: see `_yield_base_with_inferences`.
        """
        base_paths: dict[str, str] = {}
        pro_paths: dict[str, list[str]] = {}
        unclassified: list[str] = []
        for filename in sorted(os.listdir(self.fragments_dir)):
            if not filename.endswith(".db"):
                continue
            path = os.path.join(self.fragments_dir, filename)
            raw_eco = self._ecosystem_of_fragment(path)
            if raw_eco is None:
                unclassified.append(path)
                continue
            eco = canonical_ecosystem(raw_eco)
            base = pro_to_base_ecosystem(eco)
            if base is None:
                self._record_base_fragment(base_paths, eco, path)
            else:
                pro_paths.setdefault(canonical_ecosystem(base), []).append(path)
        return base_paths, pro_paths, unclassified

    def _record_base_fragment(self, base_paths: dict[str, str], eco: str, path: str) -> None:
        """Claim `path` as the fragment for `eco`, preferring the canonically named file.

        Two files can name one release only until the next `_clean_input`,
        which retires the non-canonical spelling. Until then, read the one
        whose name matches the identity so the run doesn't depend on
        directory order.
        """
        existing = base_paths.get(eco)
        if existing is None:
            base_paths[eco] = path
            return
        canonical_name = f"{canonical_slug(eco)}.db"
        keep = path if os.path.basename(path) == canonical_name else existing
        drop = existing if keep is path else path
        self.logger.warning(f"two fragments name {eco}: reading {os.path.basename(keep)}, ignoring {os.path.basename(drop)}")
        base_paths[eco] = keep

    @staticmethod
    def _ecosystem_of_fragment(path: str) -> str | None:
        """Peek the ecosystem string from a fragment by reading one envelope."""
        try:
            with result.SQLiteReader(path) as reader:
                for envelope in reader.each():
                    for aff in envelope.item.get("affected", []):
                        eco = aff.get("package", {}).get("ecosystem")
                        if eco:
                            return eco
                    return None
        except Exception:
            return None
        return None

    def _osv_covers_legacy_namespace(self, ns: str) -> bool:
        """Return True if today's OSV feed covers a legacy namespace `ubuntu:X.YY`.

        Used to filter normalized-cve-data passthrough down to the at-cutover
        EOL set — we never want to emit legacy records for a release that
        OSV (or a frozen fragment for that release) already covers.

        Checks the base release's own fragment only. A release has one fragment
        under one canonical name, so this is one lookup rather than a guess at
        which spelling was used. Pro/FIPS variants persisting after the base
        ecosystem drops is fine — they emit their own fragments, base release
        falls through to legacy.
        """
        identity = ReleaseIdentity(channel="Ubuntu", version=ns.split(":")[-1])
        return os.path.exists(os.path.join(self.fragments_dir, f"{identity.slug}.db"))

    def _iter_normalized_cve_data(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Read input/normalized-cve-data/ via the vendored v3 map_parsed.

        Emits OS-schema envelopes for at-cutover EOL releases only — namespaces
        whose base ecosystem is in today's OSV feed (or a frozen fragment) are
        skipped. The filter is applied BEFORE map_parsed so fixdater isn't
        queried for releases we'd discard anyway.
        """
        if not os.path.isdir(self.normalized_cve_dir):
            return

        os_schema = schema.OSSchema()
        for filename in sorted(os.listdir(self.normalized_cve_dir)):
            if not _CVE_FILENAME_RE.match(filename):
                continue
            full = os.path.join(self.normalized_cve_dir, filename)
            try:
                with open(full, "rb") as f:
                    cve_file = parser_legacy.CVEFile.from_dict(orjson.loads(f.read()))
            except Exception:
                self.logger.exception(f"failed to load normalized cve {full}")
                continue

            # Drop patches for releases OSV already covers. map_parsed would
            # otherwise call fixdater.best() per released patch — wasted work
            # for jammy/noble/etc. that we'd filter out post-mapping.
            cve_file.patches = [
                p for p in cve_file.patches if (ns := parser_legacy.map_namespace(p.distro)) is not None and not self._osv_covers_legacy_namespace(ns)
            ]
            if not cve_file.patches:
                continue

            vulns = parser_legacy.map_parsed(cve_file, self.fixdater, self.logger)
            for vuln in vulns:
                if not vuln.NamespaceName or not vuln.Name:
                    continue
                identifier = f"{vuln.NamespaceName}/{vuln.Name.lower()}"
                yield identifier, os_schema, {"Vulnerability": vuln.json()}

    def _clean_input(self):
        # The ubuntu-cve-tracker repo is no longer used and is huge, so delete if it exists
        # to significantly reduce cache.
        cve_tracker_path = os.path.join(self.workspace.input_path, "ubuntu-cve-tracker")
        if os.path.exists(cve_tracker_path):
            silent_remove(cve_tracker_path, tree=True)
        self._retire_husk_fragments()

    def _retire_husk_fragments(self) -> None:
        """Remove fragments written from a post-sweep husk, and rename residue.

        Runs before anything is downloaded and before any writer opens. Nothing
        here is a heuristic: the releases are named in `_KNOWN_HUSK_RELEASES`,
        and the second rule only removes a file that a canonically named file
        already supersedes. Idempotent — a workspace with nothing to retire logs
        nothing and does nothing.

        Once a release's fragment is gone and the freeze rule keeps it from
        being written again, `_osv_covers_legacy_namespace` stops finding it and
        `_iter_normalized_cve_data` serves the release from the tracker cache on
        the same run.
        """
        if not os.path.isdir(self.fragments_dir):
            return

        identities: dict[str, ReleaseIdentity | None] = {}
        for filename in sorted(os.listdir(self.fragments_dir)):
            if filename.endswith(".db"):
                identities[filename] = self._identity_of_fragment(os.path.join(self.fragments_dir, filename))

        canonical_names = {i.slug + ".db" for i in identities.values() if i is not None}
        for filename, identity in identities.items():
            if identity is None:
                continue
            if identity.version in _KNOWN_HUSK_RELEASES:
                self._retire_fragment(filename, f"{identity.version} is served from the tracker cache")
            elif filename != identity.slug + ".db" and identity.slug + ".db" in canonical_names:
                self._retire_fragment(filename, f"superseded by {identity.slug}.db")

    def _identity_of_fragment(self, path: str) -> ReleaseIdentity | None:
        """The release a fragment holds, read from its contents, or from its name.

        The contents are authoritative: a release published under two spellings
        has fragments whose names disagree about which release they hold. The
        file name is the fallback for a fragment too damaged to read, which is
        exactly the shape a husk can arrive in.
        """
        ecosystem = self._ecosystem_of_fragment(path)
        if ecosystem is not None:
            return release_identity(ecosystem)
        m = _BASE_FRAGMENT_NAME_RE.match(os.path.basename(path))
        return ReleaseIdentity(channel="Ubuntu", version=m.group(1)) if m else None

    def _retire_fragment(self, filename: str, reason: str) -> None:
        path = os.path.join(self.fragments_dir, filename)
        self.logger.info(f"retiring fragment {filename}: {reason}")
        silent_remove(path)
        # TODO: lift this to a module-level helper in vunnel.result. Editing result.py is a
        # quality-gate trigger for every provider (tests/quality/configure.py gate_globs), so
        # reach through to the method instead of paying for a full-matrix run on a one-liner.
        # The method ignores self, hence the None receiver.
        result.SQLiteStore._remove_wal_sidecar_files(None, path)  # type: ignore[arg-type]  # noqa: SLF001

    def get(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        self._clean_input()
        self._download_archive()
        self._download_vex_archive()
        # The calendar is fetched before anything is written and fails the run if
        # it cannot be obtained at all, so no fragment is ever written without it.
        calendar = self._load_calendar()
        now = datetime.datetime.now(datetime.UTC)
        self.fixdater.download()
        self._usn_overlay = self._load_usn_overlay()
        self._write_fragments(calendar=calendar, now=now)
        self.vex_store.write(self.vex_archive_path, calendar=calendar, now=now, husk_releases=_KNOWN_HUSK_RELEASES)
        self._calendar = calendar
        self._vex_overlay = self._load_vex_overlay()
        # The snapshot never changes, so this is a one-time cost on the run that
        # first needs it and nothing on every run after.
        self.tracker_index.build(self.normalized_cve_dir)
        # legacy first; OSV last (policy-only — identifier shapes don't collide)
        yield from self._iter_normalized_cve_data()
        if self.downconvert_osv_to_os:
            yield from self._iter_fragments_downconverted()
        else:
            yield from self._iter_fragments()

    def _iter_fragments_downconverted(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Yield OSV fragment envelopes rewritten into v3 OS-schema records.

        Plain Pro (ESM) slices become `ubuntu:X.YY+esm` channel records (gated by
        `downconvert_emit_esm`); FIPS/Realtime/BlueField slices and any envelope
        without an upstream CVE alias are dropped — v3 never emitted them. Pro-only-fix
        wont-fix data still appears here because `_yield_base_with_inferences` already
        merged it into the base ecosystem's affected[] list before this runs.
        """
        os_schema = schema.OSSchema()
        for _osv_identifier, _osv_schema, osv_payload in self._iter_fragments():
            os_payload = osv_to_os(osv_payload, include_esm=self.downconvert_emit_esm)
            if os_payload is None:
                continue
            yield os_identifier_for(os_payload), os_schema, os_payload

    def _load_usn_overlay(self) -> USNFixDateOverlay | None:
        """Build the (eco, src-pkg, fixed-ver) → USN-published-date index.

        Streams `osv/usn/**` out of the downloaded OSV tarball. If the archive
        is missing or unreadable, log and proceed without an overlay — fix-date
        annotations fall back to first-observed + CVE.published, same as before
        the USN overlay was added. No regression on miss.
        """
        if not os.path.isfile(self.archive_path):
            self.logger.warning(
                f"OSV archive missing at {self.archive_path}; USN fix-date overlay unavailable, fix dates will fall back to first-observed",
            )
            return None
        try:
            return USNFixDateOverlay.from_archive(self.archive_path, logger=self.logger)
        except Exception:
            self.logger.exception("failed to build USN fix-date overlay; falling back to first-observed")
            return None

    def _load_vex_overlay(self) -> VEXOverlay | None:
        """Build the read-side VEX index from the cached statements.

        Read from the fragments rather than from today's download, so a frozen
        release is still answered for after Canonical drops it from the feed. A
        workspace with no VEX fragments yields no index, which means no
        suppression and no labelling from VEX on this run — a fragment written
        by an earlier build still carries whatever label was baked into it.
        """
        try:
            return VEXOverlay(self.vex_store.fragment_paths(), self.vex_store.statements_at, logger=self.logger)
        except Exception:
            self.logger.exception("failed to read the VEX cache; won't-fix and not-affected data will be absent on this run")
            return None
