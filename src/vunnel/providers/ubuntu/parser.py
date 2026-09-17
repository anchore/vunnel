from __future__ import annotations

import logging
import os
import re
import tarfile
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import schema
from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import silent_remove

from . import cve_rows, parser_legacy, tracker, vex_cache
from .os_downconvert import (
    PackageState,
    fixed_in_for,
    is_cve_program_rejection,
    is_esm_namespace,
    os_identifier_for,
    os_record,
    osv_ecosystem_to_os_namespace,
    severity_of,
)
from .usn_fixdate_overlay import USNFixDateOverlay, usn_extra_candidates
from .vex_overlay import (
    NOT_AFFECTED,
    NOT_PRESENT,
    WONT_FIX,
    canonical_token,
    distro_label_from_purl,
    source_package_from_purl,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from vunnel.workspace import Workspace


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
# get no identity and name no release.
_ECOSYSTEM_RE = re.compile(r"^(?P<channel>Ubuntu(?::[A-Za-z][^:]*)*):(?P<version>\d+\.\d+)(?::LTS)?$")

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

    This decides the spelling of a release's identity and nothing else.
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
    identities, including the ones that map to no output namespace at all
    (FIPS, Realtime, BlueField): they are separate builds, not spellings of one
    thing.

    `version` is the base release the channel derives from, which is what the
    known-husk list is keyed on.
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


# Releases whose records in today's feed are Canonical's post-sweep residue: a
# husk of never-regenerated withdrawn records that still names the release.
# Nothing separates that residue from a healthy release's records except knowing
# which releases were swept, so the two are named here and served from the
# frozen tracker snapshot in `input/normalized-cve-data/` instead. The list is a
# fact, not a heuristic, and Canonical hosts every release from questing on
# indefinitely, so the set is closed unless that changes.
_KNOWN_HUSK_RELEASES = frozenset(
    {
        # oracular, swept 2025-07-11. The feed carries 157 records for it, 153 of
        # them withdrawn.
        "24.10",
        # plucky, swept 2026-01-20. Same shape: 184 records, 181 withdrawn. The
        # tracker snapshot is a good substitute — compared against the last
        # plucky-intact upstream commit over 115,253 (CVE, source package) pairs
        # it agrees on 99.8% of verdicts, 99.4% of the 36,791 actionable ones,
        # and on 8,966 of 8,966 fix versions byte for byte.
        "25.04",
    },
)


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
# carries. VEX and the tracker snapshot name a release by codename and OSV by
# version.
_CODENAMES_BY_VERSION = {version: codename for codename, version in parser_legacy.ubuntu_version_names.items()}


def _codename_for_version(version: str) -> str | None:
    return _CODENAMES_BY_VERSION.get(version)


class Parser:
    _osv_url_ = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
    _vex_url_ = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
    _archive_filename_ = "osv-all.tar.xz"
    _vex_archive_filename_ = "vex-all.tar.xz"
    _osv_rows_filename_ = "osv-rows.tsv"
    _vex_rows_filename_ = "vex-rows.tsv"
    _normalized_subdir_ = "normalized-cve-data"

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        downconvert_osv_to_os: bool = True,
        downconvert_emit_esm: bool = True,
    ):
        self.workspace = workspace
        self.fixdater = fixdater if fixdater is not None else fixdate.default_finder(workspace)
        self.download_timeout = download_timeout
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        # Accepted so an existing config still loads, and read nowhere else. Every
        # record this provider emits is now the v3 OS shape: the emit path assembles
        # a release's disposition from three sources, two of which can speak about a
        # package the OSV record does not carry, so there is no per-release OSV
        # envelope left to hand out instead.
        if not downconvert_osv_to_os:
            self.logger.warning(
                "downconvert_osv_to_os is set false; the OSV-native emit path no longer exists and every record is emitted in the OS schema",
            )
        # Emit `ubuntu:X.YY+esm` channel records for plain Pro (ESM). Default on;
        # the frozen-v5 lane sets this off to take base records only.
        self.downconvert_emit_esm = downconvert_emit_esm

        self.archive_path = os.path.join(workspace.input_path, self._archive_filename_)
        self.vex_archive_path = os.path.join(workspace.input_path, self._vex_archive_filename_)
        self.normalized_cve_dir = os.path.join(workspace.input_path, self._normalized_subdir_)
        self.urls = [self._osv_url_, self._vex_url_]

        # One compact row per CVE per feed, written as the archive streams past and
        # read back by offset during the merge.
        self._osv_rows = cve_rows.RowStore(os.path.join(workspace.input_path, self._osv_rows_filename_))
        self._vex_rows = cve_rows.RowStore(os.path.join(workspace.input_path, self._vex_rows_filename_))

        # Filled by the OSV pass. `_served_versions` is which base releases today's
        # feed speaks for, which is what decides whether the tracker snapshot has to
        # serve a release instead; `_base_ecosystems` is which base namespaces the
        # merge assembles, which also includes a release the feed carries only an
        # extended-support build of, since the Pro-to-base inference still speaks
        # for it.
        self._served_versions: set[str] = set()
        self._base_ecosystems: set[str] = set()
        # USN fix-date overlay, built in the same pass that reads the CVE records.
        self._usn_overlay: USNFixDateOverlay | None = None

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

    # ------------------------------------------------------------------
    # download
    # ------------------------------------------------------------------

    def _download_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._osv_url_, self.archive_path)

    def _download_vex_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._vex_url_, self.vex_archive_path)

    def _stream_to_disk(self, url: str, path: str) -> None:
        self.logger.info(f"downloading {url}")
        http.download_to_file(url, path, self.logger, timeout=self.download_timeout)

    # ------------------------------------------------------------------
    # the two distil passes
    # ------------------------------------------------------------------

    def _read_osv_archive(self) -> None:
        """Stream the OSV tarball once: write the CVE rows and build the USN overlay.

        Two things are read out of a record rather than written. Whether the CVE
        program rejected it, which is a fact about the CVE and not about any
        release the record happens to name — every record in the day's tarball is
        checked, because upstream never deletes a rejected record and a release
        the record does not name has to inherit the fact from wherever it was
        seen. And which releases the feed speaks for at all, which is what
        decides whether the frozen snapshot serves a release instead.

        Every release the archive names is read, whatever its support status.
        There is no calendar, no clock and no `now` anywhere in this pass. The
        one exception is `_KNOWN_HUSK_RELEASES`, whose records are residue from a
        sweep rather than the release's data, and which are dropped here.
        """
        self._served_versions = set()
        self._base_ecosystems = set()
        self._usn_overlay = None

        if not os.path.isfile(self.archive_path):
            self.logger.warning(
                f"OSV archive missing at {self.archive_path}; no release is served from the feeds on this run "
                "and fix dates fall back to first-observed",
            )
            return

        overlay = USNFixDateOverlay(logger=self.logger)
        records = 0
        with self._osv_rows as rows, tarfile.open(self.archive_path, mode="r:xz") as tar:
            for name, raw in cve_rows.iter_tar_members(tar, "osv/"):
                record = self._parse_json(name, raw)
                if record is None:
                    continue
                if name.startswith("osv/usn/"):
                    overlay.ingest_record(record)
                    continue
                if not name.startswith("osv/cve/"):
                    # `osv/lsn/**` is Canonical's livepatch stream; it names no
                    # source package this provider can emit against
                    continue
                row = cve_rows.distil_osv(record, is_cve_program_rejection(record))
                if row is None:
                    continue
                rows.write(row.cve, row.to_payload())
                self._note_releases(row)
                records += 1
        self._usn_overlay = overlay
        self.logger.info(f"read {records} OSV records over {len(self._base_ecosystems)} releases; USN fix dates: {len(overlay)}")

    def _note_releases(self, row: cve_rows.OsvRow) -> None:
        """Remember which releases this record speaks for.

        A release is served from the feeds when its own archive appears in them.
        A release the feed carries only an extended-support build of is not: the
        Pro-to-base inference still puts records in its base namespace, but the
        base release's own data is gone and the snapshot is what holds it.
        """
        for entry in row.entries:
            identity = release_identity(entry.ecosystem)
            if identity is None or identity.version in _KNOWN_HUSK_RELEASES:
                continue
            if identity.channel == _BASE_CHANNEL:
                self._served_versions.add(identity.version)
                self._base_ecosystems.add(identity.ecosystem)
                continue
            base = pro_to_base_ecosystem(identity.ecosystem)
            if base is not None:
                self._base_ecosystems.add(base)

    def _read_vex_archive(self) -> None:
        """Stream the VEX tarball once, writing one row per CVE.

        A missing archive leaves no rows, which means no clearance and no
        won't-fix label from VEX on this run. The OSV rows and the snapshot still
        produce records, so a failed VEX download degrades rather than empties
        the output.
        """
        if not os.path.isfile(self.vex_archive_path):
            self.logger.warning(f"VEX archive missing at {self.vex_archive_path}; no statement is read on this run")
            return

        with self._vex_rows as rows, tarfile.open(self.vex_archive_path, mode="r:xz") as tar:
            for name, raw in cve_rows.iter_tar_members(tar, "vex/cve/"):
                document = self._parse_json(name, raw)
                if document is None:
                    continue
                distilled = vex_cache.distil_row(document)
                if distilled is None:
                    continue
                cve, row = distilled
                rows.write(cve, row)
        self.logger.info(f"read VEX statements for {len(self._vex_rows)} CVEs")

    def _parse_json(self, name: str, raw: bytes) -> dict[str, Any] | None:
        try:
            return orjson.loads(raw)  # type: ignore[no-any-return]
        except orjson.JSONDecodeError:
            self.logger.warning(f"failed to parse {name}")
            return None

    # ------------------------------------------------------------------
    # the merge
    # ------------------------------------------------------------------

    def _iter_merged(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Walk every CVE any source names and emit one record per namespace it speaks for.

        The walk is by CVE because every source is keyed by CVE and assembling
        one release's answer means seeing all three at once: the OSV record for
        the fix versions, the VEX statements for what is and is not affected, and
        the frozen snapshot for what neither current feed states. A release-major
        walk has to hold one release's worth of every source to do the same job.

        The three key sets are unioned rather than driven off OSV, because a
        CVE with no OSV record is real in both directions: the statements alone
        account for over a hundred thousand findings on the extended-support
        releases, and the snapshot carries CVEs the feed never published.
        """
        os_schema = schema.OSSchema()
        snapshot = tracker.snapshot_keys(self.normalized_cve_dir)
        for cve in sorted(self._osv_rows.keys() | self._vex_rows.keys() | snapshot):
            osv_payload = self._osv_rows.get(cve)
            osv_row = cve_rows.OsvRow.from_payload(osv_payload) if osv_payload is not None else None
            if osv_row is not None and osv_row.rejected:
                # a knowingly false finding on every release, including the ones
                # the record does not name
                continue
            vex_payload = self._vex_rows.get(cve)
            statements = vex_cache.dispositions_by_token(vex_payload) if vex_payload is not None else {}
            cve_file = tracker.load(self.normalized_cve_dir, cve, self.logger) if cve in snapshot else None
            for payload in self._records_for_cve(cve, osv_row, statements, cve_file):
                yield os_identifier_for(payload), os_schema, payload

    def _records_for_cve(
        self,
        cve: str,
        osv_row: cve_rows.OsvRow | None,
        statements: dict[str, dict[str, str]],
        cve_file: parser_legacy.CVEFile | None,
    ) -> Iterator[dict[str, Any]]:
        entries = self._entries_by_release(osv_row)
        severity = severity_of(osv_row.severity) if osv_row is not None else severity_of(None)
        # both of these are read once per release below and cost a walk of the
        # whole snapshot file each time they are asked for, which over thirty
        # releases and a hundred thousand CVEs is the difference between a walk
        # and a scan
        rows = self._rows_by_codename(cve_file)
        clearances = self._clearances_by_codename(cve_file)
        statements_by_codename = self._statements_by_codename(statements)

        for base_eco in sorted(self._base_ecosystems):
            states, from_osv = self._merge_release(base_eco, entries, statements, statements_by_codename, rows, clearances)
            if not states:
                continue
            namespace = osv_ecosystem_to_os_namespace(base_eco)
            if namespace is None:
                continue
            # A record the OSV feed does not speak for takes neither the severity
            # nor the published date of the record it does publish for other
            # releases. Both are properties of the CVE rather than of a release,
            # so this is a place the per-CVE walk could improve on what the
            # release-major one could see — it has the record in hand where the
            # release-major walk did not — and it deliberately does not, because
            # widening it is a change to what is emitted rather than to how it is
            # assembled. `Unknown` is what an untriaged record has always emitted.
            published = osv_row.published if (osv_row is not None and from_osv) else None
            self._resolve_fix_dates(cve, published, states)
            fixed_in = [entry for state in states.values() for entry in fixed_in_for(state, namespace)]
            if fixed_in:
                yield os_record(cve, namespace, severity if from_osv else severity_of(None), fixed_in)

        yield from self._channel_records(cve, osv_row, entries, statements, severity)

    def _entries_by_release(self, osv_row: cve_rows.OsvRow | None) -> dict[str, list[cve_rows.OsvEntry]]:
        """The record's entries grouped by the release each names, canonically.

        Grouping is by canonical identity and not by the literal ecosystem
        string, so a record naming a release both with and without the `:LTS`
        suffix is one release here. The entries keep whatever spelling upstream
        gave them; only the key is canonical.
        """
        out: dict[str, list[cve_rows.OsvEntry]] = defaultdict(list)
        if osv_row is None:
            return out
        for entry in osv_row.entries:
            out[canonical_ecosystem(entry.ecosystem)].append(entry)
        return out

    @staticmethod
    def _rows_by_codename(cve_file: parser_legacy.CVEFile | None) -> dict[str, dict[str, parser_legacy.Patch]]:
        """The snapshot's own rows for every release it names, by codename then package.

        `patches` holds one row per release under its bare codename. A `DNE` row
        is the release saying it never shipped the package, so there is nothing
        for a record to be about and it is dropped here rather than carried and
        skipped per release.
        """
        out: dict[str, dict[str, parser_legacy.Patch]] = defaultdict(dict)
        if cve_file is None:
            return out
        for patch in cve_file.patches:
            if not patch.package or not patch.distro or not patch.status or patch.status == tracker.STATUS_DNE:
                continue
            out[patch.distro][patch.package] = patch
        return out

    def _clearances_by_codename(self, cve_file: parser_legacy.CVEFile | None) -> dict[str, set[str]]:
        """The snapshot's extended-support clearances, by codename."""
        out: dict[str, set[str]] = defaultdict(set)
        if cve_file is None:
            return out
        for codename, package in self._tracker_esm_clearances(cve_file):
            out[codename].add(package)
        return out

    @staticmethod
    def _statements_by_codename(statements: dict[str, dict[str, str]]) -> dict[str, list[str]]:
        """Which tokens may speak for which release, in precedence order.

        The release's own archive first, so that a pocket only fills what it
        leaves unsaid. A token whose pocket may say nothing about a base
        namespace, or whose codename the version table does not know, resolves
        to no release and is silent.
        """
        out: dict[str, list[str]] = defaultdict(list)
        for token in statements:
            if vex_cache.token_asserts(token):
                out[vex_cache.codename_of_token(token)].append(token)
        for tokens in out.values():
            tokens.sort(key=lambda token: (vex_cache.pocket_of_token(token), token))
        return out

    def _merge_release(  # noqa: PLR0913
        self,
        base_eco: str,
        entries: dict[str, list[cve_rows.OsvEntry]],
        statements: dict[str, dict[str, str]],
        statements_by_codename: dict[str, list[str]],
        rows: dict[str, dict[str, parser_legacy.Patch]],
        clearances: dict[str, set[str]],
    ) -> tuple[dict[str, PackageState], bool]:
        """What one base release says about one CVE, by source package.

        Six things can decide a package, and the order they are applied in is
        the precedence between them:

          1. the release's own OSV entries, which carry the fix versions
          2. the Pro-to-base inference, for a package only the extended-support
             build names — Canonical encodes "this will only be fixed on Pro" by
             omitting the base entry
          3. the VEX statements at any token of the release. A clearance travels
             from an extended-support pocket to the base release and outranks
             everything, including an OSV fix event, because it is the vendor's
             researched answer about the package and the rest is either an
             encoding of something else or an absence of research. A finding does
             not travel: only the release's own archive can put one here
          4. the frozen snapshot's own rows, which supply a fix version the feed
             has stopped carrying and a disposition for a combination neither
             feed mentions at all
          5. the snapshot's extended-support clearances, last, because a
             clearance outranks everything the steps before it put down —
             including the row step 4 just read out of the same file

        Returns the packages and whether the record carries the OSV record's own
        top-level fields, which decides whether its `published` date is a
        candidate for a fix date.
        """
        identity = release_identity(base_eco)
        codename = _codename_for_version(identity.version) if identity is not None else None
        is_base_channel = identity is not None and identity.channel == _BASE_CHANNEL
        tokens = statements_by_codename.get(codename, []) if codename else []
        # the release's own archive, which is the only token that may put a
        # finding in its namespace and the only one that can say the release
        # never shipped a package at all
        base_statements = statements.get(codename, {}) if codename else {}

        states: dict[str, PackageState] = {}

        self._apply_osv_entries(entries.get(base_eco, []), statements, states)
        from_osv = bool(states)
        from_osv |= self._apply_inference(base_eco, entries, base_statements, states)
        self._apply_statements(base_eco, tokens, statements, states)

        if codename is not None and is_base_channel:
            self._apply_tracker_rows(base_eco, rows.get(codename, {}), base_statements, states)
            self._apply_tracker_clearances(clearances.get(codename, set()), base_statements, states)

        return states, from_osv

    def _apply_osv_entries(
        self,
        own: list[cve_rows.OsvEntry],
        statements: dict[str, dict[str, str]],
        states: dict[str, PackageState],
    ) -> None:
        """Step 1: the release's own OSV entries, which are where fix versions come from."""
        for entry in own:
            token = distro_label_from_purl(entry.purl)
            package = source_package_from_purl(entry.purl)
            disposition = self._disposition(statements, token, package)
            if disposition == NOT_PRESENT:
                # the release does not ship the package, so there is nothing for
                # a record to be about; the entry it contradicts is dropped
                continue
            state = states.get(entry.package)
            if state is None:
                state = states[entry.package] = PackageState(package=entry.package, ecosystem=entry.ecosystem)
            state.fixed.extend(entry.fixed)
            if disposition == WONT_FIX:
                state.wont_fix = True
            elif disposition == NOT_AFFECTED:
                state.clear()

    @staticmethod
    def _apply_inference(
        base_eco: str,
        entries: dict[str, list[cve_rows.OsvEntry]],
        base_statements: dict[str, str],
        states: dict[str, PackageState],
    ) -> bool:
        """Step 2: the Pro-to-base inference, reading an omission.

        Canonical encodes "this will only ever be fixed on Pro" by leaving the
        base entry out, so a package the extended-support build names and the
        base release does not is presumed vulnerable there with no fix coming.

        A statement is a positive claim about that package in that release and it
        wins: where VEX can speak to an inferred package at all it agrees with
        the inference about 98.5% of the time, so deferring on the rest is
        consistent rather than a reversal. A researched clearance is restated
        rather than dropped — dropping it leaves the record saying nothing about
        a package the vendor has explicitly cleared, which is the same thing it
        says about one nobody has looked at — while a statement that the release
        does not ship the package at all means the inference read its omission
        backwards, and the package goes.

        Returns whether it put anything here, since a record it builds alone
        still carries the OSV record's own top-level fields.
        """
        inferred = False
        for eco in sorted(entries):
            if pro_to_base_ecosystem(eco) != base_eco:
                continue
            for entry in entries[eco]:
                if entry.package in states:
                    continue
                # an inferred package has no purl of its own — the Pro entry's
                # names a Pro pocket — so the statement has to be looked up at the
                # base codename explicitly or this silently reads as "VEX says
                # nothing" while appearing to work
                disposition = base_statements.get(entry.package)
                if disposition == NOT_PRESENT:
                    continue
                state = PackageState(package=entry.package, ecosystem=base_eco, wont_fix=True, inferred=True)
                if disposition == NOT_AFFECTED:
                    state.clear()
                states[entry.package] = state
                inferred = True
        return inferred

    @staticmethod
    def _apply_statements(
        base_eco: str,
        tokens: list[str],
        statements: dict[str, dict[str, str]],
        states: dict[str, PackageState],
    ) -> None:
        """Step 3: what the VEX statements at the tokens of this release say.

        This is the half of the union the OSV feed cannot express. A package the
        vendor has cleared is absent from `affected[]`, and so is a package it has
        looked at and not fixed where no OSV record exists for the release at all,
        so enumerating the OSV entries alone drops every statement of the first
        kind and a long tail of the second.

        A clearance overrides whatever is already here and everything else is
        only added where nothing has spoken about the package at all. The
        release's own archive is read first so that a pocket only fills what it
        leaves unsaid.
        """
        for token in tokens:
            speaks_findings = vex_cache.token_asserts_findings(token)
            for package in sorted(statements[token]):
                disposition = statements[token][package]
                if disposition == NOT_PRESENT:
                    continue
                if disposition != NOT_AFFECTED and not speaks_findings:
                    continue
                state = states.get(package)
                if state is not None:
                    if disposition == NOT_AFFECTED:
                        state.clear()
                        state.inferred = False
                    elif state.inferred:
                        # nothing but the inference's guess is here, and this is
                        # the vendor's own word about this package on this
                        # release, so it replaces the guess rather than being
                        # dropped. Only the first token to speak does this: the
                        # release's own archive is read before any pocket, and
                        # clearing the flag leaves the rest filling silence.
                        state.wont_fix = disposition == WONT_FIX
                        state.inferred = False
                    continue
                states[package] = PackageState(
                    package=package,
                    ecosystem=base_eco,
                    cleared=disposition == NOT_AFFECTED,
                    wont_fix=disposition == WONT_FIX,
                )

    def _apply_tracker_rows(
        self,
        base_eco: str,
        rows: dict[str, parser_legacy.Patch],
        base_statements: dict[str, str],
        states: dict[str, PackageState],
    ) -> None:
        """Step 4: the frozen snapshot's own rows, for two different jobs.

        A fix version is a historical fact and the snapshot holds thousands the
        OSV feed has stopped carrying, because Canonical drops a package from a
        release's `affected[]` when it stops tracking it there and the version
        goes with it. So a package either feed mentions, carrying no fix version,
        takes the snapshot's `released` version.

        A disposition from the snapshot is older news, so it is read only where
        neither feed mentions the package at all. A statement always outranks a
        row, including the one that says the release never shipped the package —
        which leaves nothing behind for a row to attach to, so it has to be asked
        about rather than looked for: without that, a row saying the package was
        fixed at a version would put back the package the vendor says was never
        there.
        """
        for package in sorted(rows):
            row = rows[package]
            if base_statements.get(package) == NOT_PRESENT:
                continue
            state = states.get(package)
            if state is None:
                new_state = self._tracker_state(row, base_eco)
                if new_state is not None:
                    states[package] = new_state
                continue
            if state.inferred and not state.cleared and row.status != tracker.STATUS_RELEASED:
                # same seam as the statement step: the row is the vendor's own
                # record for this package on this release, and the inference
                # only guessed at it from the Pro sibling. `released` is skipped
                # because it is a fix version rather than a disposition, and the
                # clause below is what reads it.
                disposition = tracker.disposition_of_status(row.status)
                if disposition == NOT_AFFECTED:
                    state.clear()
                    state.inferred = False
                elif disposition is not None:
                    state.wont_fix = disposition == WONT_FIX
                    state.inferred = False
            if row.status == tracker.STATUS_RELEASED and row.version and not state.cleared and not state.fixed:
                state.fixed.append(row.version)

    @staticmethod
    def _apply_tracker_clearances(
        clearances: set[str],
        base_statements: dict[str, str],
        states: dict[str, PackageState],
    ) -> None:
        """Step 5: the clearances the snapshot holds and no statement repeats.

        Last, because a clearance outranks everything the steps before it put
        down, including the row step 4 just read out of the same file. It
        overrides and never creates: the pre-OSV provider downgraded a row that
        was already there and invented no record, and unlike the VEX clearance
        population this one is unmeasured.
        """
        for package in sorted(clearances):
            state = states.get(package)
            if state is None or state.cleared:
                continue
            if base_statements.get(package) == NOT_PRESENT:
                continue
            state.clear()

    @staticmethod
    def _tracker_esm_clearances(cve_file: parser_legacy.CVEFile) -> set[tuple[str, str]]:
        """The `(codename, source package)` pairs an extended-support pocket cleared in the snapshot.

        A base release row that is an absence of research — `needs-triage` —
        standing next to an ESM pocket that researched the same source package
        and concluded the vulnerable code is not there is not a contradiction,
        and the research wins. It is the same claim a `not_affected` statement at
        that pocket makes, read out of Canonical's other file for the
        combinations where there is no statement to read it out of at all.
        """
        return tracker.esm_clearances(cve_file)

    @staticmethod
    def _tracker_state(row: parser_legacy.Patch, base_eco: str) -> PackageState | None:
        """A package only the snapshot names, or None when the row has nothing to state."""
        if row.status == tracker.STATUS_RELEASED:
            if not row.version:
                # the legacy path omits a released row with no version, and so does this
                return None
            return PackageState(package=row.package or "", ecosystem=base_eco, fixed=[row.version])
        disposition = tracker.disposition_of_status(row.status)
        if disposition is None:
            return None
        return PackageState(
            package=row.package or "",
            ecosystem=base_eco,
            cleared=disposition == NOT_AFFECTED,
            wont_fix=disposition == WONT_FIX,
        )

    @staticmethod
    def _disposition(statements: dict[str, dict[str, str]], token: str | None, package: str | None) -> str | None:
        if not token or not package:
            return None
        return statements.get(canonical_token(token), {}).get(package)

    def _channel_records(
        self,
        cve: str,
        osv_row: cve_rows.OsvRow | None,
        entries: dict[str, list[cve_rows.OsvEntry]],
        statements: dict[str, dict[str, str]],
        severity: str,
    ) -> Iterator[dict[str, Any]]:
        """The `ubuntu:X.YY+esm` records, which carry the real plain-Pro fix versions.

        Enumeration here is the OSV record alone: the channel states fix versions
        and nothing else, so a statement can only remove an entry from it and the
        snapshot has nothing to add. A cleared package is dropped rather than
        stated, because the clearance belongs to the base release's record.
        """
        if osv_row is None:
            return
        for eco in sorted(entries):
            identity = release_identity(eco)
            if identity is None or identity.version in _KNOWN_HUSK_RELEASES:
                continue
            namespace = osv_ecosystem_to_os_namespace(eco, include_esm=self.downconvert_emit_esm)
            if namespace is None or not is_esm_namespace(namespace):
                continue
            states: dict[str, PackageState] = {}
            for entry in entries[eco]:
                token = distro_label_from_purl(entry.purl)
                package = source_package_from_purl(entry.purl)
                if self._disposition(statements, token, package) in (NOT_AFFECTED, NOT_PRESENT):
                    continue
                state = states.get(entry.package)
                if state is None:
                    state = states[entry.package] = PackageState(package=entry.package, ecosystem=entry.ecosystem)
                state.fixed.extend(entry.fixed)
            if not states:
                continue
            self._resolve_fix_dates(cve, osv_row.published, states)
            fixed_in = [item for state in states.values() for item in fixed_in_for(state, namespace)]
            if fixed_in:
                yield os_record(cve, namespace, severity, fixed_in)

    def _resolve_fix_dates(self, cve: str, published: str | None, states: dict[str, PackageState]) -> None:
        """Date every fix version in the record, however it got there.

        A version the snapshot supplied is a fix like any other and gets its date
        the same way. The candidates are the USN that shipped the fix, which is
        the moment the patched package reached the archive, and the record's own
        `published` as a low-confidence fallback; the finder picks the most
        accurate of them and of whatever its own strategies know.
        """
        extra = usn_extra_candidates(self._usn_overlay)
        for state in states.values():
            for version in state.fixed:
                candidates: list[fixdate.Result] = []
                if extra is not None:
                    candidates.extend(extra(cve, state.package, version, state.ecosystem))
                if published:
                    # it isn't clear that a record's published date is the fix
                    # date, so it is offered as the inaccurate candidate it is
                    candidates.append(fixdate.Result(date=published, kind="advisory", accurate=False))  # type: ignore[arg-type]
                result = self.fixdater.best(
                    vuln_id=cve,
                    cpe_or_package=state.package,
                    fix_version=version,
                    ecosystem=state.ecosystem,
                    candidates=candidates,
                )
                if result and result.date:
                    state.available[version] = {"Date": result.date.isoformat(), "Kind": result.kind}

    # ------------------------------------------------------------------
    # the frozen snapshot, for releases the feeds do not serve
    # ------------------------------------------------------------------

    def _osv_covers_legacy_namespace(self, ns: str) -> bool:
        """Does today's feed speak for the legacy namespace `ubuntu:X.YY`?

        A release the feed names is emitted from the merge, so the passthrough
        must not emit it too. A release named in `_KNOWN_HUSK_RELEASES` is never
        in this set, whatever residue the archive still carries for it, so the
        snapshot serves it. So is a release the feed carries only an
        extended-support build of: the Pro-to-base inference still puts records
        in its base namespace, and the snapshot fills in the base data the
        inference has no access to.
        """
        return ns.split(":")[-1] in self._served_versions

    def _iter_normalized_cve_data(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Read input/normalized-cve-data/ via the vendored v3 map_parsed.

        Emits OS-schema envelopes for the releases the feeds do not serve. The
        filter is applied BEFORE map_parsed so fixdater isn't queried for
        releases we'd discard anyway.
        """
        if not os.path.isdir(self.normalized_cve_dir):
            return

        os_schema = schema.OSSchema()
        for filename in sorted(os.listdir(self.normalized_cve_dir)):
            if not tracker.CVE_FILENAME_RE.match(filename):
                continue
            cve_file = tracker.load(self.normalized_cve_dir, filename, self.logger)
            if cve_file is None:
                continue

            # Drop patches for releases the feeds already cover. map_parsed would
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

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------

    def _clean_input(self) -> None:
        """Remove input state nothing reads any more. Silent and idempotent.

        Four directories, all one-time. `ubuntu-cve-tracker` was the cloned
        security tracker repo and `distro-info` a fetched release calendar. The
        other three were the re-encoding of the two feeds and the snapshot into
        per-release SQLite: 12 GB arranged so a release-major walk could read
        them, which walking by CVE removes the need for. The workspace keeps
        `input/` between runs, so leaving them would leave the 12 GB for good.

        And any `.part` staging file an interrupted download left behind.
        `download_to_file` removes its own only when its own retry loop
        exhausts, so a hard kill (OOM, SIGKILL) mid-archive skips that — and
        `input/` surviving between runs is the same reason the directories
        above have to be named here: nothing else would ever remove it.
        """
        for name in ("ubuntu-cve-tracker", "distro-info", "fragments", "vex-fragments", "tracker-index"):
            silent_remove(os.path.join(self.workspace.input_path, name), tree=True)
        http.remove_stale_partial_downloads(self.workspace.input_path, self.logger)

    def get(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        self._clean_input()
        self._download_archive()
        self._download_vex_archive()
        self.fixdater.download()
        try:
            self._read_osv_archive()
            self._read_vex_archive()
            # the snapshot first and the merge last (policy-only, with one case
            # where it is not: a release the feed carries only an extended-support
            # build of is emitted by both, and the merge's record is the one that
            # has seen every source)
            yield from self._iter_normalized_cve_data()
            yield from self._iter_merged()
        finally:
            self._osv_rows.close()
            self._vex_rows.close()
