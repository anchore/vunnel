from __future__ import annotations

import logging
import os
import re
import tarfile
from collections import defaultdict
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import result, schema
from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

from . import parser_legacy
from .usn_fixdate_overlay import USNFixDateOverlay, usn_extra_candidates
from .vex_overlay import VEXOverlay, distro_label_from_purl, source_package_from_purl

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
                "status": "wont-fix",
                # `inference.source_ecosystems` filled in by the caller — the same
                # base (CVE, source-pkg) may have inferences from multiple Pro slices
                # (though restriction to plain Pro makes this rare in practice).
            },
        },
    }


def slice_by_ecosystem(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Group a record's affected[] entries by ecosystem.

    Returns a mapping {ecosystem -> sliced_record}. Each sliced record
    has the original top-level fields and an affected[] containing only
    the entries for that ecosystem. Records with no affected[] entries
    yield an empty mapping.
    """
    by_eco: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for aff in record.get("affected", []):
        eco = aff.get("package", {}).get("ecosystem")
        if not eco:
            continue
        by_eco[eco].append(aff)

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
            db_spec = aff.get("database_specific") or {}
            anchore = db_spec.get("anchore") or {}
            anchore["status"] = "wont-fix"
            db_spec["anchore"] = anchore
            aff["database_specific"] = db_spec


class Parser:
    _osv_url_ = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
    _vex_url_ = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
    _archive_filename_ = "osv-all.tar.xz"
    _vex_archive_filename_ = "vex-all.tar.xz"
    _fragments_subdir_ = "fragments"
    _normalized_subdir_ = "normalized-cve-data"

    def __init__(
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.workspace = workspace
        self.fixdater = fixdater if fixdater is not None else fixdate.default_finder(workspace)
        self.download_timeout = download_timeout
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)

        self.archive_path = os.path.join(workspace.input_path, self._archive_filename_)
        self.vex_archive_path = os.path.join(workspace.input_path, self._vex_archive_filename_)
        self.fragments_dir = os.path.join(workspace.input_path, self._fragments_subdir_)
        self.normalized_cve_dir = os.path.join(workspace.input_path, self._normalized_subdir_)
        self.urls = [self._osv_url_, self._vex_url_]
        # USN fix-date overlay built lazily in get(); _iter_envelopes_with_fixdate reads it.
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

    def _download_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._osv_url_, self.archive_path)

    def _download_vex_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._vex_url_, self.vex_archive_path)

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
        """Open a writer for a single ecosystem's fragment.

        Uses DELETE_BEFORE_WRITE so any prior fragment for this ecosystem
        is replaced wholesale. Fragments for ecosystems we don't open
        this run are left untouched (frozen).
        """
        os.makedirs(self.fragments_dir, exist_ok=True)
        path = os.path.join(self.fragments_dir, f"{ecosystem_to_slug(ecosystem)}.db")
        writer = result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=path,
            logger=self.logger,
        )
        return writer.__enter__()

    def _write_fragments(self, vex_overlay: VEXOverlay | None = None) -> None:
        """Stream the tarball, slice records by ecosystem, write per-ecosystem fragments.

        Each ecosystem encountered in today's tarball gets its fragment
        file wiped (via DELETE_BEFORE_WRITE) and rewritten. Ecosystems
        absent from today's tarball are not touched.

        NOTE: `patch_fix_date` is intentionally NOT called here. Fix-date
        annotations are applied at yield time (in _iter_fragments) so that
        improvements to the fixdate cache flow through to frozen fragments
        on the next run without rewriting them.

        Fix DISPOSITION (won't-fix vs other) is the opposite: it's baked
        into the fragment at write time using today's VEX overlay, so
        that frozen fragments carry the disposition forward through EOL.
        When VEX stops publishing for a release, the fragment retains the
        last-known wont-fix status from when the release was still tracked.
        """
        writers: dict[str, result.Writer] = {}
        exc: BaseException | None = None
        try:
            with tarfile.open(self.archive_path, mode="r:xz") as tar:
                for record in _iter_cve_records(tar):
                    self._dispatch_record_to_fragments(record, writers, vex_overlay)
        except BaseException as e:
            exc = e
            raise
        finally:
            for writer in writers.values():
                writer.__exit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)

    def _dispatch_record_to_fragments(
        self,
        record: dict[str, Any],
        writers: dict[str, result.Writer],
        vex_overlay: VEXOverlay | None,
    ) -> None:
        sliced = slice_by_ecosystem(record)
        if not sliced:
            return
        if vex_overlay is not None:
            _annotate_wont_fix(sliced, record, vex_overlay)
        rec_schema = self._record_schema(record)
        cve_id = record["id"].lower()
        for eco, sliced_record in sliced.items():
            if eco not in writers:
                writers[eco] = self._open_fragment_writer(eco)
            identifier = f"{ecosystem_to_slug(eco)}/{cve_id}"
            writers[eco].write(identifier=identifier, schema=rec_schema, payload=sliced_record)

    def _iter_fragments(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Yield (identifier, schema, payload) from every fragment on disk + inferred entries.

        Three things happen here, all at yield time so that improvements to
        upstream feeds + the fixdate cache flow through to frozen fragments
        on the next run without rewriting them:

          1. Real envelopes from each fragment are yielded verbatim (with
             fix-date patching applied).
          2. For each base Ubuntu ecosystem with sibling plain-Pro (ESM)
             fragments, any (CVE, source-pkg) tuple Pro has and base does
             NOT have produces a synthesized base wont-fix envelope. This
             reconstructs the signal Canonical encodes by *omission* of the
             base entry when a CVE will only be fixed in Pro.
          3. The inference runs from current Pro data every yield, so:
               - while base is still in OSV: inferred entries fill Pro-only-fix gaps
               - after base EOLs (frozen base fragment): inferred entries
                 from continuing Pro coverage layer on top of the frozen state.
        """
        if not os.path.isdir(self.fragments_dir):
            return

        base_paths, pro_paths, unclassified = self._group_fragments_by_base()

        # Yield unclassifiable fragments verbatim (test fixtures with empty affected[],
        # future shapes we don't recognize, etc.) — never apply inference to them.
        for path in unclassified:
            yield from self._iter_envelopes_with_fixdate(path)

        # Pass 1: yield Pro fragments verbatim. (Inference happens during the base pass.)
        seen_pro_paths: set[str] = set()
        for paths in pro_paths.values():
            for path in paths:
                if path in seen_pro_paths:
                    continue
                seen_pro_paths.add(path)
                yield from self._iter_envelopes_with_fixdate(path)

        # Pass 2: yield base envelopes (real + merged inferences from Pro siblings).
        # An inferred base entry shares the (base_eco, cve_id) key — and therefore the
        # envelope identifier — with any real base entry for the same CVE. We must
        # merge inferred affected[] entries INTO the real envelope before yielding;
        # emitting a separate envelope would collide under INSERT OR REPLACE and
        # the synthesized one would overwrite the real data.
        all_base_ecos = set(base_paths) | set(pro_paths)
        for base_eco in sorted(all_base_ecos):
            yield from self._yield_base_with_inferences(
                base_eco,
                base_path=base_paths.get(base_eco),
                pro_paths=pro_paths.get(base_eco, []),
            )

    def _yield_base_with_inferences(
        self,
        base_eco: str,
        base_path: str | None,
        pro_paths: list[str],
    ) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        # Collect real envelopes by cve, keyed so we can merge inferences in.
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

        for cve in cve_order:
            entry = by_cve[cve]
            yield entry["identifier"], entry["schema"], entry["payload"]

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
        pro_affs = payload.get("affected", [])
        pro_eco = pro_affs[0].get("package", {}).get("ecosystem") if pro_affs else None
        target = by_cve.get(cve)
        existing_pkgs = _affected_package_names(target["payload"]) if target else set()
        new_affs = _synthesize_missing(pro_affs, existing_pkgs, base_eco, pro_eco)
        if not new_affs:
            return
        if target is None:
            self._add_synthetic_envelope(by_cve, cve_order, envelope, new_affs, base_eco)
        else:
            target["payload"].setdefault("affected", []).extend(new_affs)

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
            "identifier": f"{ecosystem_to_slug(base_eco)}/{cve.lower()}",
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
                yield (
                    envelope.identifier,
                    _schema_from_envelope_url(envelope.schema),
                    payload,
                )

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
        slug; every envelope in a fragment shares the same ecosystem by
        the slicing invariant.
        """
        base_paths: dict[str, str] = {}
        pro_paths: dict[str, list[str]] = {}
        unclassified: list[str] = []
        for filename in sorted(os.listdir(self.fragments_dir)):
            if not filename.endswith(".db"):
                continue
            path = os.path.join(self.fragments_dir, filename)
            eco = self._ecosystem_of_fragment(path)
            if eco is None:
                unclassified.append(path)
                continue
            base = pro_to_base_ecosystem(eco)
            if base is None:
                base_paths[eco] = path
            else:
                pro_paths.setdefault(base, []).append(path)
        return base_paths, pro_paths, unclassified

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
        Checks the base ecosystem only (`ubuntu-X.YY-lts.db` or `ubuntu-X.YY.db`);
        Pro/FIPS variants persisting after the base ecosystem drops is fine —
        they emit their own fragments, base release falls through to legacy.
        """
        version = ns.split(":")[-1]
        return any(os.path.exists(os.path.join(self.fragments_dir, candidate)) for candidate in (f"ubuntu-{version}-lts.db", f"ubuntu-{version}.db"))

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

    def get(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        self._download_archive()
        self._download_vex_archive()
        self.fixdater.download()
        vex_overlay = self._load_vex_overlay()
        self._usn_overlay = self._load_usn_overlay()
        self._write_fragments(vex_overlay=vex_overlay)
        # legacy first; OSV last (policy-only — identifier shapes don't collide)
        yield from self._iter_normalized_cve_data()
        yield from self._iter_fragments()

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
        """Build the won't-fix overlay from the downloaded VEX archive.

        If the archive is missing or unreadable, log a warning and proceed
        without an overlay — the fragments still get written with full OSV
        data, just without won't-fix annotations on this run. Frozen
        fragments from prior runs retain whatever they were written with.
        """
        if not os.path.isfile(self.vex_archive_path):
            self.logger.warning(
                f"VEX archive missing at {self.vex_archive_path}; won't-fix annotations will be absent on this run",
            )
            return None
        try:
            return VEXOverlay.from_archive(self.vex_archive_path, logger=self.logger)
        except Exception:
            self.logger.exception("failed to build VEX overlay; won't-fix annotations will be absent on this run")
            return None
