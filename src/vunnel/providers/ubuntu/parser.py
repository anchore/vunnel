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
        """Yield (identifier, schema, payload) from every fragment on disk.

        Includes both fragments written this run and frozen fragments
        from prior runs whose ecosystem is no longer in the OSV feed.
        Fix-date patching is applied here, at yield time, so today's
        fixdater state annotates even records cached from prior runs.
        """
        if not os.path.isdir(self.fragments_dir):
            return
        for filename in sorted(os.listdir(self.fragments_dir)):
            if not filename.endswith(".db"):
                continue
            path = os.path.join(self.fragments_dir, filename)
            with result.SQLiteReader(path) as reader:
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
                    )
                    yield (
                        envelope.identifier,
                        _schema_from_envelope_url(envelope.schema),
                        payload,
                    )

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
        self._write_fragments(vex_overlay=vex_overlay)
        # legacy first; OSV last (policy-only — identifier shapes don't collide)
        yield from self._iter_normalized_cve_data()
        yield from self._iter_fragments()

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
