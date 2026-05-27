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


class Parser:
    _osv_url_ = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
    _archive_filename_ = "osv-all.tar.xz"
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
        self.fragments_dir = os.path.join(workspace.input_path, self._fragments_subdir_)
        self.normalized_cve_dir = os.path.join(workspace.input_path, self._normalized_subdir_)
        self.urls = [self._osv_url_]

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
        self.logger.info(f"downloading {self._osv_url_}")
        with (
            http.get(self._osv_url_, self.logger, stream=True, timeout=self.download_timeout) as r,
            open(
                self.archive_path,
                "wb",
            ) as fh,
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

    def _write_fragments(self) -> None:
        """Stream the tarball, slice records by ecosystem, write per-ecosystem fragments.

        Each ecosystem encountered in today's tarball gets its fragment
        file wiped (via DELETE_BEFORE_WRITE) and rewritten. Ecosystems
        absent from today's tarball are not touched.
        """
        writers: dict[str, result.Writer] = {}
        exc: BaseException | None = None
        try:
            with tarfile.open(self.archive_path, mode="r:xz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    if not (member.name.startswith("osv/cve/") and member.name.endswith(".json")):
                        continue
                    fh = tar.extractfile(member)
                    if fh is None:
                        continue
                    record = orjson.loads(fh.read())
                    osv.patch_fix_date(record, self.fixdater)

                    sliced = slice_by_ecosystem(record)
                    if not sliced:
                        continue

                    rec_schema = self._record_schema(record)
                    cve_id = record["id"].lower()
                    for eco, sliced_record in sliced.items():
                        if eco not in writers:
                            writers[eco] = self._open_fragment_writer(eco)
                        identifier = f"{ecosystem_to_slug(eco)}/{cve_id}"
                        writers[eco].write(identifier=identifier, schema=rec_schema, payload=sliced_record)
        except BaseException as e:
            exc = e
            raise
        finally:
            for writer in writers.values():
                writer.__exit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)

    def _iter_fragments(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Yield (identifier, schema, payload) from every fragment on disk.

        Includes both fragments written this run and frozen fragments
        from prior runs whose ecosystem is no longer in the OSV feed.
        """
        if not os.path.isdir(self.fragments_dir):
            return
        for filename in sorted(os.listdir(self.fragments_dir)):
            if not filename.endswith(".db"):
                continue
            path = os.path.join(self.fragments_dir, filename)
            with result.SQLiteReader(path) as reader:
                for envelope in reader.each():
                    yield (
                        envelope.identifier,
                        _schema_from_envelope_url(envelope.schema),
                        envelope.item,
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
        skipped to avoid double-emission.
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
            vulns = parser_legacy.map_parsed(cve_file, self.fixdater, self.logger)
            for vuln in vulns:
                if not vuln.NamespaceName or not vuln.Name:
                    continue
                if self._osv_covers_legacy_namespace(vuln.NamespaceName):
                    continue
                identifier = f"{vuln.NamespaceName}/{vuln.Name.lower()}"
                yield identifier, os_schema, {"Vulnerability": vuln.json()}

    def get(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        self._download_archive()
        self.fixdater.download()
        self._write_fragments()
        # legacy first; OSV last (policy-only — identifier shapes don't collide)
        yield from self._iter_normalized_cve_data()
        yield from self._iter_fragments()
