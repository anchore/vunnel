from __future__ import annotations

import glob
import logging
import os
import re
import shutil
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import schema
from vunnel.result import SQLiteReader
from vunnel.tool import fixdate
from vunnel.utils import archive, osv
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from vunnel.workspace import Workspace

_SCHEMA_VERSION_RE = re.compile(r"/schema-([0-9]+(?:\.[0-9]+){1,2})\.json$")


def _schema_from_envelope_url(url: str) -> schema.Schema:
    """Reconstruct a Schema object from an envelope's schema URL."""
    m = _SCHEMA_VERSION_RE.search(url)
    version = m.group(1) if m else "0.0.0"
    return schema.Schema(version=version, url=url)


class Parser:
    _osv_url_ = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
    _archive_filename_ = "osv-all.tar.xz"
    _osv_subdir_ = "osv"
    _legacy_subdir_ = "legacy"

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
        self.osv_dir = os.path.join(workspace.input_path, self._osv_subdir_)
        self.legacy_dir = os.path.join(workspace.input_path, self._legacy_subdir_)
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

    def _download(self) -> None:
        self.logger.info(f"downloading {self._osv_url_}")
        with http.get(self._osv_url_, self.logger, stream=True, timeout=self.download_timeout) as r, open(self.archive_path, "wb") as fh:
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)

    def _extract(self) -> None:
        # Wipe stale extracted records so dropped CVEs don't linger as ghosts.
        if os.path.isdir(self.osv_dir):
            shutil.rmtree(self.osv_dir)
        self.logger.info(f"extracting {self.archive_path} -> {self.workspace.input_path}")
        archive.extract(self.archive_path, self.workspace.input_path)

    def _iter_osv_records(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        cve_dir = os.path.join(self.osv_dir, "cve")
        if not os.path.isdir(cve_dir):
            return
        for dirpath, dirnames, filenames in os.walk(cve_dir):
            dirnames.sort()
            for filename in sorted(filenames):
                if not filename.endswith(".json"):
                    continue
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as f:
                    record = orjson.loads(f.read())

                osv.patch_fix_date(record, self.fixdater)

                identifier = record["id"].lower()
                rec_schema = schema.OSVSchema(version=record.get("schema_version", schema.OSV_SCHEMA_VERSION))
                yield identifier, rec_schema, record

    def _iter_legacy_records(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        if not os.path.isdir(self.legacy_dir):
            return
        db_paths = sorted(glob.glob(os.path.join(self.legacy_dir, "**", "results.db"), recursive=True))
        for db_path in db_paths:
            self.logger.info(f"reading legacy passthrough from {db_path}")
            with SQLiteReader(db_path) as reader:
                for envelope in reader.each():
                    yield (
                        envelope.identifier,
                        _schema_from_envelope_url(envelope.schema),
                        envelope.item,
                    )

    def get(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        self._download()
        self._extract()
        self.fixdater.download()

        # legacy first; OSV last so it wins on identifier collision via INSERT OR REPLACE
        yield from self._iter_legacy_records()
        yield from self._iter_osv_records()
