from __future__ import annotations

import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.providers.govulndb.go_release_dates import (
    SOURCE_URLS,
    ReleaseDateResolver,
    ReleaseDates,
    fixed_versions,
    go_extra_candidates,
)
from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


namespace = "govulndb"


class Parser:
    _source_url_ = "https://vuln.go.dev/vulndb.zip"

    def __init__(  # noqa: PLR0913
        self,
        ws: Workspace,
        url: str | None = None,
        download_timeout: int = 125,
        skip_download: bool = False,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
        release_date_resolver: ReleaseDateResolver | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.url = url or self._source_url_
        self.download_timeout = download_timeout
        self.skip_download = skip_download
        self.urls = [self.url, *SOURCE_URLS]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.zip_path = os.path.join(self.workspace.input_path, "vulndb.zip")
        self.extract_dir = os.path.join(self.workspace.input_path, "vulndb")
        # With skip_download the resolver serves the committed release-date tables and
        # nothing else, so the run stays offline.
        self.release_date_resolver = release_date_resolver or ReleaseDateResolver(logger=self.logger, offline=self.skip_download)

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self.logger.info(f"downloading go vulnerability database from {self.url}")
        # no need to remove the previous zip first: download_to_file publishes atomically
        http.download_to_file(self.url, self.zip_path, self.logger, timeout=self.download_timeout)

    def _extract(self) -> None:
        shutil.rmtree(self.extract_dir, ignore_errors=True)
        os.makedirs(self.extract_dir, exist_ok=True)
        dest_root = Path(os.path.abspath(self.extract_dir))
        with zipfile.ZipFile(self.zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                target = Path(os.path.normpath(os.path.join(dest_root, info.filename)))
                if dest_root != target and dest_root not in target.parents:
                    self.logger.warning(f"skipping zip entry outside destination: {info.filename!r}")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    def _load(self) -> Generator[dict[str, Any]]:
        self.logger.info("loading data from extracted vulnerability database")

        id_dir = os.path.join(self.extract_dir, "ID")
        if not os.path.isdir(id_dir):
            self.logger.warning(f"no ID directory found under {self.extract_dir}; nothing to load")
            return

        for name in sorted(os.listdir(id_dir)):
            if not name.endswith(".json"):
                continue
            full_path = os.path.join(id_dir, name)
            with open(full_path, encoding="utf-8") as f:
                yield orjson.loads(f.read())

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry["schema_version"]
        return vuln_id, vuln_schema, vuln_entry

    def _resolve_release_dates(self) -> ReleaseDates:
        # outside the fallback: a record that isn't JSON should fail the run as itself, not
        # first be reported as a release-date failure. fixed_versions skips shapes it doesn't
        # understand, so nothing else can escape from here.
        pairs = fixed_versions(self._load())
        # the resolver handles network failures itself; anything else it raises is a bug,
        # and a fix-date enrichment must never cost the run, so carry on with what the
        # committed tables know
        try:
            return self.release_date_resolver.resolve(pairs)
        except Exception:
            self.logger.exception("go release-date resolve failed; using the committed release-date tables only")
        try:
            return self.release_date_resolver.committed()
        except Exception:
            self.logger.exception("committed go release-date tables are unreadable; no go release dates this run")
            return ReleaseDates({}, {})

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        if self.skip_download:
            self.logger.info(f"skipping download; using existing data under {self.extract_dir}")
        else:
            self._download()
            self._extract()

        # go.dev's OSV records carry no per-fix date, so patch database_specific.anchore.fixes
        # for the grype OSV transformer. The Go release date is accurate=True, beating the
        # advisory's published date; an earlier accurate first-observed date still caps it.
        # See go_release_dates.
        self.fixdater.download()

        # all release-date network traffic happens here, once, before the per-record loop;
        # the loop only consults the frozen result
        release_dates = self._resolve_release_dates()
        extra_candidates = go_extra_candidates(release_dates)

        for vuln_entry in self._load():
            osv.patch_fix_date(vuln_entry, self.fixdater, extra_candidates=extra_candidates)
            yield self._normalize(vuln_entry)
