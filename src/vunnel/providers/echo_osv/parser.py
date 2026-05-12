from __future__ import annotations

import io
import logging
import zipfile
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

# Only ingest advisories with affected entries in these ecosystems.
# The Echo OSV feed also contains "Echo" ecosystem entries for OS-level
# packages, which are already handled by the existing "echo" OS provider.
_LANGUAGE_ECOSYSTEMS = frozenset({"Echo:PyPi", "Echo:npm"})


class Parser:
    def __init__(
        self,
        ws: Workspace,
        url: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.url = url
        self.download_timeout = download_timeout

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

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

    def _download(self) -> bytes:
        self.logger.info(f"downloading Echo OSV archive from {self.url}")
        r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
        return r.content

    def _load(self, archive_bytes: bytes) -> Generator[dict[str, Any]]:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for name in sorted(zf.namelist()):
                if not name.endswith(".json"):
                    continue
                with zf.open(name) as f:
                    yield orjson.loads(f.read())

    @staticmethod
    def _has_language_ecosystem(entry: dict[str, Any]) -> bool:
        """Return True if at least one affected entry targets a language ecosystem."""
        for affected in entry.get("affected", []):
            eco = affected.get("package", {}).get("ecosystem", "")
            if eco in _LANGUAGE_ECOSYSTEMS:
                return True
        return False

    @staticmethod
    def _filter_language_affected(entry: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of the entry with only language-ecosystem affected entries."""
        filtered = [
            a
            for a in entry.get("affected", [])
            if a.get("package", {}).get("ecosystem", "") in _LANGUAGE_ECOSYSTEMS
        ]
        result = dict(entry)
        result["affected"] = filtered
        return result

    def _normalize(
        self,
        entry: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]] | None:
        if not self._has_language_ecosystem(entry):
            return None

        record = self._filter_language_affected(entry)

        vuln_id = record.get("id", "")
        if not vuln_id:
            return None

        vuln_schema = record.get("schema_version", "1.7.5")

        return vuln_id, vuln_schema, record

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        archive_bytes = self._download()
        self.fixdater.download()

        for entry in self._load(archive_bytes):
            osv.patch_fix_date(entry, self.fixdater)
            result = self._normalize(entry)
            if result is not None:
                yield result
