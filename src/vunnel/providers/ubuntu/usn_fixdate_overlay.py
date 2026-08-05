"""Index Canonical USN records by their per-(ecosystem, source-pkg, fixed-version)
publish dates, used as an authoritative fix-availability date source.

OpenVEX's per-statement `timestamp` is the *vulnerability* publication date,
not the fix-ship date — checked against real records, the chromium "fixed"
statements carry CVE-publish timestamps from years before the fix actually
shipped. The OSV CVE record's `published` is similarly the vulnerability date.

The actual fix-ship date lives in `osv/usn/USN-*.json`'s top-level `published`
field — that's the moment Canonical pushed the patched package to the archive.
Real-world spot-check: CVE-2023-38545 (curl) → USN-6429-1 published
`2023-10-11T11:34:51Z`, which matches the public coordinated disclosure date.

Measured coverage against today's tarball: USN ships 77% of CVE fix tuples
overall; plain-Pro tier coverage is 88-100% (the regime the v3-to-OSV cutover
most needs to backfill). FIPS/Realtime/Nvidia tiers have low USN coverage
(those tiers don't ship via USN); they fall through to first-observed.

The overlay is read-only — built once per run by streaming the same OSV
tarball the fragment writer reads. ~150k tuples, ~50 MB in-memory dict.
"""

from __future__ import annotations

import logging
import tarfile
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Callable

    from vunnel.tool import fixdate as _fixdate


class USNFixDateOverlay:
    """`(ecosystem, source-pkg, fixed-version) → earliest USN published date`.

    "Earliest" because Canonical occasionally re-ships the same fix tuple in
    a follow-up USN (e.g. USN-X-2 supersedes USN-X-1 with a regression fix
    at the same version). The first one is the actual fix-ship date.

    Build by streaming the OSV tarball — same archive the fragment writer
    reads — and walking `osv/usn/**/*.json` records. Each USN's top-level
    `published` field is the authoritative fix-ship date; we associate it
    with every (eco, src-pkg, fixed-ver) tuple in the USN's `affected[]`.
    """

    def __init__(self, logger: logging.Logger | None = None):
        self._index: dict[tuple[str, str, str], date] = {}
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        self._built = False

    @classmethod
    def from_archive(cls, archive_path: str, logger: logging.Logger | None = None) -> USNFixDateOverlay:
        ov = cls(logger=logger)
        ov.build_from_archive(archive_path)
        return ov

    def build_from_archive(self, archive_path: str) -> None:
        """Stream the OSV tarball and index every USN's fix-ship dates."""
        self.logger.info(f"building USN fix-date overlay from {archive_path}")
        with tarfile.open(archive_path, mode="r:xz") as tar:
            self._ingest_members(tar)
        self._built = True
        self.logger.info(f"USN fix-date overlay built: {len(self._index)} (eco, pkg, ver) tuples")

    def _ingest_members(self, tar: tarfile.TarFile) -> None:
        for member in tar:
            if not member.isfile():
                continue
            if not (member.name.startswith("osv/usn/") and member.name.endswith(".json")):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                record = orjson.loads(fh.read())
            except orjson.JSONDecodeError:
                self.logger.warning(f"failed to parse USN record {member.name}")
                continue
            self._ingest_record(record)

    def _ingest_record(self, record: dict[str, Any]) -> None:
        pub_raw = record.get("published")
        if not pub_raw:
            return
        pub_date = _parse_iso_date(pub_raw)
        if pub_date is None:
            return
        for aff in record.get("affected", []):
            pkg = aff.get("package") or {}
            eco = pkg.get("ecosystem")
            name = pkg.get("name")
            if not (eco and name):
                continue
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    fv = ev.get("fixed")
                    if not fv:
                        continue
                    self._observe(eco, name, fv, pub_date)

    def _observe(self, eco: str, src_pkg: str, fixed_ver: str, pub: date) -> None:
        key = (eco, src_pkg, fixed_ver)
        existing = self._index.get(key)
        if existing is None or pub < existing:
            self._index[key] = pub

    def lookup(self, eco: str, src_pkg: str, fixed_ver: str) -> date | None:
        """Return the earliest USN-published date for the tuple, or None on miss."""
        return self._index.get((eco, src_pkg, fixed_ver))

    def __len__(self) -> int:
        return len(self._index)


def _parse_iso_date(s: str) -> date | None:
    """Parse an OSV ISO-8601 timestamp into a date; return None on garbage.

    USNs use UTC ISO strings — `2023-10-11T11:34:51Z` or
    `2023-10-11T11:34:51.353678Z`. Some early records lack the Z. Strip
    common variants and date-only-parse, since we don't care about
    sub-day precision for fix dating.
    """
    try:
        # datetime.fromisoformat in 3.11+ handles Z; otherwise normalize.
        normalized = s.rstrip("Z").rstrip()
        if "T" in normalized:
            return datetime.fromisoformat(normalized).date()
        # Date-only form
        return date.fromisoformat(normalized)
    except (ValueError, TypeError):
        return None


def usn_extra_candidates(
    overlay: USNFixDateOverlay | None,
) -> Callable[[str, str, str, str | None], list[_fixdate.Result]] | None:
    """Build the extra-candidates callable for osv.patch_fix_date.

    Returns a function with the signature patch_fix_date expects
    (vuln_id, package_name, fix_version, ecosystem) -> list[Result]. The
    USN-derived candidate is marked accurate=True so it wins against
    first-observed's lower-confidence results.
    """
    if overlay is None or len(overlay) == 0:
        return None

    # Local import — fixdate package isn't always loaded at module-init time.
    from vunnel.tool import fixdate  # noqa: PLC0415

    def candidates(vuln_id: str, package_name: str, fix_version: str, ecosystem: str | None) -> list[fixdate.Result]:
        if not ecosystem:
            return []
        d = overlay.lookup(ecosystem, package_name, fix_version)
        if d is None:
            return []
        return [fixdate.Result(date=d, kind="advisory", accurate=True)]

    return candidates
