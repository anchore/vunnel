"""Stream Canonical's published VEX feed and surface fix disposition.

Canonical's OSV publication collapses six tracker statuses
(`needs-triage`, `needed`, `ignored`, `pending`, `deferred`, `in-progress`)
into a single shape — `affected[]` with `events: [{"introduced": "0"}]`
and no `fixed:` event — losing the won't-fix signal that downstream
matchers and humans use to triage findings. See
documentation.ubuntu.com/security/security-updates/osv/ for the
explicit mapping table.

VEX preserves more granularity. For `status: "affected"`, the
`action_statement` field uses four canonical opening phrases
(measured against the full live feed):

  * "...decided to not fix it..."        →  ignored (won't fix)
  * "...is no longer supported..."       →  ignored (EOL flavor — won't fix)
  * "...needs fixing"                    →  needed (will be fixed eventually)
  * "...needs fixing, and...actively..." →  active/in-progress

Only the first two indicate won't-fix intent. This module streams
`vex-all.tar.xz`, prefix-matches `action_statement`, and exposes a
lookup keyed by (cve_id, distro_label_from_purl, source_package).

Why distro label and not OSV ecosystem string: both OSV and VEX records
embed the same `distro=X` qualifier in their package PURLs (e.g.
`distro=noble`, `distro=esm-infra/jammy`). Joining on the PURL distro
avoids the ecosystem-string-to-channel-codename inverse lookup that
would otherwise be necessary.
"""

from __future__ import annotations

import logging
import re
import tarfile
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Iterable


# action_statement openings (from the live vex-all.tar.xz feed) that mean
# "Canonical decided not to fix". Measured against ~156k statements — these
# two prefixes cover all wont-fix dispositions.
_WONT_FIX_PREFIXES: tuple[str, ...] = (
    "This package (for the given release) is vulnerable to the CVE, the problem is understood, but the Ubuntu Security Team decided to not fix it",
    "This package (for the given release) is no longer supported",
)

# Extracts (distro, source-pkg) from a deb PURL.
_PURL_DISTRO_RE = re.compile(r"distro=([^&]+)")
_PURL_NAME_RE = re.compile(r"^pkg:deb/ubuntu/([^@?]+)")


def is_wont_fix_action(action_statement: str | None) -> bool:
    """Prefix-match an OpenVEX action_statement against the won't-fix openings.

    Canonical writes one of four canonical openings; the two that indicate
    won't-fix are matched here. Returns False for unset, empty, or
    "needs fixing"-style action statements.
    """
    if not action_statement:
        return False
    return action_statement.startswith(_WONT_FIX_PREFIXES)


def distro_label_from_purl(purl: str) -> str | None:
    """Pull the `distro=` qualifier value out of a deb PURL.

    Returns values like "noble", "esm-infra/jammy", "fips-updates/focal",
    or None if the PURL doesn't carry one. Both OSV and VEX records use
    the same distro qualifier, so we use it as the join key.
    """
    m = _PURL_DISTRO_RE.search(purl or "")
    return m.group(1) if m else None


def source_package_from_purl(purl: str) -> str | None:
    """Pull the source package name from a deb PURL (`pkg:deb/ubuntu/<name>@...`)."""
    m = _PURL_NAME_RE.match(purl or "")
    return m.group(1) if m else None


class VEXOverlay:
    """Index of (cve_id, distro_label, source_pkg) tuples that Canonical's VEX
    feed marks as won't-fix.

    Built by streaming Canonical's `vex-all.tar.xz` and prefix-matching
    OpenVEX statements against the won't-fix openings. The index covers
    only `vex/cve/**/*.json`; USN records are skipped (they don't carry
    per-release fix disposition we'd use here).

    Memory cost on the production feed: ~1.25M tuples, ~60 MB Python set.
    Rebuilt each run from the freshly-downloaded tarball; not persisted.
    """

    def __init__(self, logger: logging.Logger | None = None):
        self._wont_fix: set[tuple[str, str, str]] = set()
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        self._built = False

    @classmethod
    def from_archive(cls, archive_path: str, logger: logging.Logger | None = None) -> VEXOverlay:
        ov = cls(logger=logger)
        ov.build_from_archive(archive_path)
        return ov

    def build_from_archive(self, archive_path: str) -> None:
        """Stream the VEX tarball and populate the index in one pass."""
        self.logger.info(f"building VEX overlay from {archive_path}")
        with tarfile.open(archive_path, mode="r:xz") as tar:
            self._ingest_members(tar)
        self._built = True
        self.logger.info(f"VEX overlay built: {len(self._wont_fix)} won't-fix entries")

    def _ingest_members(self, tar: tarfile.TarFile) -> None:
        for member in tar:
            if not member.isfile():
                continue
            if not (member.name.startswith("vex/cve/") and member.name.endswith(".json")):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                record = orjson.loads(fh.read())
            except orjson.JSONDecodeError:
                self.logger.warning(f"failed to parse VEX record {member.name}")
                continue
            self._ingest_statements(record.get("statements", []))

    def _ingest_statements(self, statements: Iterable[dict[str, Any]]) -> None:
        for stmt in statements:
            if stmt.get("status") != "affected":
                continue
            if not is_wont_fix_action(stmt.get("action_statement")):
                continue
            cve = stmt.get("vulnerability", {}).get("name")
            if not cve:
                continue
            for prod in stmt.get("products", []):
                purl = prod.get("@id") or ""
                # Both binaries and the source package carry the same disposition;
                # dedup by only indexing source-arch entries. The OSV lookup side
                # also uses source-package names, so this matches naturally.
                if "arch=source" not in purl:
                    continue
                distro = distro_label_from_purl(purl)
                pkg = source_package_from_purl(purl)
                if distro and pkg:
                    self._wont_fix.add((cve, distro, pkg))

    def is_wont_fix(self, cve_id: str, distro_label: str, source_pkg: str) -> bool:
        """Return True iff Canonical's VEX feed marks this triple as won't-fix.

        cve_id is the upstream CVE identifier (e.g. "CVE-2016-20013"), NOT
        the UBUNTU-CVE-* OSV record id. distro_label is the PURL `distro=`
        qualifier value (e.g. "noble", "esm-infra/jammy"). source_pkg is
        the source package name.
        """
        return (cve_id, distro_label, source_pkg) in self._wont_fix

    def __len__(self) -> int:
        return len(self._wont_fix)
