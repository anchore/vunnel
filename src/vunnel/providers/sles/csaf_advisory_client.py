from __future__ import annotations

import os
import sys
import tarfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    import logging

    from vunnel.workspace import Workspace

CSAF_ADVISORY_ARCHIVE_URL = "https://ftp.suse.com/pub/projects/security/csaf.tar.bz2"

# NEVRAs in the advisory feed carry a trailing ".{arch}" that the VEX feed omits.
# Closed set, verified against the corpus.
_ARCHES = frozenset(
    {
        "x86_64",
        "aarch64",
        "aarch64_ilp32",
        "ppc64le",
        "ppc64",
        "s390x",
        "s390",
        "i386",
        "i486",
        "i586",
        "i686",
        "ia64",
        "armv6hl",
        "armv7hl",
        "noarch",
        "src",
        "nosrc",
    },
)

# The advisory feed covers openSUSE and even RHSA rebuilds as well as SLE. Only SLE
# platforms can date a SLES fix, and dropping the rest halves the index (2.8M -> 1.4M
# entries) while costing 0.1pp of coverage.
_SLE_PLATFORM_PREFIX = "SUSE Linux Enterprise"


@dataclass(frozen=True)
class AdvisoryDates:
    """Earliest advisory release dates, indexed two ways.

    `by_cve_nevr` answers "when did an advisory naming this CVE ship this build" -- the
    precise question, and the primary key. `by_nevr` answers "when did this build ship at
    all", a property of the build rather than of the CVE, and is the fallback for builds
    SUSE never listed under the CVE that VEX says they fix. See README.md, "Fix dates".
    """

    by_cve_nevr: dict[tuple[str, str], str] = field(default_factory=dict)
    by_nevr: dict[str, str] = field(default_factory=dict)


def strip_arch(nevra: str) -> str:
    """'python3-uamqp-1.5.3-150100.4.13.1.x86_64' -> 'python3-uamqp-1.5.3-150100.4.13.1'."""
    head, _, tail = nevra.rpartition(".")
    return head if head and tail in _ARCHES else nevra


class SLESCSAFAdvisoryClient:
    """Downloads SUSE's advisory-oriented CSAF archive and indexes the release date of
    every (CVE, package NEVR) it ships.

    This exists only to date the fixes in the CVE-oriented VEX feed, which carries no fix
    date of its own: its `document.tracking` dates describe when SUSE's CVE page was
    created and last touched, not when anything shipped. An advisory document *is* one
    advisory, so its `initial_release_date` is the date those packages became available.
    Neither feed has a per-remediation date (`remediations[].date` is empty in both), so a
    document-level date is the finest granularity available.
    """

    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger,
        archive_url: str = CSAF_ADVISORY_ARCHIVE_URL,
        download_timeout: int = 125,
        skip_download: bool = False,
    ):
        self.workspace = workspace
        self.logger = logger
        self.archive_url = archive_url
        self.download_timeout = download_timeout
        self.skip_download = skip_download
        self.archive_path = os.path.join(workspace.input_path, "csaf.tar.bz2")

    def download(self) -> None:
        if self.skip_download:
            self.logger.info("skipping download in SLES CSAF advisory client")
            return

        if not os.path.exists(self.workspace.input_path):
            os.makedirs(self.workspace.input_path)

        self.logger.info(f"downloading {self.archive_url}")
        with (
            http.get(self.archive_url, self.logger, stream=True, timeout=self.download_timeout) as response,
            open(self.archive_path, "wb") as fh,
        ):
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)

    def fix_dates(self) -> AdvisoryDates:
        """Index the earliest advisory release date (a YYYY-MM-DD string) of every build
        the archive ships, by (CVE id, arch-stripped NEVR) and by NEVR alone.

        Keyed without the product, deliberately: the two feeds attribute products
        differently -- an advisory ships to `...Module for Basesystem 15 SP6` where VEX
        records the base OS -- so an exact (CVE, product, NEVR) key resolves far fewer VEX
        tuples. Earliest wins where a NEVR was shipped by several advisories.
        """
        if not os.path.exists(self.archive_path):
            raise FileNotFoundError(f"CSAF advisory archive not found at {self.archive_path!r}; call download() first")

        dates = AdvisoryDates()
        parsed = skipped = 0
        with tarfile.open(self.archive_path, mode="r:bz2") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                doc = self._load(fh.read(), member.name)
                if doc is None:
                    skipped += 1
                    continue
                parsed += 1
                self._index(doc, dates)

        self.logger.info(
            f"indexed fix dates from {parsed} advisories ({skipped} unparseable), "
            f"{len(dates.by_cve_nevr)} (cve, package) keys, {len(dates.by_nevr)} package keys",
        )
        return dates

    def _load(self, raw: bytes, name: str) -> dict[str, Any] | None:
        try:
            return orjson.loads(raw)
        except Exception:  # noqa: S110
            pass
        try:
            # ~185 documents carry latin-1 bytes in prose while declaring UTF-8; every
            # field this index reads (dates, CVE ids, product ids) is ASCII anyway.
            return orjson.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            self.logger.warning(f"failed to parse CSAF advisory doc {name!r}, skipping")
            return None

    @staticmethod
    def _index(doc: dict[str, Any], dates: AdvisoryDates) -> None:
        released = (doc.get("document") or {}).get("tracking", {}).get("initial_release_date")
        if not released:
            return
        day = sys.intern(released[:10])

        for vuln in doc.get("vulnerabilities") or []:
            cve_id = vuln.get("cve")
            if not cve_id:
                continue
            cve_id = sys.intern(cve_id)
            status = vuln.get("product_status") or {}
            for category in ("fixed", "recommended"):
                for product_id in status.get(category) or []:
                    platform, _, nevra = product_id.partition(":")
                    if not nevra or not platform.startswith(_SLE_PLATFORM_PREFIX):
                        continue
                    nevr = sys.intern(strip_arch(nevra))
                    key = (cve_id, nevr)
                    known = dates.by_cve_nevr.get(key)
                    if known is None or day < known:
                        dates.by_cve_nevr[key] = day
                    known = dates.by_nevr.get(nevr)
                    if known is None or day < known:
                        dates.by_nevr[nevr] = day
