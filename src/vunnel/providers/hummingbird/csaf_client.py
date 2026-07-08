from __future__ import annotations

import concurrent.futures
import contextlib
import csv
import email.utils
import os
import shutil
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from vunnel.utils import http_wrapper as http
from vunnel.utils.archive import extract

if TYPE_CHECKING:
    import logging

    from vunnel.workspace import Workspace

VEX_FEED_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/vex-feed/archive_latest.txt"

ARCHIVE_SUFFIXES = (".tar", ".tar.zst", ".tar.gz", ".tar.xz", ".tar.bz2")

# state files written by a previous incremental version of this client; they are
# meaningless now that every run downloads the archive, but would otherwise
# persist in the workspace (and any cached copies of it) forever
LEGACY_STATE_FILES = ("archive_timestamp.txt", "changes_timestamp.txt")


class CSAFVEXClient:
    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger,
        max_workers: int = 16,
        latest_url: str = VEX_FEED_LATEST_URL,
        skip_download: bool = False,
    ):
        self.workspace = workspace
        self.latest_url = latest_url
        self.latest_filename = "archive_latest.txt"
        self.logger = logger
        self.max_workers = max_workers
        self.advisories_path = os.path.join(self.workspace.input_path, "advisories")
        self.archive_mod_time: datetime | None = None

        if not skip_download:
            self._sync()
        else:
            self.logger.info("skipping downloads in hummingbird CSAF VEX client")

    @staticmethod
    def default_url() -> str:
        return VEX_FEED_LATEST_URL

    # ── public ────────────────────────────────────────────────────────

    def cve_paths(self) -> list[str]:
        """Return absolute paths for every CVE JSON file on disk."""
        paths = []
        for dirpath, _dirnames, filenames in os.walk(self.advisories_path):
            for fn in filenames:
                if fn.endswith(".json"):
                    paths.append(os.path.join(dirpath, fn))
        return sorted(paths)

    # ── URLs ──────────────────────────────────────────────────────────

    def _changes_url(self) -> str:
        return self.latest_url.replace(self.latest_filename, "changes.csv")

    def _deletions_url(self) -> str:
        return self.latest_url.replace(self.latest_filename, "deletions.csv")

    def _archive_url(self) -> str:
        resp = http.get(self.latest_url, logger=self.logger)
        return self.latest_url.replace(self.latest_filename, resp.text.strip())

    # ── local paths ───────────────────────────────────────────────────

    def _local_changes_path(self) -> str:
        return os.path.join(self.workspace.input_path, "changes.csv")

    def _local_deletions_path(self) -> str:
        return os.path.join(self.workspace.input_path, "deletions.csv")

    # ── download helpers ──────────────────────────────────────────────

    def _download_stream(self, url: str, path: str) -> datetime | None:
        """Download url to path, returning the response Last-Modified (if any)."""
        with http.get(url, logger=self.logger, stream=True) as response, open(path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)
            lm = response.headers.get("Last-Modified")
        if lm:
            return email.utils.parsedate_to_datetime(lm)
        return None

    # ── core sync logic ───────────────────────────────────────────────

    def _sync(self) -> None:
        os.makedirs(self.advisories_path, exist_ok=True)
        self._remove_stray_files()

        # stateless flow: every run downloads and extracts the archive, then
        # re-applies everything that changed since the archive was baked. this
        # trades some redundant downloading for having no persisted state that
        # can disagree with what is actually on disk.
        self._download_archive(self._archive_url())

        self._download_stream(self._changes_url(), self._local_changes_path())
        self._download_stream(self._deletions_url(), self._local_deletions_path())
        self._process_changes_and_deletions()

    def _remove_stray_files(self) -> None:
        # leftover archives or partial extractions from interrupted runs would
        # otherwise persist in the workspace (and any cached copies of it) forever
        tmp_dir = self._advisories_tmp_path()
        if os.path.isdir(tmp_dir):
            self.logger.warning(f"removing stray partial extraction: {tmp_dir}")
            shutil.rmtree(tmp_dir)

        for name in os.listdir(self.workspace.input_path):
            if name.endswith(ARCHIVE_SUFFIXES):
                self.logger.warning(f"removing stray archive: {name}")
                with contextlib.suppress(OSError):
                    os.remove(os.path.join(self.workspace.input_path, name))

        for name in LEGACY_STATE_FILES:
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(self.workspace.input_path, name))

    def _advisories_tmp_path(self) -> str:
        return self.advisories_path + ".tmp"

    def _download_archive(self, archive_url: str) -> None:
        archive_name = archive_url.rsplit("/", 1)[-1]
        archive_path = os.path.join(self.workspace.input_path, archive_name)

        self.logger.info(f"downloading archive: {archive_url}")
        try:
            remote_mod = self._download_stream(archive_url, archive_path)

            # the downloaded archive supersedes the existing advisories tree, so
            # remove the tree before extracting to keep peak disk usage at one
            # tree plus the archive (instead of two trees plus the archive)
            if os.path.isdir(self.advisories_path):
                shutil.rmtree(self.advisories_path)

            self.logger.info("extracting archive")
            tmp_dir = self._advisories_tmp_path()
            extract(archive_path, tmp_dir)
            os.rename(tmp_dir, self.advisories_path)

            self.archive_mod_time = remote_mod or datetime.now(tz=UTC)
        finally:
            # always clean up the archive file to save disk space
            with contextlib.suppress(OSError):
                os.remove(archive_path)

    def _process_changes_and_deletions(self) -> None:
        self._apply_deletions()

        seen_files, years = self._collect_pending_changes()

        if not seen_files:
            self.logger.info("no changed files newer than archive")
            return

        self.logger.info(f"downloading {len(seen_files)} changed files")

        for year in years:
            os.makedirs(os.path.join(self.advisories_path, year), exist_ok=True)

        self._download_changed_files(seen_files)

    def _apply_deletions(self) -> None:
        with open(self._local_deletions_path(), newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                deleted_fragment = row[0]
                with contextlib.suppress(FileNotFoundError):
                    os.remove(os.path.join(self.advisories_path, deleted_fragment))

    def _collect_pending_changes(self) -> tuple[set[str], set[str]]:
        """Read changes.csv (newest first) and return (files, years) for entries newer than the archive."""
        seen_files: set[str] = set()
        years: set[str] = set()
        with open(self._local_changes_path(), newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                changed_file = row[0]
                change_date = datetime.fromisoformat(row[1])
                if self.archive_mod_time and change_date < self.archive_mod_time:
                    break
                seen_files.add(changed_file)
                years.add(changed_file.split("/")[0])

        return seen_files, years

    def _download_changed_files(self, seen_files: set[str]) -> None:
        """Download the given advisory fragments in parallel; failures are logged and retried next run."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._download_stream,
                    url=self.latest_url.replace("archive_latest.txt", changed_file),
                    path=os.path.join(self.advisories_path, changed_file),
                ): changed_file
                for changed_file in seen_files
            }
            concurrent.futures.wait(futures.keys())
            for future, changed_file in futures.items():
                if future.exception() is not None:
                    self.logger.warning(f"failed to download {changed_file}: {future.exception()}")
