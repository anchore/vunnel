from __future__ import annotations

import concurrent.futures
import contextlib
import csv
import email.utils
import os
import shutil
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import requests

from vunnel.utils import http_wrapper as http
from vunnel.utils.archive import extract

if TYPE_CHECKING:
    import logging

    from vunnel.workspace import Workspace

VEX_FEED_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/vex-feed/archive_latest.txt"

TIMESTAMP_FILE = "archive_timestamp.txt"
CHANGES_TIMESTAMP_FILE = "changes_timestamp.txt"

ARCHIVE_SUFFIXES = (".tar", ".tar.zst", ".tar.gz", ".tar.xz", ".tar.bz2")


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
            self._load_timestamp()
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

    def _timestamp_path(self) -> str:
        return os.path.join(self.workspace.input_path, TIMESTAMP_FILE)

    def _changes_timestamp_path(self) -> str:
        return os.path.join(self.workspace.input_path, CHANGES_TIMESTAMP_FILE)

    def _local_changes_path(self) -> str:
        return os.path.join(self.workspace.input_path, "changes.csv")

    def _local_deletions_path(self) -> str:
        return os.path.join(self.workspace.input_path, "deletions.csv")

    # ── timestamp persistence ─────────────────────────────────────────

    def _load_timestamp(self) -> None:
        ts_path = self._timestamp_path()
        if os.path.exists(ts_path):
            with open(ts_path) as fh:
                self.archive_mod_time = datetime.fromisoformat(fh.read().strip())
            self.logger.debug(f"loaded archive timestamp: {self.archive_mod_time}")

    def _save_timestamp(self, mod_time: datetime) -> None:
        self.archive_mod_time = mod_time
        with open(self._timestamp_path(), "w") as fh:
            fh.write(mod_time.isoformat())

    def _load_changes_timestamp(self) -> datetime | None:
        ts_path = self._changes_timestamp_path()
        if os.path.exists(ts_path):
            with open(ts_path) as fh:
                return datetime.fromisoformat(fh.read().strip())
        return None

    def _save_changes_timestamp(self, mod_time: datetime) -> None:
        with open(self._changes_timestamp_path(), "w") as fh:
            fh.write(mod_time.isoformat())

    def _clear_changes_timestamp(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.remove(self._changes_timestamp_path())

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

    def _head_last_modified(self, url: str) -> datetime | None:
        """HEAD the URL and return Last-Modified as a tz-aware datetime, or None."""
        resp = requests.head(url, timeout=30)
        resp.raise_for_status()
        lm = resp.headers.get("Last-Modified")
        if lm:
            return email.utils.parsedate_to_datetime(lm)
        return None

    # ── core sync logic ───────────────────────────────────────────────

    def _sync(self) -> None:
        os.makedirs(self.advisories_path, exist_ok=True)
        self._remove_stray_files()

        archive_url = self._archive_url()
        self._load_timestamp()

        # decide whether we need to (re-)download the archive
        need_download = False
        if self.archive_mod_time is None:
            self.logger.info("no local timestamp found - downloading archive")
            need_download = True
        else:
            remote_mod = self._head_last_modified(archive_url)
            if remote_mod and remote_mod > self.archive_mod_time:
                self.logger.info(f"remote archive is newer ({remote_mod}) than local ({self.archive_mod_time}) - re-downloading")
                need_download = True
            else:
                self.logger.info("archive is up to date")

        if need_download:
            self._download_archive(archive_url)

        # always apply incremental updates
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

    def _advisories_tmp_path(self) -> str:
        return self.advisories_path + ".tmp"

    def _download_archive(self, archive_url: str) -> None:
        archive_name = archive_url.rsplit("/", 1)[-1]
        archive_path = os.path.join(self.workspace.input_path, archive_name)

        self.logger.info(f"downloading archive: {archive_url}")
        try:
            remote_mod = self._download_stream(archive_url, archive_path)

            # extract to a temp dir and swap so a failed extraction can't
            # destroy the existing advisories tree
            self.logger.info("extracting archive")
            tmp_dir = self._advisories_tmp_path()
            extract(archive_path, tmp_dir)

            if os.path.isdir(self.advisories_path):
                shutil.rmtree(self.advisories_path)
            os.rename(tmp_dir, self.advisories_path)

            self._save_timestamp(remote_mod or datetime.now(tz=UTC))
            # the new tree supersedes any previously applied changes
            self._clear_changes_timestamp()
        finally:
            # always clean up the archive file to save disk space
            with contextlib.suppress(OSError):
                os.remove(archive_path)

    def _process_changes_and_deletions(self) -> None:
        self._apply_deletions()

        seen_files, years, newest_change = self._collect_pending_changes()

        if not seen_files:
            self.logger.info("no changed files newer than archive")
            return

        self.logger.info(f"downloading {len(seen_files)} changed files")

        for year in years:
            os.makedirs(os.path.join(self.advisories_path, year), exist_ok=True)

        any_failed = self._download_changed_files(seen_files)

        # only advance the watermark when everything landed, so failed files are retried next run
        if not any_failed and newest_change:
            self._save_changes_timestamp(newest_change)

    def _apply_deletions(self) -> None:
        with open(self._local_deletions_path(), newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                deleted_fragment = row[0]
                with contextlib.suppress(FileNotFoundError):
                    os.remove(os.path.join(self.advisories_path, deleted_fragment))

    def _collect_pending_changes(self) -> tuple[set[str], set[str], datetime | None]:
        """Read changes.csv (newest first) and return (files, years, newest change date) not yet applied."""
        # skip changes already applied by a previous run (the watermark), falling
        # back to the archive timestamp when no changes have been applied yet
        watermark = self.archive_mod_time
        changes_applied = self._load_changes_timestamp()
        if changes_applied and (watermark is None or changes_applied > watermark):
            watermark = changes_applied

        seen_files: set[str] = set()
        years: set[str] = set()
        newest_change: datetime | None = None
        with open(self._local_changes_path(), newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                changed_file = row[0]
                date_str = row[1]
                change_date = datetime.fromisoformat(date_str)
                if watermark and change_date < watermark:
                    break
                if newest_change is None or change_date > newest_change:
                    newest_change = change_date
                seen_files.add(changed_file)
                year = changed_file.split("/")[0]
                years.add(year)

        return seen_files, years, newest_change

    def _download_changed_files(self, seen_files: set[str]) -> bool:
        """Download the given advisory fragments in parallel, returning True if any failed."""
        any_failed = False
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
                    any_failed = True
                    self.logger.warning(f"failed to download {changed_file}: {future.exception()}")
        return any_failed
