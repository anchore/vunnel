from __future__ import annotations

import io
import logging
import os
import tarfile
from datetime import datetime
from pathlib import Path

import pytest
import zstandard

from vunnel.providers.hummingbird import csaf_client
from vunnel.providers.hummingbird.csaf_client import CSAFVEXClient

FEED_BASE = "https://example.com/feed"
FEED_URL = f"{FEED_BASE}/archive_latest.txt"
ARCHIVE_NAME = "vex-archive.tar.zst"
ARCHIVE_URL = f"{FEED_BASE}/{ARCHIVE_NAME}"
CHANGES_URL = f"{FEED_BASE}/changes.csv"
DELETIONS_URL = f"{FEED_BASE}/deletions.csv"

ARCHIVE_LAST_MODIFIED = "Fri, 03 Jul 2026 00:00:00 GMT"
ARCHIVE_MOD_TIME = datetime.fromisoformat("2026-07-03T00:00:00+00:00")


class FakeWorkspace:
    def __init__(self, tmp_path: Path):
        self.input_path = str(tmp_path / "input")
        os.makedirs(self.input_path, exist_ok=True)


class FakeResponse:
    def __init__(self, content: bytes, headers: dict[str, str] | None = None):
        self.content = content
        self.headers = headers or {}

    @property
    def text(self) -> str:
        return self.content.decode()

    def iter_content(self, chunk_size: int = 65536):
        yield self.content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def tar_zst_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return zstandard.ZstdCompressor().compress(buf.getvalue())


def serve(monkeypatch, responses: dict, requested: list[str] | None = None) -> None:
    """Fake http.get: responses maps url -> bytes | (bytes, headers) | Exception."""

    def fake_get(url, logger=None, stream=False, **kwargs):
        if requested is not None:
            requested.append(url)
        if url not in responses:
            raise AssertionError(f"unexpected request: {url}")
        entry = responses[url]
        if isinstance(entry, Exception):
            raise entry
        content, headers = entry if isinstance(entry, tuple) else (entry, {})
        return FakeResponse(content, headers)

    monkeypatch.setattr(csaf_client.http, "get", fake_get)


def serve_head(monkeypatch, last_modified: str | None) -> None:
    class HeadResponse:
        headers = {"Last-Modified": last_modified} if last_modified else {}

        def raise_for_status(self):
            pass

    monkeypatch.setattr(csaf_client.requests, "head", lambda *a, **k: HeadResponse())


def forbid_head(monkeypatch) -> None:
    def fail(*a, **k):
        raise AssertionError("unexpected HEAD request")

    monkeypatch.setattr(csaf_client.requests, "head", fail)


def make_client(workspace: FakeWorkspace) -> CSAFVEXClient:
    return CSAFVEXClient(workspace=workspace, logger=logging.getLogger("test"), latest_url=FEED_URL)


def write_input(workspace: FakeWorkspace, name: str, content: str = "") -> str:
    path = os.path.join(workspace.input_path, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    return path


def advisory_path(workspace: FakeWorkspace, fragment: str) -> str:
    return os.path.join(workspace.input_path, "advisories", fragment)


BASE_RESPONSES = {
    FEED_URL: ARCHIVE_NAME.encode(),
    CHANGES_URL: b"",
    DELETIONS_URL: b"",
}


class TestArchiveDownload:
    def test_first_run_downloads_and_extracts(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (tar_zst_bytes({"2026/cve-2026-0001.json": "{}"}), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        forbid_head(monkeypatch)  # no local timestamp means no staleness check is needed

        client = make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))
        assert client.archive_mod_time == ARCHIVE_MOD_TIME

    def test_timestamp_comes_from_get_response(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (tar_zst_bytes({"2026/cve-2026-0001.json": "{}"}), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        forbid_head(monkeypatch)

        make_client(ws)

        with open(os.path.join(ws.input_path, csaf_client.TIMESTAMP_FILE)) as fh:
            assert datetime.fromisoformat(fh.read().strip()) == ARCHIVE_MOD_TIME

    def test_archive_file_removed_after_extraction(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (tar_zst_bytes({"2026/cve-2026-0001.json": "{}"}), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        forbid_head(monkeypatch)

        make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, ARCHIVE_NAME))

    def test_up_to_date_archive_not_downloaded(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        requested: list[str] = []
        serve(monkeypatch, BASE_RESPONSES, requested)
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert ARCHIVE_URL not in requested
        assert CHANGES_URL in requested
        assert DELETIONS_URL in requested

    def test_newer_remote_archive_is_downloaded(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, "2026-06-01T00:00:00+00:00")
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (tar_zst_bytes({"2026/cve-2026-0001.json": "{}"}), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        client = make_client(ws)

        assert client.archive_mod_time == ARCHIVE_MOD_TIME
        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))


class TestFailureCleanup:
    def test_archive_removed_when_extraction_fails(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (b"not a zst archive", {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        forbid_head(monkeypatch)

        with pytest.raises(Exception):
            make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, ARCHIVE_NAME))
        assert not os.path.exists(os.path.join(ws.input_path, csaf_client.TIMESTAMP_FILE))

    def test_failed_extraction_preserves_existing_advisories(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, "2026-06-01T00:00:00+00:00")
        write_input(ws, "advisories/2025/cve-2025-0001.json", "{}")
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (b"not a zst archive", {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        with pytest.raises(Exception):
            make_client(ws)

        assert os.path.exists(advisory_path(ws, "2025/cve-2025-0001.json"))


class TestStrayFileCleanup:
    def test_stray_archives_and_partial_extractions_removed(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        write_input(ws, "leaked-archive.tar.zst", "stale bytes")
        write_input(ws, "advisories.tmp/2026/cve-2026-0001.json", "{}")
        serve(monkeypatch, BASE_RESPONSES)
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, "leaked-archive.tar.zst"))
        assert not os.path.exists(os.path.join(ws.input_path, "advisories.tmp"))

    def test_stray_cleanup_keeps_other_input_files(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        write_input(ws, "advisories/2026/cve-2026-0001.json", "{}")
        serve(monkeypatch, BASE_RESPONSES)
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))
        assert os.path.exists(os.path.join(ws.input_path, csaf_client.TIMESTAMP_FILE))


class TestChangesAndDeletions:
    def test_changes_newer_than_archive_downloaded(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        changes = b"2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n2026/cve-2026-0001.json,2026-07-01T00:00:00+00:00\n"
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                CHANGES_URL: changes,
                f"{FEED_BASE}/2026/cve-2026-0002.json": b"{}",
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0002.json"))
        assert not os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))

    def test_watermark_saved_after_changes_applied(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        changes = b"2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n"
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                CHANGES_URL: changes,
                f"{FEED_BASE}/2026/cve-2026-0002.json": b"{}",
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        with open(os.path.join(ws.input_path, csaf_client.CHANGES_TIMESTAMP_FILE)) as fh:
            assert datetime.fromisoformat(fh.read().strip()) == datetime.fromisoformat("2026-07-03T12:00:00+00:00")

    def test_watermark_skips_already_applied_changes(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        write_input(ws, csaf_client.CHANGES_TIMESTAMP_FILE, "2026-07-04T00:00:00+00:00")
        changes = b"2026/cve-2026-0003.json,2026-07-04T06:00:00+00:00\n2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n"
        requested: list[str] = []
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                CHANGES_URL: changes,
                f"{FEED_BASE}/2026/cve-2026-0003.json": b"{}",
            },
            requested,
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert f"{FEED_BASE}/2026/cve-2026-0003.json" in requested
        assert f"{FEED_BASE}/2026/cve-2026-0002.json" not in requested

    def test_watermark_not_advanced_when_a_download_fails(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        changes = b"2026/cve-2026-0003.json,2026-07-04T06:00:00+00:00\n2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n"
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                CHANGES_URL: changes,
                f"{FEED_BASE}/2026/cve-2026-0003.json": b"{}",
                f"{FEED_BASE}/2026/cve-2026-0002.json": RuntimeError("boom"),
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, csaf_client.CHANGES_TIMESTAMP_FILE))

    def test_archive_refresh_resets_watermark(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, "2026-06-01T00:00:00+00:00")
        # a stale watermark newer than the fresh archive must not mask changes since that archive
        write_input(ws, csaf_client.CHANGES_TIMESTAMP_FILE, "2026-07-04T00:00:00+00:00")
        changes = b"2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n"
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (tar_zst_bytes({"2026/cve-2026-0001.json": "{}"}), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
                CHANGES_URL: changes,
                f"{FEED_BASE}/2026/cve-2026-0002.json": b"{}",
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0002.json"))
        with open(os.path.join(ws.input_path, csaf_client.CHANGES_TIMESTAMP_FILE)) as fh:
            assert datetime.fromisoformat(fh.read().strip()) == datetime.fromisoformat("2026-07-03T12:00:00+00:00")

    def test_archive_refresh_replaces_advisory_tree(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, "2026-06-01T00:00:00+00:00")
        write_input(ws, "advisories/2025/cve-2025-0001.json", "{}")
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                ARCHIVE_URL: (tar_zst_bytes({"2026/cve-2026-0001.json": "{}"}), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))
        assert not os.path.exists(advisory_path(ws, "2025/cve-2025-0001.json"))

    def test_deletions_remove_files(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, csaf_client.TIMESTAMP_FILE, ARCHIVE_MOD_TIME.isoformat())
        write_input(ws, "advisories/2026/cve-2026-0009.json", "{}")
        serve(
            monkeypatch,
            {
                **BASE_RESPONSES,
                DELETIONS_URL: b"2026/cve-2026-0009.json\n",
            },
        )
        serve_head(monkeypatch, ARCHIVE_LAST_MODIFIED)

        make_client(ws)

        assert not os.path.exists(advisory_path(ws, "2026/cve-2026-0009.json"))
