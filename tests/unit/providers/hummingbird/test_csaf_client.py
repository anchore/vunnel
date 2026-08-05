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


def base_responses(archive_files: dict[str, str] | None = None) -> dict:
    if archive_files is None:
        archive_files = {"2026/cve-2026-0001.json": "{}"}
    return {
        FEED_URL: ARCHIVE_NAME.encode(),
        ARCHIVE_URL: (tar_zst_bytes(archive_files), {"Last-Modified": ARCHIVE_LAST_MODIFIED}),
        CHANGES_URL: b"",
        DELETIONS_URL: b"",
    }


class TestArchiveDownload:
    def test_downloads_and_extracts(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(monkeypatch, base_responses())

        client = make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))
        assert client.archive_mod_time == ARCHIVE_MOD_TIME

    def test_archive_downloaded_every_run(self, tmp_path, monkeypatch):
        # stateless: even with a fully populated advisories tree the archive is
        # always re-downloaded and the tree is rebuilt from it
        ws = FakeWorkspace(tmp_path)
        write_input(ws, "advisories/2025/cve-2025-0001.json", "{}")
        requested: list[str] = []
        serve(monkeypatch, base_responses(), requested)

        make_client(ws)

        assert ARCHIVE_URL in requested
        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))
        assert not os.path.exists(advisory_path(ws, "2025/cve-2025-0001.json"))

    def test_archive_file_removed_after_extraction(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(monkeypatch, base_responses())

        make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, ARCHIVE_NAME))

    def test_no_state_files_written(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        serve(monkeypatch, base_responses())

        make_client(ws)

        for name in csaf_client.LEGACY_STATE_FILES:
            assert not os.path.exists(os.path.join(ws.input_path, name))


class TestFailureCleanup:
    def test_archive_removed_when_extraction_fails(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        responses = base_responses()
        responses[ARCHIVE_URL] = (b"not a zst archive", {"Last-Modified": ARCHIVE_LAST_MODIFIED})
        serve(monkeypatch, responses)

        with pytest.raises(Exception):
            make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, ARCHIVE_NAME))

    def test_failed_extraction_recovers_on_next_run(self, tmp_path, monkeypatch):
        # a failed extraction may leave no advisories tree behind, but the next
        # run re-downloads the archive unconditionally and rebuilds it
        ws = FakeWorkspace(tmp_path)
        write_input(ws, "advisories/2025/cve-2025-0001.json", "{}")
        responses = base_responses()
        responses[ARCHIVE_URL] = (b"not a zst archive", {"Last-Modified": ARCHIVE_LAST_MODIFIED})
        serve(monkeypatch, responses)

        with pytest.raises(Exception):
            make_client(ws)

        serve(monkeypatch, base_responses())

        client = make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0001.json"))
        assert client.archive_mod_time == ARCHIVE_MOD_TIME


class TestStrayFileCleanup:
    def test_stray_archives_and_partial_extractions_removed(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        write_input(ws, "leaked-archive.tar.zst", "stale bytes")
        write_input(ws, "advisories.tmp/2026/cve-2026-0001.json", "{}")
        serve(monkeypatch, base_responses())

        make_client(ws)

        assert not os.path.exists(os.path.join(ws.input_path, "leaked-archive.tar.zst"))
        assert not os.path.exists(os.path.join(ws.input_path, "advisories.tmp"))

    def test_legacy_state_files_removed(self, tmp_path, monkeypatch):
        # timestamp files from the previous incremental flow linger in cached
        # workspaces; they must be scrubbed so they don't persist forever
        ws = FakeWorkspace(tmp_path)
        for name in csaf_client.LEGACY_STATE_FILES:
            write_input(ws, name, "2026-06-01T00:00:00+00:00")
        serve(monkeypatch, base_responses())

        make_client(ws)

        for name in csaf_client.LEGACY_STATE_FILES:
            assert not os.path.exists(os.path.join(ws.input_path, name))


class TestChangesAndDeletions:
    def test_changes_newer_than_archive_downloaded(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        changes = b"2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n2026/cve-2026-0001.json,2026-07-01T00:00:00+00:00\n"
        responses = base_responses(archive_files={"2026/cve-2026-9999.json": "{}"})
        responses[CHANGES_URL] = changes
        responses[f"{FEED_BASE}/2026/cve-2026-0002.json"] = b"{}"
        requested: list[str] = []
        serve(monkeypatch, responses, requested)

        make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0002.json"))
        assert f"{FEED_BASE}/2026/cve-2026-0001.json" not in requested

    def test_changes_reapplied_every_run(self, tmp_path, monkeypatch):
        # stateless: there is no watermark, so all changes since the archive was
        # baked are re-downloaded on every run
        ws = FakeWorkspace(tmp_path)
        changes = b"2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n"
        responses = base_responses(archive_files={"2026/cve-2026-9999.json": "{}"})
        responses[CHANGES_URL] = changes
        responses[f"{FEED_BASE}/2026/cve-2026-0002.json"] = b"{}"
        requested: list[str] = []
        serve(monkeypatch, responses, requested)

        make_client(ws)
        make_client(ws)

        assert requested.count(f"{FEED_BASE}/2026/cve-2026-0002.json") == 2

    def test_failed_change_download_does_not_fail_run(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        changes = b"2026/cve-2026-0003.json,2026-07-04T06:00:00+00:00\n2026/cve-2026-0002.json,2026-07-03T12:00:00+00:00\n"
        responses = base_responses(archive_files={"2026/cve-2026-9999.json": "{}"})
        responses[CHANGES_URL] = changes
        responses[f"{FEED_BASE}/2026/cve-2026-0003.json"] = b"{}"
        responses[f"{FEED_BASE}/2026/cve-2026-0002.json"] = RuntimeError("boom")
        serve(monkeypatch, responses)

        make_client(ws)

        assert os.path.exists(advisory_path(ws, "2026/cve-2026-0003.json"))
        assert not os.path.exists(advisory_path(ws, "2026/cve-2026-0002.json"))

    def test_deletions_remove_files(self, tmp_path, monkeypatch):
        ws = FakeWorkspace(tmp_path)
        responses = base_responses(archive_files={"2026/cve-2026-0009.json": "{}"})
        responses[DELETIONS_URL] = b"2026/cve-2026-0009.json\n"
        serve(monkeypatch, responses)

        make_client(ws)

        assert not os.path.exists(advisory_path(ws, "2026/cve-2026-0009.json"))
