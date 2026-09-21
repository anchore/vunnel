from __future__ import annotations

import logging
import os

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import IncompleteRead, ProtocolError

from vunnel.utils import http_wrapper as http

BODY = bytes(range(256)) * 400  # 102,400 bytes of non-uniform content
URL = "https://origin.example/archive.tar.bz2"


@pytest.fixture(autouse=True)
def reset_registry():
    http._reset_for_testing()
    yield
    http._reset_for_testing()


@pytest.fixture
def logger():
    return logging.getLogger("test-download")


def read_bytes(path) -> bytes:
    """Read a file and close it.

    Kept out of the assert expressions themselves: a call inlined there leaks the handle
    until GC, and the whole expression vanishes under `python -O`.
    """
    with open(path, "rb") as fh:
        return fh.read()


class FakeRaw:
    """Stands in for urllib3's response body.

    `requests.iter_content` calls `raw.stream(...)` and turns a urllib3 ProtocolError
    into ChunkedEncodingError, so raising from here reproduces the failure that took out
    a provider run in CI: a connection dropped partway through the body.
    """

    def __init__(self, payload: bytes, fail_after: int | None = None):
        self.payload = payload
        self.fail_after = fail_after

    def stream(self, amt, decode_content=True):
        limit = len(self.payload) if self.fail_after is None else self.fail_after
        sent = 0
        while sent < len(self.payload):
            if sent >= limit:
                raise ProtocolError("Connection broken: IncompleteRead", IncompleteRead(sent, len(self.payload) - sent))
            chunk = self.payload[sent : min(sent + amt, limit)]
            yield chunk
            sent += len(chunk)

    def close(self):
        pass

    def release_conn(self):
        pass


class Origin:
    def __init__(self) -> None:
        self.body = BODY
        self.requests: list[str] = []
        # request indices (0-based) that should hang up mid-body
        self.hang_up_on: set[int] = set()
        self.hang_up_after_bytes = 1024
        # request indices (0-based) that should come back rate-limited instead of succeeding
        self.rate_limit_on: set[int] = set()
        self.retry_after_seconds = 30

    def respond(self, request: requests.PreparedRequest) -> requests.Response:
        index = len(self.requests)
        self.requests.append(request.url)

        response = requests.Response()
        response.url = request.url
        response.request = request

        if index in self.rate_limit_on:
            response.status_code = 429
            response.headers = CaseInsensitiveDict({"Retry-After": str(self.retry_after_seconds)})
            return response

        response.status_code = 200
        response.headers = CaseInsensitiveDict({"Content-Length": str(len(self.body)), "Last-Modified": "Fri, 18 Sep 2026 01:53:43 GMT"})
        response.raw = FakeRaw(self.body, fail_after=self.hang_up_after_bytes if index in self.hang_up_on else None)
        return response


class FakeAdapter(BaseAdapter):
    def __init__(self, origin: Origin):
        super().__init__()
        self.origin = origin

    def send(self, request, **kwargs):
        return self.origin.respond(request)

    def close(self):
        pass


@pytest.fixture
def origin():
    origin = Origin()
    # mount onto the session download_to_file will pull from the registry
    http._get_registry().get_state("origin.example").session.mount("https://", FakeAdapter(origin))
    return origin


def download(dest, logger, **kwargs):
    kwargs.setdefault("backoff_in_seconds", 0)
    return http.download_to_file(URL, dest, logger, **kwargs)


class TestMisuse:
    def test_rejects_status_handler(self, origin, tmp_path, logger):
        """A status_handler that accepts a non-2xx response would have its body written
        to dest and published as if it were a valid download - not supported."""
        dest = str(tmp_path / "archive.tar.bz2")

        with pytest.raises(TypeError, match="status_handler"):
            download(dest, logger, status_handler=lambda response: None)


class TestDownload:
    def test_downloads_and_publishes_atomically(self, origin, tmp_path, logger):
        dest = str(tmp_path / "archive.tar.bz2")

        response = download(dest, logger)

        downloaded = read_bytes(dest)
        assert downloaded == BODY
        assert response.headers["Last-Modified"] == "Fri, 18 Sep 2026 01:53:43 GMT"
        # the staging file must not survive a successful download
        assert not os.path.exists(dest + ".part")

    def test_creates_missing_parent_directory(self, origin, tmp_path, logger):
        dest = str(tmp_path / "nested" / "deeper" / "archive.tar.bz2")

        download(dest, logger)

        downloaded = read_bytes(dest)
        assert downloaded == BODY


class TestRetry:
    def test_retries_a_disconnect_partway_through_the_body(self, origin, tmp_path, logger):
        """The whole point: `get(stream=True)` returns once headers arrive, so a body
        that dies mid-transfer used to get no retries at all."""
        dest = str(tmp_path / "archive.tar.bz2")
        origin.hang_up_on = {0}

        download(dest, logger, retries=3)

        downloaded = read_bytes(dest)
        assert downloaded == BODY
        assert len(origin.requests) == 2

    def test_retries_repeatedly(self, origin, tmp_path, logger):
        dest = str(tmp_path / "archive.tar.bz2")
        origin.hang_up_on = {0, 1, 2}

        download(dest, logger, retries=5)

        downloaded = read_bytes(dest)
        assert downloaded == BODY
        assert len(origin.requests) == 4

    def test_exhausted_retries_reraise_without_publishing(self, origin, tmp_path, logger):
        dest = str(tmp_path / "archive.tar.bz2")
        origin.hang_up_on = set(range(50))  # never succeeds

        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            download(dest, logger, retries=2)

        assert len(origin.requests) == 3  # retries + 1
        # a failed download must leave nothing behind for the next run to trip over
        assert not os.path.exists(dest)
        assert not os.path.exists(dest + ".part")


class TestRateLimit:
    def test_honors_retry_after_instead_of_its_own_backoff(self, origin, tmp_path, logger, monkeypatch):
        """download_to_file forces its inner get() call to retries=0, so a rate-limited
        response is always get()'s "no retries left" case. That must still record the
        rate limit (so the next attempt's acquire_slot waits on it) rather than silently
        falling through to download_to_file's own backoff, which knows nothing about
        Retry-After and would otherwise hammer a host that just asked to be left alone."""
        dest = str(tmp_path / "archive.tar.bz2")
        origin.rate_limit_on = {0}
        origin.retry_after_seconds = 47  # far outside backoff_in_seconds=0's range below

        sleeps: list[float] = []
        monkeypatch.setattr(http.time, "sleep", lambda seconds: sleeps.append(seconds))

        download(dest, logger, retries=1, backoff_in_seconds=0)

        downloaded = read_bytes(dest)
        assert downloaded == BODY
        assert len(origin.requests) == 2
        # the wait must come from Retry-After (~47s), not download_to_file's own ~0s backoff
        assert any(s >= 40 for s in sleeps), f"expected a Retry-After-driven wait, got {sleeps}"


class TestStaging:
    def test_stages_in_the_destination_directory(self, origin, tmp_path, logger):
        """Publishing is an os.replace, which fails with EXDEV across filesystems.

        In CI the workspace and the system temp dir are routinely different volumes, so
        staging anywhere but the destination's own directory would turn every completed
        download into a crash.
        """
        dest_dir = tmp_path / "workspace" / "input"
        dest = str(dest_dir / "archive.tar.bz2")
        origin.hang_up_on = {0}

        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            download(dest, logger, retries=0)

        # nothing published, and nothing staged outside the destination directory
        assert not os.path.exists(dest)
        assert sorted(p.name for p in dest_dir.iterdir()) == []

    def test_publish_is_a_same_directory_rename(self, origin, tmp_path, logger, monkeypatch):
        dest = str(tmp_path / "archive.tar.bz2")
        renames: list[tuple[str, str]] = []
        real_replace = os.replace

        def record(src, dst, *args, **kwargs):
            renames.append((str(src), str(dst)))
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(http.os, "replace", record)

        download(dest, logger)

        assert renames, "expected the download to be published via a rename"
        for src, dst in renames:
            assert os.path.dirname(src) == os.path.dirname(dst)
