from __future__ import annotations

import datetime
from types import SimpleNamespace

import pytest

from vunnel.providers.govulndb.go_release_dates import (
    GoReleaseDateLookupError,
    GoReleaseDateOverlay,
    _escape_module_path,
    _stdlib_version_to_tag,
    go_extra_candidates,
)


def test_stdlib_version_to_tag():
    assert _stdlib_version_to_tag("1.21.5") == "go1.21.5"
    assert _stdlib_version_to_tag("go1.21.5") == "go1.21.5"
    assert _stdlib_version_to_tag("1.27.0-rc.3") == "go1.27rc3"
    assert _stdlib_version_to_tag("1.20.0-beta.1") == "go1.20beta1"


def test_escape_module_path():
    assert _escape_module_path("github.com/Azure/azure-sdk-for-go") == "github.com/!azure/azure-sdk-for-go"


def test_lookup_module_uses_module_proxy_and_caches(monkeypatch):
    overlay = GoReleaseDateOverlay()
    calls = []

    def fake_get(url):
        calls.append(url)
        return SimpleNamespace(
            status_code=200,
            content=b'{"Time":"2023-08-01T17:46:51Z"}',
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert overlay.lookup("golang.org/x/image", "0.10.0") == datetime.date(2023, 8, 1)
    assert overlay.lookup("golang.org/x/image", "0.10.0") == datetime.date(2023, 8, 1)
    assert calls == ["https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info"]


def test_lookup_module_misses_on_not_found(monkeypatch):
    overlay = GoReleaseDateOverlay()

    def fake_get(url):
        return SimpleNamespace(
            status_code=404,
            content=b"not found",
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert overlay.lookup("golang.org/x/image", "0.10.0") is None


def test_lookup_stdlib_uses_go_release_tag_and_caches(monkeypatch):
    overlay = GoReleaseDateOverlay()
    calls = []

    def fake_get(url):
        calls.append(url)
        return SimpleNamespace(
            status_code=200,
            content=b')]}\'\n{"committer":{"time":"Tue Dec 05 18:12:56 2023 +0000"}}',
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert overlay.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)
    assert overlay.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.21.5?format=JSON"]


def test_lookup_raises_when_release_source_fails(monkeypatch):
    overlay = GoReleaseDateOverlay()

    def fake_get(url):
        raise GoReleaseDateLookupError(f"failed: {url}")

    monkeypatch.setattr(overlay, "_get", fake_get)

    with pytest.raises(GoReleaseDateLookupError):
        overlay.lookup("golang.org/x/image", "0.10.0")


def test_lookup_raises_when_release_source_returns_invalid_json(monkeypatch):
    overlay = GoReleaseDateOverlay()

    def fake_get(url):
        return SimpleNamespace(
            status_code=200,
            content=b"not json",
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    with pytest.raises(GoReleaseDateLookupError):
        overlay.lookup("golang.org/x/image", "0.10.0")


def test_go_extra_candidates_marks_release_date_accurate():
    class Overlay:
        def lookup(self, module, version):
            assert module == "stdlib"
            assert version == "1.21.5"
            return datetime.date(2023, 12, 5)

    candidates = go_extra_candidates(Overlay())

    assert candidates is not None
    results = candidates("GO-2023-9999", "stdlib", "1.21.5", "Go")

    assert len(results) == 1
    assert results[0].date == datetime.date(2023, 12, 5)
    assert results[0].kind == "go-release"
    assert results[0].accurate is True


def test_go_extra_candidates_returns_empty_when_lookup_misses():
    class Overlay:
        def lookup(self, module, version):
            return None

    candidates = go_extra_candidates(Overlay())

    assert candidates is not None
    assert candidates("GO-2023-9999", "stdlib", "1.21.5", "Go") == []
