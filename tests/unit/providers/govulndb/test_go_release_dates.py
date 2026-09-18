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
    is_go_maintained,
)
from vunnel.providers.govulndb.go_release_dates_data import GO_RELEASE_DATES


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.21.5", "go1.21.5"),
        ("go1.21.5", "go1.21.5"),
        ("1.25.13", "go1.25.13"),
        ("1.27.0-rc.3", "go1.27rc3"),
        ("1.20.0-beta.1", "go1.20beta1"),
        # go only started tagging goX.Y.0 at go1.21.0; the 1.20 series has no go1.20.0
        ("1.20.0", "go1.20"),
        ("1.19.0", "go1.19"),
        ("1.21.0", "go1.21.0"),
        ("1.24.0", "go1.24.0"),
    ],
)
def test_stdlib_version_to_tag(version, expected):
    assert _stdlib_version_to_tag(version) == expected


@pytest.mark.parametrize(
    "module,expected",
    [
        ("stdlib", True),
        ("toolchain", True),
        ("golang.org/x/net", True),
        ("golang.org/x/crypto", True),
        ("github.com/golang/glog", False),
        ("github.com/mattermost/mattermost-server", False),
        ("k8s.io/kubernetes", False),
        ("", False),
    ],
)
def test_is_go_maintained(module, expected):
    assert is_go_maintained(module) is expected


def test_lookup_skips_third_party_modules(monkeypatch):
    """Third-party release dates are dropped downstream, so we never pay for the lookup."""
    overlay = GoReleaseDateOverlay()

    def fail(url):
        raise AssertionError(f"unexpected lookup for {url}")

    monkeypatch.setattr(overlay, "_get", fail)

    assert overlay.lookup("github.com/mattermost/mattermost-server", "9.11.14+incompatible") is None
    assert overlay.lookup("k8s.io/kubernetes", "1.29.4") is None


def test_stdlib_and_toolchain_share_a_single_fetch(monkeypatch):
    """Both module names share a release tag, so fetch it once.

    Uses a version past the committed table, since released ones never fetch.
    """
    overlay = GoReleaseDateOverlay()
    calls = []

    def fake_get(url):
        calls.append(url)
        return SimpleNamespace(
            status_code=200,
            content=b')]}\'\n{"committer":{"time":"Tue Dec 05 18:12:56 2023 +0000"}}',
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert overlay.lookup("toolchain", "1.99.0") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]


def test_lookup_caches_misses(monkeypatch):
    overlay = GoReleaseDateOverlay()
    calls = []

    def fake_get(url):
        calls.append(url)
        return SimpleNamespace(status_code=404, content=b"not found")

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert len(calls) == 1


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
    """The gitiles fallback (versions past the committed table) is fetched once."""
    overlay = GoReleaseDateOverlay()
    calls = []

    def fake_get(url):
        calls.append(url)
        return SimpleNamespace(
            status_code=200,
            content=b')]}\'\n{"committer":{"time":"Tue Dec 05 18:12:56 2023 +0000"}}',
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]


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


def test_committed_table_is_well_formed():
    assert len(GO_RELEASE_DATES) > 350

    for tag, released in GO_RELEASE_DATES.items():
        assert tag.startswith("go1"), f"unexpected tag {tag!r}"
        # raises if not a real ISO date
        parsed = datetime.date.fromisoformat(released)
        assert datetime.date(2009, 1, 1) < parsed < datetime.date(2100, 1, 1), f"{tag} -> {released}"


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.19.2", datetime.date(2022, 10, 4)),
        ("1.21.5", datetime.date(2023, 12, 5)),
        # the 1.20 series has no go1.20.0 tag; go1.20 shipped 2023-02-01
        ("1.20.0", datetime.date(2023, 2, 1)),
        ("1.24.0", datetime.date(2025, 2, 11)),
        ("1.21.0-rc.4", datetime.date(2023, 8, 2)),
    ],
)
def test_stdlib_release_dates_come_from_the_committed_table(monkeypatch, version, expected):
    """Releases already out never hit the network -- the answer can't change."""
    overlay = GoReleaseDateOverlay()

    def fail(url):
        raise AssertionError(f"unexpected request for {url}")

    monkeypatch.setattr(overlay, "_get", fail)

    assert overlay.lookup("stdlib", version) == expected
    assert overlay.lookup("toolchain", version) == expected


def test_stdlib_falls_back_to_the_mirror_for_releases_newer_than_the_table(monkeypatch):
    overlay = GoReleaseDateOverlay()
    calls = []

    def fake_get(url):
        calls.append(url)
        return SimpleNamespace(
            status_code=200,
            content=b')]}\'\n{"committer":{"time":"Tue Dec 05 18:12:56 2023 +0000"}}',
        )

    monkeypatch.setattr(overlay, "_get", fake_get)

    assert "go1.99.0" not in GO_RELEASE_DATES
    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]
