from __future__ import annotations

import datetime
import logging
from types import SimpleNamespace

import pytest
import requests
from vunnel.providers.govulndb.go_release_dates import (
    GoReleaseDateOverlay,
    _escape_module_path,
    _module_info_url,
    _stdlib_version_to_tag,
    go_extra_candidates,
    is_go_maintained,
    should_resolve,
)
from vunnel.providers.govulndb.go_release_dates_data import GO_RELEASE_DATES

GITILES_BODY = b')]}\'\n{"committer":{"time":"Tue Dec 05 18:12:56 2023 +0000"}}'


def response(status_code=200, content=b"{}"):
    return SimpleNamespace(status_code=status_code, content=content)


@pytest.fixture
def overlay():
    return GoReleaseDateOverlay(logger=logging.getLogger("test"))


def stub_http(monkeypatch, handler):
    """Replace the http layer the overlay calls, recording the urls requested."""
    calls = []

    def fake_get(url, logger, **kwargs):
        calls.append(url)
        return handler(url)

    monkeypatch.setattr("vunnel.providers.govulndb.go_release_dates.http.get", fake_get)
    return calls


def no_http(monkeypatch):
    def fail(url, logger, **kwargs):
        raise AssertionError(f"unexpected request for {url}")

    monkeypatch.setattr("vunnel.providers.govulndb.go_release_dates.http.get", fail)


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
        # govulndb's semver floor: "every 1.21 prerelease and later". Go tags no such
        # release, and building one anyway produced the bogus tag "go1.210".
        ("1.21.0-0", None),
        ("1.22.0-pre1", None),
        ("", None),
        ("not-a-version", None),
        ("../../etc/passwd", None),
    ],
)
def test_stdlib_version_to_tag(version, expected):
    assert _stdlib_version_to_tag(version) == expected


def test_stdlib_semver_floor_costs_no_request(overlay, monkeypatch):
    """A version naming no released artifact must not become a speculative fetch.

    GO-2024-2962 fixes `toolchain` at 1.21.0-0, which used to resolve to the tag
    "go1.210" and put a doomed request to go.googlesource.com in every run.
    """
    no_http(monkeypatch)
    assert overlay.lookup("toolchain", "1.21.0-0") is None


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


@pytest.mark.parametrize(
    "module,aliases,expected",
    [
        # go's own modules are always worth resolving, aliased or not
        ("stdlib", ["GHSA-xxxx-yyyy-zzzz"], True),
        ("toolchain", ["CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"], True),
        ("golang.org/x/net", ["GHSA-xxxx-yyyy-zzzz"], True),
        # a third-party module with a GHSA twin gets merged away downstream
        ("github.com/foo/bar", ["GHSA-xxxx-yyyy-zzzz"], False),
        ("github.com/foo/bar", ["CVE-2024-1234", "GHSA-xxxx-yyyy-zzzz"], False),
        ("github.com/foo/bar", ["ghsa-xxxx-yyyy-zzzz"], False),
        # ... but with no GHSA to merge into, its date is the one that ships
        ("github.com/foo/bar", [], True),
        ("github.com/foo/bar", None, True),
        ("github.com/foo/bar", ["CVE-2024-1234"], True),
        ("", [], False),
    ],
)
def test_should_resolve(module, aliases, expected):
    assert should_resolve(module, aliases) is expected


def test_stdlib_and_toolchain_share_a_single_fetch(overlay, monkeypatch):
    """Both module names share a release tag, so fetch it once.

    Uses a version past the committed table, since released ones never fetch.
    """
    calls = stub_http(monkeypatch, lambda url: response(content=GITILES_BODY))

    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert overlay.lookup("toolchain", "1.99.0") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]


def test_lookup_caches_misses(overlay, monkeypatch):
    calls = stub_http(monkeypatch, lambda url: response(status_code=404, content=b"not found"))

    assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert len(calls) == 1


def test_escape_module_path():
    assert _escape_module_path("github.com/Azure/azure-sdk-for-go") == "github.com/!azure/azure-sdk-for-go"


def test_lookup_module_uses_module_proxy_and_caches(overlay, monkeypatch):
    calls = stub_http(monkeypatch, lambda url: response(content=b'{"Time":"2023-08-01T17:46:51Z"}'))

    assert overlay.lookup("golang.org/x/image", "0.10.0") == datetime.date(2023, 8, 1)
    assert overlay.lookup("golang.org/x/image", "0.10.0") == datetime.date(2023, 8, 1)
    assert calls == ["https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info"]


def test_lookup_module_misses_on_not_found(overlay, monkeypatch):
    stub_http(monkeypatch, lambda url: response(status_code=404, content=b"not found"))
    assert overlay.lookup("golang.org/x/image", "0.10.0") is None


def test_lookup_stdlib_uses_go_release_tag_and_caches(overlay, monkeypatch):
    """The gitiles fallback (versions past the committed table) is fetched once."""
    calls = stub_http(monkeypatch, lambda url: response(content=GITILES_BODY))

    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]


# ---------------------------------------------------------------------------
# url construction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module,version,expected",
    [
        ("golang.org/x/image", "0.10.0", "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info"),
        ("golang.org/x/image", "v0.10.0", "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info"),
        (
            "github.com/Azure/azure-sdk-for-go",
            "68.0.0+incompatible",
            "https://proxy.golang.org/github.com/!azure/azure-sdk-for-go/@v/v68.0.0+incompatible.info",
        ),
        # the proxy's case encoding applies to the version too
        (
            "example.com/mod",
            "1.0.0-RC1",
            "https://proxy.golang.org/example.com/mod/@v/v1.0.0-!r!c1.info",
        ),
        (
            "github.com/bnb-chain/tss-lib",
            "1.3.6-0.20230324145555-bb6fb30bd3eb",
            "https://proxy.golang.org/github.com/bnb-chain/tss-lib/@v/v1.3.6-0.20230324145555-bb6fb30bd3eb.info",
        ),
    ],
)
def test_module_info_url(module, version, expected):
    assert _module_info_url(module, version) == expected


@pytest.mark.parametrize(
    "module,version",
    [
        # anything that could re-point the request is refused rather than escaped
        ("../../../etc/passwd", "1.0.0"),
        ("golang.org/x/../../evil", "1.0.0"),
        ("golang.org/x/image/./tiff", "1.0.0"),
        ("golang.org//x/image", "1.0.0"),
        ("evil.com/mod?x=1", "1.0.0"),
        ("evil.com/mod#frag", "1.0.0"),
        ("evil.com/mod%2e%2e", "1.0.0"),
        ("https://evil.com/mod", "1.0.0"),
        ("evil.com/mod\nHost: x", "1.0.0"),
        ("evil.com/mod ", "1.0.0"),
        ("/absolute/path", "1.0.0"),
        ("a" * 600, "1.0.0"),
        ("golang.org/x/image", "0.10.0/../../evil"),
        ("golang.org/x/image", "?format=JSON"),
        ("golang.org/x/image", "latest"),
        ("golang.org/x/image", ""),
    ],
)
def test_module_info_url_refuses_unsafe_input(module, version):
    assert _module_info_url(module, version) is None


def test_unsafe_module_costs_no_request(overlay, monkeypatch):
    no_http(monkeypatch)
    assert overlay.lookup("../../../etc/passwd", "1.0.0") is None


# ---------------------------------------------------------------------------
# failure handling: a missing date must never cost the run
# ---------------------------------------------------------------------------


def test_lookup_returns_none_when_the_host_is_down(overlay, monkeypatch, caplog):
    def boom(url, logger, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr("vunnel.providers.govulndb.go_release_dates.http.get", boom)

    with caplog.at_level(logging.WARNING):
        assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert "connection refused" in caplog.text


def test_lookup_returns_none_on_a_garbage_body(overlay, monkeypatch, caplog):
    stub_http(monkeypatch, lambda url: response(content=b"<html>503 from a proxy</html>"))

    with caplog.at_level(logging.WARNING):
        assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert "unparseable" in caplog.text


def test_lookup_returns_none_on_a_non_object_body(overlay, monkeypatch):
    stub_http(monkeypatch, lambda url: response(content=b"[1, 2, 3]"))
    assert overlay.lookup("golang.org/x/image", "0.10.0") is None


def test_lookup_returns_none_on_a_truncated_gitiles_guard(overlay, monkeypatch):
    """A body of only the XSS guard has no newline to split on."""
    stub_http(monkeypatch, lambda url: response(content=b")]}'"))
    assert overlay.lookup("stdlib", "1.99.0") is None


def test_lookup_returns_none_when_the_payload_has_no_time(overlay, monkeypatch):
    stub_http(monkeypatch, lambda url: response(content=b'{"Version":"v0.10.0"}'))
    assert overlay.lookup("golang.org/x/image", "0.10.0") is None


def test_failures_are_cached_so_a_dead_host_is_asked_once(overlay, monkeypatch):
    calls = stub_http(monkeypatch, lambda url: response(content=b"nope"))

    assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert overlay.lookup("golang.org/x/image", "0.10.0") is None
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# offline (skip_download)
# ---------------------------------------------------------------------------


def test_offline_serves_the_committed_table(monkeypatch):
    ov = GoReleaseDateOverlay(offline=True)
    no_http(monkeypatch)
    assert ov.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)


@pytest.mark.parametrize(
    "module,version",
    [
        ("stdlib", "1.99.0"),  # past the committed table -> would hit gitiles
        ("golang.org/x/image", "0.10.0"),  # would hit the module proxy
        ("github.com/foo/bar", "1.0.0"),
    ],
)
def test_offline_never_fetches(monkeypatch, module, version):
    ov = GoReleaseDateOverlay(offline=True)
    no_http(monkeypatch)
    assert ov.lookup(module, version) is None


# ---------------------------------------------------------------------------
# timezone normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "git_time,expected",
    [
        ("Tue Dec 05 18:12:56 2023 +0000", datetime.date(2023, 12, 5)),
        # a late-in-the-day release tagged from US Pacific is the next day in UTC
        ("Wed Mar 04 17:30:00 2026 -0800", datetime.date(2026, 3, 5)),
        ("Tue Feb 11 09:24:39 2025 -0800", datetime.date(2025, 2, 11)),
        ("not a git time", None),
        (None, None),
    ],
)
def test_gitiles_times_are_normalized_to_utc(overlay, monkeypatch, git_time, expected):
    payload = b'{"committer":{}}' if git_time is None else b')]}\'\n{"committer":{"time":"' + git_time.encode() + b'"}}'
    stub_http(monkeypatch, lambda url: response(content=payload))
    assert overlay.lookup("stdlib", "1.99.0") == expected


@pytest.mark.parametrize(
    "proxy_time,expected",
    [
        ("2023-08-01T17:46:51Z", datetime.date(2023, 8, 1)),
        ("2023-08-01T17:46:51-08:00", datetime.date(2023, 8, 2)),
        ("2023-08-01T00:30:00+05:30", datetime.date(2023, 7, 31)),
        ("garbage", None),
    ],
)
def test_proxy_times_are_normalized_to_utc(overlay, monkeypatch, proxy_time, expected):
    stub_http(monkeypatch, lambda url: response(content=b'{"Time":"' + proxy_time.encode() + b'"}'))
    assert overlay.lookup("golang.org/x/image", "0.10.0") == expected


# ---------------------------------------------------------------------------
# candidate wiring
# ---------------------------------------------------------------------------


def test_go_extra_candidates_marks_release_date_accurate():
    class Overlay:
        def lookup(self, module, version):
            assert module == "stdlib"
            assert version == "1.21.5"
            return datetime.date(2023, 12, 5)

    results = go_extra_candidates(Overlay())("GO-2023-9999", "stdlib", "1.21.5", "Go")

    assert len(results) == 1
    assert results[0].date == datetime.date(2023, 12, 5)
    assert results[0].kind == "release"
    assert results[0].accurate is True


def test_go_extra_candidates_returns_empty_when_lookup_misses():
    class Overlay:
        def lookup(self, module, version):
            return None

    assert go_extra_candidates(Overlay())("GO-2023-9999", "stdlib", "1.21.5", "Go") == []


def test_go_extra_candidates_skips_third_party_with_a_ghsa_twin():
    class Overlay:
        def lookup(self, module, version):
            raise AssertionError("should not have been asked")

    candidates = go_extra_candidates(Overlay(), ["CVE-2024-1234", "GHSA-8r3f-844c-mc37"])
    assert candidates("GO-2024-2611", "google.golang.org/protobuf", "1.33.0", "Go") == []


def test_go_extra_candidates_resolves_third_party_with_no_ghsa_twin():
    class Overlay:
        def lookup(self, module, version):
            return datetime.date(2024, 3, 5)

    candidates = go_extra_candidates(Overlay(), ["CVE-2024-1234"])
    results = candidates("GO-2024-2611", "google.golang.org/protobuf", "1.33.0", "Go")
    assert [r.date for r in results] == [datetime.date(2024, 3, 5)]


# ---------------------------------------------------------------------------
# the committed table
# ---------------------------------------------------------------------------


def test_committed_table_is_well_formed():
    assert len(GO_RELEASE_DATES) > 350

    for tag, released in GO_RELEASE_DATES.items():
        assert _stdlib_version_to_tag(tag) == tag, f"table key {tag!r} is not a tag the mapper produces"
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
        # tagged 2026-03-05 in US Pacific, which is 2026-03-06 UTC
        ("1.25.8", datetime.date(2026, 3, 6)),
    ],
)
def test_stdlib_release_dates_come_from_the_committed_table(overlay, monkeypatch, version, expected):
    """Releases already out never hit the network -- the answer can't change."""
    no_http(monkeypatch)

    assert overlay.lookup("stdlib", version) == expected
    assert overlay.lookup("toolchain", version) == expected


def test_stdlib_falls_back_to_the_mirror_for_releases_newer_than_the_table(overlay, monkeypatch):
    calls = stub_http(monkeypatch, lambda url: response(content=GITILES_BODY))

    assert "go1.99.0" not in GO_RELEASE_DATES
    assert overlay.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert calls == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]
