from __future__ import annotations

import datetime
import logging
import time
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
import requests
from vunnel.providers.govulndb import go_release_dates
from vunnel.providers.govulndb.go_module_release_dates_data import GO_MODULE_RELEASE_DATES
from vunnel.providers.govulndb.go_release_dates import (
    DEFAULT_TIMEOUT,
    ReleaseDateResolver,
    ReleaseDates,
    _escape_module_path,
    fixed_versions,
    go_extra_candidates,
    module_info_url,
    module_key,
    stdlib_version_to_tag,
)
from vunnel.providers.govulndb.go_release_dates_data import GO_RELEASE_DATES
from vunnel.utils import http_wrapper

GITILES_BODY = b')]}\'\n{"committer":{"time":"Tue Dec 05 18:12:56 2023 +0000"}}'
PROXY_BODY = b'{"Time":"2023-08-01T17:46:51Z"}'


class Forbidden(BaseException):
    """Not an Exception, so nothing in the resolver can swallow it and make a guard pass vacuously."""


class FakeResponse:
    def __init__(self, status_code=200, content=b"{}", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


def response(status_code=200, content=b"{}", headers=None):
    return FakeResponse(status_code, content, headers)


class FakeHTTP:
    """Stands in for http_wrapper.get with retries=0, recording every call with all its kwargs.

    Like the real wrapper it raises on a rate limit -- by the wrapper's own definition --
    before the caller sees the response, and otherwise runs the caller's status_handler,
    so what that handler lets through is what the resolver has to deal with.
    """

    def __init__(self, handler=None):
        self.handler = handler or (lambda url: response(status_code=404))
        self.calls = []

    def get(self, url, logger, **kwargs):
        self.calls.append(SimpleNamespace(url=url, kwargs=kwargs))
        result = self.handler(url)
        if isinstance(result, Exception):
            raise result
        if http_wrapper._is_rate_limited(result):
            result.raise_for_status()
        kwargs["status_handler"](result)
        return result

    def urls(self):
        return [c.url for c in self.calls]


@pytest.fixture
def fake_http(monkeypatch):
    def install(handler=None):
        fake = FakeHTTP(handler)
        monkeypatch.setattr(go_release_dates.http, "get", fake.get)
        return fake

    return install


@pytest.fixture
def no_network(monkeypatch):
    def forbidden(url, logger, **kwargs):
        raise Forbidden(f"unexpected request for {url}")

    monkeypatch.setattr(go_release_dates.http, "get", forbidden)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def resolver(**kwargs):
    kwargs.setdefault("stdlib_table", {})
    kwargs.setdefault("module_table", {})
    return ReleaseDateResolver(logger=logging.getLogger("test"), **kwargs)


def refused(url):
    return requests.exceptions.ConnectionError("connection refused")


# ---------------------------------------------------------------------------
# version and url construction
# ---------------------------------------------------------------------------


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
    assert stdlib_version_to_tag(version) == expected


def test_escape_module_path():
    assert _escape_module_path("github.com/Azure/azure-sdk-for-go") == "github.com/!azure/azure-sdk-for-go"


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
    assert module_info_url(module, version) == expected


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
        ("golang.org/x/image", "1.0.0-" + "a" * 200),
    ],
)
def test_module_info_url_refuses_unsafe_input(module, version):
    assert module_info_url(module, version) is None


def test_fixed_versions():
    records = [
        {
            "affected": [
                {
                    "package": {"name": "stdlib"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.21.5"}, {"introduced": "1.22.0"}, {"fixed": "1.22.1"}]}],
                },
                {"package": {"name": "golang.org/x/net"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.17.0"}]}]},
                # no fix, no name, garbage: all skipped
                {"package": {"name": "github.com/foo/bar"}, "ranges": [{"events": [{"introduced": "0"}]}]},
                {"package": {}, "ranges": [{"events": [{"fixed": "1.0.0"}]}]},
                {"package": {"name": "github.com/foo/baz"}, "ranges": [{"events": [{"fixed": 3}]}]},
            ],
        },
        {"affected": None},
        {},
    ]
    assert fixed_versions(records) == {("stdlib", "1.21.5"), ("stdlib", "1.22.1"), ("golang.org/x/net", "0.17.0")}


@pytest.mark.parametrize(
    "affected",
    [
        {"package": {"name": "example.com/m"}, "ranges": ["garbage"]},
        {"package": {"name": "example.com/m"}, "ranges": [{"events": ["garbage"]}]},
        {"package": {"name": "example.com/m"}, "ranges": [{"events": "garbage"}]},
        {"package": {"name": "example.com/m"}, "ranges": "garbage"},
        {"package": {"name": "example.com/m"}, "ranges": 3},
        {"package": {"name": "example.com/m"}, "ranges": [{"events": 3}]},
        {"package": "garbage"},
        "garbage",
    ],
    ids=[
        "range-not-a-dict",
        "event-not-a-dict",
        "events-not-a-list",
        "ranges-not-a-list",
        "ranges-an-int",
        "events-an-int",
        "package-not-a-dict",
        "affected-not-a-dict",
    ],
)
def test_fixed_versions_skips_malformed_shapes_instead_of_raising(affected):
    """This runs outside the parser's fallback, so a shape the record loop would tolerate
    (it skips entries with no ecosystem before looking at ranges) must not fail the run here."""
    good = {"affected": [{"package": {"name": "golang.org/x/net"}, "ranges": [{"events": [{"fixed": "0.17.0"}]}]}]}

    assert fixed_versions([{"affected": [affected]}, good]) == {("golang.org/x/net", "0.17.0")}


@pytest.mark.parametrize("record", [[], "garbage", None, {"affected": "garbage"}], ids=["list", "str", "null", "affected-not-a-list"])
def test_fixed_versions_skips_malformed_records(record):
    good = {"affected": [{"package": {"name": "golang.org/x/net"}, "ranges": [{"events": [{"fixed": "0.17.0"}]}]}]}

    assert fixed_versions([record, good]) == {("golang.org/x/net", "0.17.0")}


# ---------------------------------------------------------------------------
# the frozen lookup and the candidate wiring
# ---------------------------------------------------------------------------


def test_release_dates_lookup():
    dates = ReleaseDates(
        stdlib={"go1.21.5": datetime.date(2023, 12, 5)},
        modules={"golang.org/x/net@0.17.0": datetime.date(2023, 10, 10)},
    )
    assert dates.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)
    assert dates.lookup("toolchain", "1.21.5") == datetime.date(2023, 12, 5)
    assert dates.lookup("golang.org/x/net", "0.17.0") == datetime.date(2023, 10, 10)
    assert dates.lookup("golang.org/x/net", "0.18.0") is None
    assert dates.lookup("stdlib", "1.21.0-0") is None
    assert dates.lookup("", "1.0.0") is None


@pytest.mark.parametrize("module", ["stdlib", "toolchain", "golang.org/x/net"])
@pytest.mark.parametrize("version", [1, 1.5, True, {"v": "1.21.0"}, ["1.21.0"]], ids=["int", "float", "bool", "dict", "list"])
def test_a_non_string_fix_version_is_a_miss_not_a_crash(module, version):
    """The record loop hands the callback raw OSV values, outside any fallback."""
    dates = ReleaseDates({"go1.21.0": datetime.date(2023, 8, 8)}, {})

    assert dates.lookup(module, version) is None
    assert go_extra_candidates(dates)("GO-1", module, version, "Go") == []


@pytest.mark.parametrize("module", [None, 3, ["stdlib"]], ids=["null", "int", "list"])
def test_a_non_string_module_is_a_miss_not_a_crash(module):
    dates = ReleaseDates({"go1.21.0": datetime.date(2023, 8, 8)}, {})

    assert dates.lookup(module, "1.21.0") is None


def test_go_extra_candidates_marks_release_date_accurate():
    dates = ReleaseDates(stdlib={"go1.21.5": datetime.date(2023, 12, 5)}, modules={})

    results = go_extra_candidates(dates)("GO-2023-9999", "stdlib", "1.21.5", "Go")

    assert len(results) == 1
    assert results[0].date == datetime.date(2023, 12, 5)
    assert results[0].kind == "release"
    assert results[0].accurate is True


def test_go_extra_candidates_returns_empty_when_lookup_misses():
    assert go_extra_candidates(ReleaseDates({}, {}))("GO-2023-9999", "stdlib", "1.21.5", "Go") == []


# ---------------------------------------------------------------------------
# resolve: the committed tables answer first
# ---------------------------------------------------------------------------


def test_committed_tables_answer_without_the_network(no_network):
    r = resolver(
        stdlib_table={"go1.21.5": "2023-12-05"},
        module_table={"golang.org/x/net@0.17.0": "2023-10-10"},
    )

    dates = r.resolve([("stdlib", "1.21.5"), ("toolchain", "1.21.5"), ("golang.org/x/net", "0.17.0")])

    assert dates.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)
    assert dates.lookup("golang.org/x/net", "0.17.0") == datetime.date(2023, 10, 10)


def test_committed_unknown_is_not_asked_about_again(no_network):
    r = resolver(module_table={"github.com/fleetdm/fleet/v4@4.75.2": None})
    assert r.resolve([("github.com/fleetdm/fleet/v4", "4.75.2")]).lookup("github.com/fleetdm/fleet/v4", "4.75.2") is None


def test_versions_naming_no_release_cost_no_request(no_network):
    """GO-2024-2962 fixes `toolchain` at 1.21.0-0, which names no tag; don't go looking for one."""
    assert resolver().resolve([("toolchain", "1.21.0-0")]).lookup("toolchain", "1.21.0-0") is None


def test_unsafe_module_costs_no_request(no_network):
    assert resolver().resolve([("../../../etc/passwd", "1.0.0")]).lookup("../../../etc/passwd", "1.0.0") is None


def test_offline_never_fetches(no_network):
    r = resolver(offline=True, stdlib_table={"go1.21.5": "2023-12-05"})

    dates = r.resolve([("stdlib", "1.21.5"), ("stdlib", "1.99.0"), ("golang.org/x/image", "0.10.0")])

    assert dates.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)
    assert dates.lookup("stdlib", "1.99.0") is None
    assert dates.lookup("golang.org/x/image", "0.10.0") is None


def test_invalid_committed_entries_are_skipped(no_network):
    r = resolver(module_table={"a.io/m@1.0.0": "not-a-date", "b.io/m@1.0.0": 20230801, "c.io/m@1.0.0": "2023-08-01"})

    dates = r.committed()

    assert dates.lookup("a.io/m", "1.0.0") is None
    assert dates.lookup("b.io/m", "1.0.0") is None
    assert dates.lookup("c.io/m", "1.0.0") == datetime.date(2023, 8, 1)


def test_committed_is_the_tables_alone(no_network):
    r = resolver(stdlib_table={"go1.21.5": "2023-12-05"}, module_table={"golang.org/x/net@0.17.0": "2023-10-10", "x.io/y@1.0.0": None})

    dates = r.committed()

    assert dates.lookup("stdlib", "1.21.5") == datetime.date(2023, 12, 5)
    assert dates.lookup("golang.org/x/net", "0.17.0") == datetime.date(2023, 10, 10)
    assert dates.lookup("x.io/y", "1.0.0") is None


# ---------------------------------------------------------------------------
# resolve: misses
# ---------------------------------------------------------------------------


def test_stdlib_miss_asks_gitiles_once_per_tag(fake_http):
    fake = fake_http(lambda url: response(content=GITILES_BODY))

    dates = resolver().resolve([("stdlib", "1.99.0"), ("toolchain", "1.99.0")])

    assert dates.lookup("stdlib", "1.99.0") == datetime.date(2023, 12, 5)
    assert dates.lookup("toolchain", "1.99.0") == datetime.date(2023, 12, 5)
    assert fake.urls() == ["https://go.googlesource.com/go/+/refs/tags/go1.99.0?format=JSON"]


def test_module_miss_asks_the_proxy(fake_http):
    image = "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info"
    fake = fake_http(lambda url: response(content=PROXY_BODY) if url == image else response(status_code=404, content=b"not found"))

    dates = resolver().resolve([("golang.org/x/image", "0.10.0"), ("example.com/gone", "1.0.0")])

    assert dates.lookup("golang.org/x/image", "0.10.0") == datetime.date(2023, 8, 1)
    assert dates.lookup("example.com/gone", "1.0.0") is None
    assert fake.urls() == [
        "https://proxy.golang.org/example.com/gone/@v/v1.0.0.info",
        "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info",
    ]


def test_every_request_is_single_shot_short_and_identified(fake_http):
    """retries=0, and not download_timeout: that is sized for the vulndb zip, and would let
    one black-holed connection stall the run for minutes."""
    fake = fake_http()

    resolver().resolve([("stdlib", "1.99.0"), ("golang.org/x/image", "0.10.0")])

    assert len(fake.calls) == 2
    for call in fake.calls:
        assert call.kwargs["retries"] == 0
        assert call.kwargs["timeout"] == DEFAULT_TIMEOUT == 30
        assert call.kwargs["user_agent"].startswith("vunnel/")
        assert call.kwargs["allow_redirects"] is False


def test_the_wrapper_logs_quietly(monkeypatch):
    """A failed lookup is an expected miss the budget reports itself; the wrapper's per-attempt
    WARNING and ERROR lines would just be noise."""
    loggers = []

    def get(url, logger, **kwargs):
        loggers.append(logger)
        return response(status_code=404)

    monkeypatch.setattr(go_release_dates.http, "get", get)

    resolver().resolve([("example.com/mod", "1.0.0")])

    [logger] = loggers
    assert not logger.isEnabledFor(logging.ERROR)
    assert logger.isEnabledFor(logging.CRITICAL)


@pytest.mark.parametrize("status", [404, 410])
def test_not_found_is_an_answer_not_a_failure(fake_http, status):
    """The status_handler lets 404/410 through, so they never count against the host."""
    fake = fake_http(lambda url: response(status_code=status))

    resolver(max_failures_per_host=1).resolve([("example.com/mod", f"1.0.{i}") for i in range(5)])

    assert len(fake.calls) == 5


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_errors_count_against_the_host(fake_http, status):
    fake = fake_http(lambda url: response(status_code=status))

    resolver(max_failures_per_host=2).resolve([("example.com/mod", f"1.0.{i}") for i in range(5)])

    assert len(fake.calls) == 2


# ---------------------------------------------------------------------------
# failure handling: bounded by construction, and a missing date never costs the run
# ---------------------------------------------------------------------------


def test_a_host_that_keeps_failing_is_abandoned(fake_http, caplog):
    fake = fake_http(refused)
    pairs = [("stdlib", f"1.99.{i}") for i in range(10)]

    with caplog.at_level(logging.WARNING):
        dates = resolver(max_failures_per_host=3).resolve(pairs)

    assert len(fake.calls) == 3
    assert all(dates.lookup(m, v) is None for m, v in pairs)
    assert "not contacting go.googlesource.com again this run" in caplog.text


@pytest.mark.parametrize(
    "rate_limit",
    [response(status_code=429), response(status_code=503, headers={"Retry-After": "300"})],
    ids=["429", "503-with-retry-after"],
)
def test_a_rate_limit_abandons_the_host_at_once(fake_http, rate_limit):
    """A rate limit means stop, not wait: the next request would sleep out the wrapper's block."""
    fake = fake_http(lambda url: rate_limit)

    resolver().resolve([("stdlib", f"1.99.{i}") for i in range(10)])

    assert len(fake.calls) == 1


def test_a_rate_limit_ends_the_host_without_sleeping_through_the_real_wrapper(monkeypatch):
    """End to end through http_wrapper's own rate-limit registry, which the fake above only imitates."""
    http_wrapper._reset_for_testing()
    sleeps = []
    calls = []
    monkeypatch.setattr(time, "sleep", sleeps.append)

    def get(self, url, **kwargs):
        calls.append(url)
        resp = requests.Response()
        resp.status_code = 503
        resp.headers["Retry-After"] = "300"
        resp.url = url
        return resp

    monkeypatch.setattr(requests.Session, "get", get)

    try:
        resolver(deadline_seconds=120).resolve({("example.com/m", f"1.0.{i}") for i in range(10)})
    finally:
        http_wrapper._reset_for_testing()

    assert sleeps == [], f"slept {sleeps} inside the resolve phase"
    assert len(calls) == 1


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_a_failed_lookup(fake_http, status):
    """Redirects are refused, and a refused redirect must count against the host -- otherwise a host
    that redirects everything would quietly use up the whole lookup budget and the deadline."""
    fake = fake_http(lambda url: response(status_code=status, headers={"Location": "https://elsewhere.example/"}))

    dates = resolver(max_failures_per_host=3).resolve([("example.com/mod", f"1.0.{i}") for i in range(20)])

    assert len(fake.calls) == 3
    assert dates.lookup("example.com/mod", "1.0.0") is None


def test_a_host_that_only_redirects_is_abandoned_through_the_real_wrapper(monkeypatch):
    """End to end: with allow_redirects=False the wrapper hands back the 3xx, and it must still count."""
    http_wrapper._reset_for_testing()
    calls = []

    def get(self, url, **kwargs):
        calls.append(url)
        resp = requests.Response()
        resp.status_code = 302
        resp.url = url
        resp.headers["Location"] = "https://elsewhere.example/"
        resp._content = b""
        return resp

    monkeypatch.setattr(requests.Session, "get", get)

    try:
        resolver(max_failures_per_host=3).resolve({("example.com/m", f"1.0.{i}") for i in range(20)})
    finally:
        http_wrapper._reset_for_testing()

    assert len(calls) == 3, f"{len(calls)} requests to a host that answers every one with a redirect"


@pytest.mark.parametrize("status", [204, 206])
def test_a_host_answering_only_non_answers_is_abandoned(monkeypatch, status):
    """Only 200/404/410 are answers; any other success-range status counts against the host too."""
    http_wrapper._reset_for_testing()
    calls = []

    def get(self, url, **kwargs):
        calls.append(url)
        resp = requests.Response()
        resp.status_code = status
        resp.url = url
        resp._content = b""
        return resp

    monkeypatch.setattr(requests.Session, "get", get)

    try:
        resolver(max_failures_per_host=3).resolve({("example.com/m", f"1.0.{i}") for i in range(10)})
    finally:
        http_wrapper._reset_for_testing()

    assert len(calls) == 3


def test_one_dead_host_does_not_stop_the_others(fake_http):
    def handler(url):
        if urlparse(url).netloc == "go.googlesource.com":
            return response(status_code=429)
        return response(content=PROXY_BODY)

    fake_http(handler)

    dates = resolver().resolve([("stdlib", "1.99.0"), ("stdlib", "1.99.1"), ("golang.org/x/image", "0.10.0")])

    assert dates.lookup("golang.org/x/image", "0.10.0") == datetime.date(2023, 8, 1)
    assert dates.lookup("stdlib", "1.99.0") is None


def test_lookups_are_capped_per_host(fake_http, caplog):
    fake = fake_http()

    with caplog.at_level(logging.WARNING):
        resolver(max_lookups_per_host=5).resolve([("stdlib", f"1.99.{i}") for i in range(50)])

    assert len(fake.calls) == 5
    assert "task update-go-release-dates" in caplog.text


def test_the_resolve_phase_has_a_deadline(fake_http, caplog):
    clock = FakeClock()

    def slow(url):
        clock.now += 30
        return response(status_code=404)

    fake = fake_http(slow)

    with caplog.at_level(logging.WARNING):
        resolver(deadline_seconds=100, clock=clock).resolve([("stdlib", f"1.99.{i}") for i in range(50)])

    assert len(fake.calls) == 4
    assert "deadline reached" in caplog.text


def test_a_bug_is_not_mistaken_for_an_outage(fake_http):
    """Only network errors are misses; anything else propagates to the parser's fallback,
    which logs the traceback."""
    fake_http(lambda url: RuntimeError("something nobody anticipated"))

    with pytest.raises(RuntimeError, match="nobody anticipated"):
        resolver().resolve([("golang.org/x/image", "0.10.0")])


@pytest.mark.parametrize(
    "body",
    [
        b"<html>503 from a proxy</html>",
        b"[1, 2, 3]",
        b'{"Version":"v0.10.0"}',
        b'{"Time":"garbage"}',
        b'{"Time": 12345}',
    ],
)
def test_garbage_proxy_bodies_are_misses(fake_http, body):
    fake_http(lambda url: response(content=body))
    assert resolver().resolve([("golang.org/x/image", "0.10.0")]).lookup("golang.org/x/image", "0.10.0") is None


@pytest.mark.parametrize("body", [b"<html>oops</html>", b")]}'", b'{"committer": "nope"}'])
def test_garbage_gitiles_bodies_are_misses(fake_http, body):
    fake_http(lambda url: response(content=body))
    assert resolver().resolve([("stdlib", "1.99.0")]).lookup("stdlib", "1.99.0") is None


@pytest.mark.parametrize(
    "body",
    [
        # astimezone(UTC) overflows: there is no UTC date before year 1
        b'{"Time":"0001-01-01T00:00:00+05:00"}',
        # parses fine, but predates Go
        b'{"Time":"1999-01-01T00:00:00Z"}',
        b'{"Time":"9999-12-31T00:00:00Z"}',
    ],
)
def test_out_of_range_module_timestamps_are_misses(fake_http, body):
    """These are accurate=True and the generator commits them forever, so garbage must not get through."""
    fake_http(lambda url: response(content=body))
    assert resolver().resolve([("golang.org/x/image", "0.10.0")]).lookup("golang.org/x/image", "0.10.0") is None


def test_out_of_range_gitiles_timestamp_is_a_miss(fake_http):
    fake_http(lambda url: response(content=b')]}\'\n{"committer":{"time":"Mon Jan 01 00:00:00 0001 +0500"}}'))
    assert resolver().resolve([("stdlib", "1.99.0")]).lookup("stdlib", "1.99.0") is None


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
def test_gitiles_times_are_normalized_to_utc(fake_http, git_time, expected):
    payload = b'{"committer":{}}' if git_time is None else b')]}\'\n{"committer":{"time":"' + git_time.encode() + b'"}}'
    fake_http(lambda url: response(content=payload))
    assert resolver().resolve([("stdlib", "1.99.0")]).lookup("stdlib", "1.99.0") == expected


@pytest.mark.parametrize(
    "published,expected",
    [
        ("2023-08-01T17:46:51Z", datetime.date(2023, 8, 1)),
        ("2023-08-01T17:46:51-08:00", datetime.date(2023, 8, 2)),
        ("2023-08-01T00:30:00+05:30", datetime.date(2023, 7, 31)),
        ("garbage", None),
    ],
)
def test_module_times_are_normalized_to_utc(fake_http, published, expected):
    fake_http(lambda url: response(content=b'{"Time":"' + published.encode() + b'"}'))
    assert resolver().resolve([("golang.org/x/image", "0.10.0")]).lookup("golang.org/x/image", "0.10.0") == expected


# ---------------------------------------------------------------------------
# the committed tables
# ---------------------------------------------------------------------------


def test_committed_stdlib_table_is_well_formed():
    assert len(GO_RELEASE_DATES) > 350

    for tag, released in GO_RELEASE_DATES.items():
        assert stdlib_version_to_tag(tag) == tag, f"table key {tag!r} is not a tag the mapper produces"
        # raises if not a real ISO date
        parsed = datetime.date.fromisoformat(released)
        assert datetime.date(2009, 1, 1) < parsed < datetime.date(2100, 1, 1), f"{tag} -> {released}"


def test_committed_module_table_is_well_formed():
    assert len(GO_MODULE_RELEASE_DATES) > 3000

    for key, released in GO_MODULE_RELEASE_DATES.items():
        module, _, version = key.rpartition("@")
        assert module and version and module_key(module, version) == key
        assert module not in ("stdlib", "toolchain"), key
        if released is not None:
            parsed = datetime.date.fromisoformat(released)
            assert datetime.date(2009, 1, 1) < parsed < datetime.date(2100, 1, 1), f"{key} -> {released}"


@pytest.mark.parametrize(
    "module,version,expected",
    [
        ("stdlib", "1.19.2", datetime.date(2022, 10, 4)),
        ("stdlib", "1.21.5", datetime.date(2023, 12, 5)),
        # the 1.20 series has no go1.20.0 tag; go1.20 shipped 2023-02-01
        ("stdlib", "1.20.0", datetime.date(2023, 2, 1)),
        ("toolchain", "1.24.0", datetime.date(2025, 2, 11)),
        ("stdlib", "1.21.0-rc.4", datetime.date(2023, 8, 2)),
        # tagged 2026-03-05 in US Pacific, which is 2026-03-06 UTC
        ("stdlib", "1.25.8", datetime.date(2026, 3, 6)),
        ("golang.org/x/net", "0.17.0", datetime.date(2023, 10, 10)),
        ("golang.org/x/image", "0.10.0", datetime.date(2023, 8, 1)),
    ],
)
def test_real_fix_versions_come_from_the_committed_tables(no_network, module, version, expected):
    """Releases already out never hit the network -- the answer can't change."""
    r = ReleaseDateResolver(logger=logging.getLogger("test"))
    assert r.resolve([(module, version)]).lookup(module, version) == expected
