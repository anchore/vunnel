import datetime
import logging
import os
import shutil
from types import SimpleNamespace
from unittest.mock import patch

import orjson
import pytest
import requests
from vunnel import result, schema
from vunnel.providers.govulndb import Config, Provider
from vunnel.providers.govulndb import go_release_dates
from vunnel.providers.govulndb import parser as parser_module
from vunnel.providers.govulndb.parser import Parser
from vunnel.tool.fixdate.finder import Finder, Result, Strategy
from vunnel.utils import osv

# what the committed table really holds for the fix versions in test-fixtures
COMMITTED_MODULE_DATES = {
    "golang.org/x/image@0.10.0": "2023-08-01",
    "google.golang.org/protobuf@1.33.0": "2024-03-05",
}


class Forbidden(BaseException):
    """Not an Exception, so nothing in the resolver can swallow it and make a guard pass vacuously."""


class FakeHTTP:
    """Stands in for http_wrapper.get, answering every request with `handler` and recording the url."""

    def __init__(self):
        self.calls = []
        self.handler = self.forbidden

    @staticmethod
    def forbidden(url):
        raise Forbidden(f"unexpected request for {url}")

    def get(self, url, logger, **kwargs):
        self.calls.append(url)
        result = self.handler(url)
        if isinstance(result, Exception):
            raise result
        kwargs["status_handler"](result)
        return result


def proxy_response(status_code=200, content=b"{}"):
    return SimpleNamespace(status_code=status_code, content=content, headers={}, raise_for_status=lambda: None)


@pytest.fixture
def release_date_http(monkeypatch):
    """Route the resolver's HTTP through a recorder; by default nothing may be requested."""
    fake = FakeHTTP()
    monkeypatch.setattr(go_release_dates.http, "get", fake.get)
    return fake


@pytest.fixture
def stub_go_release_dates(monkeypatch, release_date_http):
    """Serve the fixtures' fix versions from a committed table, with the network forbidden."""
    monkeypatch.setattr(go_release_dates, "GO_MODULE_RELEASE_DATES", COMMITTED_MODULE_DATES)
    return release_date_http


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_provider_schema(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests, stub_go_release_dates):
    mock_download.return_value = None
    mock_extract.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    assert 2 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_parser(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests, stub_go_release_dates):
    mock_download.return_value = None
    mock_extract.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())
    assert len(vuln_tuples) == 2
    assert vuln_tuples[0][0] == "GO-2023-1989"
    assert vuln_tuples[0][1] == "1.3.1"
    assert vuln_tuples[1][0] == "GO-2024-2611"
    assert vuln_tuples[1][1] == "1.3.1"


def _fixes(vuln_tuple):
    return vuln_tuple[2]["affected"][0]["ranges"][0]["database_specific"]["anchore"]["fixes"]


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_parser_prefers_go_release_date(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    disable_get_requests,
    stub_go_release_dates,
):
    mock_download.return_value = None
    mock_extract.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)

    vuln_tuples = list(parser.get())

    # the module's commit time wins over the advisory's published date (2023-08-02)
    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-01", "kind": "release"}]
    assert _fixes(vuln_tuples[1]) == [{"version": "1.33.0", "date": "2024-03-05", "kind": "release"}]
    assert stub_go_release_dates.calls == []


def _stage(helpers, mock_download, mock_extract):
    mock_download.return_value = None
    mock_extract.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    shutil.copytree(helpers.local_dir("test-fixtures"), workspace.input_dir, dirs_exist_ok=True)
    return workspace


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_parser_resolves_versions_newer_than_the_committed_table(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    disable_get_requests,
    release_date_http,
    monkeypatch,
):
    monkeypatch.setattr(go_release_dates, "GO_MODULE_RELEASE_DATES", {})
    release_date_http.handler = lambda url: proxy_response(
        content={
            "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info": b'{"Time":"2023-08-01T17:46:51Z"}',
            "https://proxy.golang.org/google.golang.org/protobuf/@v/v1.33.0.info": b'{"Time":"2024-03-05T19:00:20Z"}',
        }[url],
    )
    parser = Parser(ws=_stage(helpers, mock_download, mock_extract), logger=None)

    vuln_tuples = list(parser.get())

    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-01", "kind": "release"}]
    assert _fixes(vuln_tuples[1]) == [{"version": "1.33.0", "date": "2024-03-05", "kind": "release"}]
    assert release_date_http.calls == [
        "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info",
        "https://proxy.golang.org/google.golang.org/protobuf/@v/v1.33.0.info",
    ]


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_parser_survives_a_dead_release_date_host(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    disable_get_requests,
    release_date_http,
    monkeypatch,
):
    """A release-date source being down must cost the date, not the run."""
    monkeypatch.setattr(go_release_dates, "GO_MODULE_RELEASE_DATES", {})
    release_date_http.handler = lambda url: requests.exceptions.ConnectionError("connection refused")
    parser = Parser(ws=_stage(helpers, mock_download, mock_extract), logger=None)

    vuln_tuples = list(parser.get())

    assert len(vuln_tuples) == 2
    # fell back to the advisory's published date rather than blowing up
    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-02", "kind": "advisory"}]
    # one attempt per version, nothing retried
    assert release_date_http.calls == [
        "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info",
        "https://proxy.golang.org/google.golang.org/protobuf/@v/v1.33.0.info",
    ]


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_the_record_loop_never_touches_the_network(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    disable_get_requests,
    release_date_http,
    monkeypatch,
):
    """Every release-date request happens before the first record is patched."""
    monkeypatch.setattr(go_release_dates, "GO_MODULE_RELEASE_DATES", {})
    release_date_http.handler = lambda url: proxy_response(status_code=404, content=b"not found")

    original = parser_module.osv.patch_fix_date
    during_loop = []

    def patch_fix_date(*args, **kwargs):
        before = len(release_date_http.calls)
        original(*args, **kwargs)
        during_loop.append(len(release_date_http.calls) - before)

    monkeypatch.setattr(parser_module.osv, "patch_fix_date", patch_fix_date)
    parser = Parser(ws=_stage(helpers, mock_download, mock_extract), logger=None)

    list(parser.get())

    assert release_date_http.calls, "the resolve phase should have asked about the misses"
    assert during_loop == [0, 0]


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_a_resolver_that_raises_anyway_costs_only_the_fresh_dates(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    disable_get_requests,
):
    """The resolver is written to be total; if it raises anyway, the committed tables still answer."""

    class Exploding(go_release_dates.ReleaseDateResolver):
        def resolve(self, pairs):
            raise RuntimeError("a bug nobody anticipated")

    resolver = Exploding(module_table={"golang.org/x/image@0.10.0": "2023-08-01"})
    parser = Parser(ws=_stage(helpers, mock_download, mock_extract), logger=None, release_date_resolver=resolver)

    vuln_tuples = list(parser.get())

    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-01", "kind": "release"}]
    assert _fixes(vuln_tuples[1])[0]["kind"] == "advisory"


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_unreadable_committed_tables_cost_only_the_release_dates(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    disable_get_requests,
):
    class Broken(go_release_dates.ReleaseDateResolver):
        def resolve(self, pairs):
            raise RuntimeError("resolve blew up")

        def committed(self):
            raise RuntimeError("and so did the tables")

    parser = Parser(ws=_stage(helpers, mock_download, mock_extract), logger=None, release_date_resolver=Broken())

    vuln_tuples = list(parser.get())

    assert len(vuln_tuples) == 2
    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-02", "kind": "advisory"}]


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_a_record_that_isnt_json_fails_the_run_as_itself(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    stub_go_release_dates,
    caplog,
):
    """The vulndb is read outside the release-date fallback, so a corrupt file surfaces as what it
    is rather than first being logged as a release-date failure and swallowed."""
    workspace = _stage(helpers, mock_download, mock_extract)
    parser = Parser(ws=workspace, logger=None)
    with open(os.path.join(parser.extract_dir, "ID", "GO-9999-0001.json"), "w") as f:
        f.write("not json")

    with caplog.at_level(logging.ERROR), pytest.raises(orjson.JSONDecodeError):
        list(parser.get())

    assert "release-date resolve failed" not in caplog.text


class FirstObserved(Strategy):
    def __init__(self, results):
        self.results = results

    def download(self):
        pass

    def get_changed_vuln_ids_since(self, since):
        return set()

    def find(self, *args, **kwargs):
        return self.results


@pytest.mark.parametrize(
    ("first_observed", "expected_kind"),
    [
        (Result(date=datetime.date(2024, 1, 1), kind="first-observed", accurate=True), "release"),
        (Result(date=datetime.date(2020, 1, 1), kind="first-observed", accurate=False), "release"),
        (Result(date=datetime.date(2023, 8, 1), kind="first-observed", accurate=True), "release"),
        (Result(date=datetime.date(2023, 7, 1), kind="first-observed", accurate=True), "first-observed"),
    ],
    ids=["later-accurate", "inaccurate", "same-day", "earlier-accurate"],
)
def test_release_date_precedence_against_first_observed(first_observed, expected_kind):
    """The release date beats every first-observed date except an accurate earlier one."""
    record = {
        "id": "GO-X",
        "published": "2023-08-02T00:00:00Z",
        "affected": [
            {
                "package": {"name": "golang.org/x/image", "ecosystem": "Go"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.10.0"}]}],
            },
        ],
    }
    dates = go_release_dates.ReleaseDates({}, {"golang.org/x/image@0.10.0": datetime.date(2023, 8, 1)})

    osv.patch_fix_date(record, Finder([], FirstObserved([first_observed])), extra_candidates=go_release_dates.go_extra_candidates(dates))

    assert record["affected"][0]["ranges"][0]["database_specific"]["anchore"]["fixes"][0]["kind"] == expected_kind


@pytest.mark.parametrize(
    "schema_version,expected",
    [
        ("1.3.1", schema.OSVSchema(version="1.3.1")),
        ("1.5.0", schema.OSVSchema(version="1.5.0")),
        ("1.6.1", schema.OSVSchema(version="1.6.1")),
        ("0.6.0", None),
        ("2.4.0", None),
    ],
)
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_provider_via_snapshot(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests, stub_go_release_dates):
    mock_download.return_value = None
    mock_extract.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    workspace.assert_result_snapshots()


def test_provider_skip_download(helpers, auto_fake_fixdate_finder, monkeypatch):
    """With skip_download=True, no HTTP request should be made and pre-staged input is used.

    Nothing here stubs the HTTP layer out of the way: any request fails the test, so the
    point is that skip_download is genuinely offline. The committed module table is
    emptied, so every fix version is a miss the resolver has to decline to fetch.
    """
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    # nothing committed, so every fix version is a miss that skip_download must decline to fetch
    monkeypatch.setattr(go_release_dates, "GO_MODULE_RELEASE_DATES", {})
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    def _fail_on_http(*args, **kwargs):
        # a BaseException: the parser's fallback would swallow an ordinary one
        raise Forbidden("HTTP request attempted during skip_download test")

    monkeypatch.setattr("vunnel.utils.http_wrapper.get", _fail_on_http)

    p.update(None)

    assert workspace.num_result_entries() == 2
