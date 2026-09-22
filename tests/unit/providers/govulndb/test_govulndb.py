import shutil
from unittest.mock import patch

import pytest
import requests
from vunnel import result, schema
from vunnel.providers.govulndb import Config, Provider
from vunnel.providers.govulndb.go_release_dates import GoReleaseDateOverlay
from vunnel.providers.govulndb.parser import Parser


# what proxy.golang.org really returns for the fix versions in test-fixtures
GO_RELEASE_INFO = {
    "https://proxy.golang.org/golang.org/x/image/@v/v0.10.0.info": {"Time": "2023-08-01T17:46:51Z"},
}


@pytest.fixture
def stub_go_release_dates(monkeypatch):
    """Answer release-date lookups from canned payloads instead of the network.

    Stubs the transport rather than `lookup`, so URL construction, the
    should_resolve policy, caching and the candidate wiring all still run: what
    the snapshot records is what a real run writes.
    """

    def fake_fetch(self, url, strip_xss_guard):
        return GO_RELEASE_INFO.get(url)

    monkeypatch.setattr(GoReleaseDateOverlay, "_fetch_json", fake_fetch)


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

    # golang.org/x/image is go-maintained: the module proxy's tag time wins over the
    # advisory's published date (2023-08-02)
    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-01", "kind": "release"}]

    # google.golang.org/protobuf is third-party and GO-2024-2611 aliases GHSA-8r3f-844c-mc37,
    # so grype merges this package away; we never pay for a date that gets discarded
    assert _fixes(vuln_tuples[1])[0]["kind"] == "advisory"


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_parser_survives_a_dead_release_date_host(
    mock_download,
    mock_extract,
    helpers,
    auto_fake_fixdate_finder,
    monkeypatch,
):
    """A release-date source being down must cost the date, not the run."""
    mock_download.return_value = None
    mock_extract.return_value = None

    def refused(url, logger, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr("vunnel.providers.govulndb.go_release_dates.http.get", refused)

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)

    vuln_tuples = list(parser.get())

    assert len(vuln_tuples) == 2
    # fell back to the advisory's published date rather than blowing up
    assert _fixes(vuln_tuples[0]) == [{"version": "0.10.0", "date": "2023-08-02", "kind": "advisory"}]


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

    Nothing here stubs the release-date overlay: the point is that skip_download is
    genuinely offline. The overlay serves the committed Go release table and declines
    to fetch anything else.
    """
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    def _fail_on_http(*args, **kwargs):
        raise RuntimeError("HTTP request attempted during skip_download test")

    monkeypatch.setattr("vunnel.utils.http_wrapper.get", _fail_on_http)

    p.update(None)

    assert workspace.num_result_entries() == 2
