import shutil
from unittest.mock import patch

import pytest
from vunnel import result, schema
from vunnel.providers.govulndb import Config, Provider
from vunnel.providers.govulndb.parser import Parser


@patch("vunnel.providers.govulndb.parser.Parser._extract")
@patch("vunnel.providers.govulndb.parser.Parser._download")
def test_provider_schema(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
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
def test_parser(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
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
def test_provider_via_snapshot(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
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
    """With skip_download=True, no HTTP request should be made and pre-staged input is used."""
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
