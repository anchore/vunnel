import shutil
import pytest
from unittest.mock import MagicMock, call, patch
from unittest import mock

from vunnel import result
from vunnel.providers.rocky import Config, Provider
from vunnel.providers.rocky.parser import Parser
from vunnel.providers.rocky.client import Client


@patch("vunnel.providers.rocky.client.Client._download")
def test_provider_schema(mock_download, helpers):
    mock_download.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    assert 3 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)

@patch("vunnel.providers.rocky.client.Client._download")
def test_provider_skip_download(mock_download, helpers):
    assert Provider.supports_skip_download()

    mock_download.side_effect = RuntimeError("should not be called")
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    assert mock_download.call_count == 0
    assert 3 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)

def test_provider_skip_download_error_on_empty():
    assert Provider.supports_skip_download()

    workspace = MagicMock()
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace, config=c)

    with pytest.raises(RuntimeError):
        p.update(None)


@patch("vunnel.providers.rocky.client.Client._download")
def test_parser(mock_download, helpers):
    mock_download.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())
    assert len(vuln_tuples) == 3
    assert vuln_tuples[0][0] == "RLSA-2021:3891"
    assert vuln_tuples[0][1] == "1.3.1"
    assert vuln_tuples[1][0] == "RLSA-2023:3220"
    assert vuln_tuples[1][1] == "1.3.1"
    assert vuln_tuples[2][0] == "RLSA-2024:3671"
    assert vuln_tuples[2][1] == "1.3.1"

@patch("vunnel.utils.http_wrapper.get")
def test_client(mock_http_get, helpers):
    page1 = MagicMock()
    page1.json.return_value = {
        "links": {"next": "/api/v3/osv/?page=2"},
        "advisories": [], # intentionally empty
    }
    page2 = MagicMock()
    page2.json.return_value = {
        "links": {"next": None},
        "advisories": [], # intentionally empty
    }
    mock_http_get.side_effect = [page1, page2]
    mock_host = "https://apollo.example.com"
    logger = MagicMock()
    client = Client(download_path=helpers.local_dir("test-fixtures"), logger=logger, api_host=mock_host)
    client._download()
    assert mock_http_get.call_count == 2
    expected_calls = [
        mock.call(f"{mock_host}/api/v3/osv/", logger),
        mock.call(f"{mock_host}/api/v3/osv/?page=2", logger)
    ]
    mock_http_get.assert_has_calls(expected_calls)
