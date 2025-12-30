import json
import os

import pytest
from vunnel import result, schema
from vunnel.providers.rootio import Config, Provider
from vunnel.providers.rootio.parser import Parser


def test_provider_schema(helpers, auto_fake_fixdate_finder, disable_get_requests, mocker):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE

    # Mock HTTP GET calls
    mock_data_path = helpers.local_dir("test-fixtures")

    # Load mock all.json
    with open(os.path.join(mock_data_path, "all.json")) as f:
        mock_ids = json.load(f)

    # Create a side_effect function to return different responses based on URL
    def mock_http_get(url, logger, **kwargs):
        mock_response = mocker.Mock()
        if url.endswith("/all.json"):
            mock_response.json.return_value = mock_ids
        else:
            # Extract OSV ID from URL
            osv_id = url.split("/")[-1].replace(".json", "")
            osv_file = os.path.join(mock_data_path, "osv", f"{osv_id}.json")
            with open(osv_file) as f:
                mock_response.json.return_value = json.load(f)
        return mock_response

    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=mock_http_get)

    p = Provider(root=workspace.root, config=c)
    p.update(None)

    assert 5 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)


def test_parser(helpers, disable_get_requests, auto_fake_fixdate_finder, mocker):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")

    # Load mock all.json
    with open(os.path.join(mock_data_path, "all.json")) as f:
        mock_ids = json.load(f)

    # Create a side_effect function to return different responses based on URL
    def mock_http_get(url, logger, **kwargs):
        mock_response = mocker.Mock()
        if url.endswith("/all.json"):
            mock_response.json.return_value = mock_ids
        else:
            # Extract OSV ID from URL
            osv_id = url.split("/")[-1].replace(".json", "")
            osv_file = os.path.join(mock_data_path, "osv", f"{osv_id}.json")
            with open(osv_file) as f:
                mock_response.json.return_value = json.load(f)
        return mock_response

    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=mock_http_get)

    parser = Parser(ws=workspace, logger=None)
    with parser:
        vuln_tuples = list(parser.get())

    assert len(vuln_tuples) == 5
    assert vuln_tuples[0][0] == "ROOT-OS-ALPINE-318-CVE-2000-0548"
    assert vuln_tuples[0][1] == "1.6.1"
    assert vuln_tuples[1][0] == "ROOT-OS-DEBIAN-bookworm-CVE-2025-53014"
    assert vuln_tuples[1][1] == "1.6.1"
    assert vuln_tuples[2][0] == "ROOT-OS-UBUNTU-2004-CVE-2024-12345"
    assert vuln_tuples[2][1] == "1.6.1"
    assert vuln_tuples[3][0] == "ROOT-APP-NPM-CVE-2022-25883"
    assert vuln_tuples[3][1] == "1.6.1"
    assert vuln_tuples[4][0] == "ROOT-APP-PYPI-CVE-2025-30473"
    assert vuln_tuples[4][1] == "1.6.1"


def test_parser_normalize_with_root_prefix(helpers, auto_fake_fixdate_finder, disable_get_requests, mocker):
    """Test that parser strips 'Root:' prefix from ecosystem field."""
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    # Create a mock OSV record with "Root:" prefix (as returned by actual API)
    mock_record = {
        "schema_version": "1.6.0",
        "id": "ROOT-OS-ALPINE-318-CVE-2000-0548",
        "modified": "2024-11-20T16:00:00Z",
        "published": "2024-11-15T12:00:00Z",
        "affected": [
            {
                "package": {
                    "ecosystem": "Root:Alpine:3.18",  # API format with "Root:" prefix
                    "name": "rootio-util-linux"
                }
            }
        ],
        "database_specific": {"source": "Root"}
    }

    parser = Parser(ws=workspace, logger=None)
    vuln_id, schema_version, normalized_record = parser._normalize(mock_record)

    # Verify the ecosystem was normalized
    assert vuln_id == "ROOT-OS-ALPINE-318-CVE-2000-0548"
    assert schema_version == "1.6.0"
    assert normalized_record["affected"][0]["package"]["ecosystem"] == "Alpine:3.18"  # Should be stripped


@pytest.mark.parametrize(
    "schema_version,expected",
    [
        ("1.6.1", schema.OSVSchema(version="1.6.1")),
        ("1.5.0", schema.OSVSchema(version="1.5.0")),
        ("1.7.0", schema.OSVSchema(version="1.7.0")),
        ("0.6.0", None),
        ("2.4.0", None),
    ],
)
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


def test_provider_via_snapshot(helpers, auto_fake_fixdate_finder, disable_get_requests, mocker):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE

    # Mock HTTP GET calls
    mock_data_path = helpers.local_dir("test-fixtures")

    # Load mock all.json
    with open(os.path.join(mock_data_path, "all.json")) as f:
        mock_ids = json.load(f)

    # Create a side_effect function to return different responses based on URL
    def mock_http_get(url, logger, **kwargs):
        mock_response = mocker.Mock()
        if url.endswith("/all.json"):
            mock_response.json.return_value = mock_ids
        else:
            # Extract OSV ID from URL
            osv_id = url.split("/")[-1].replace(".json", "")
            osv_file = os.path.join(mock_data_path, "osv", f"{osv_id}.json")
            with open(osv_file) as f:
                mock_response.json.return_value = json.load(f)
        return mock_response

    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=mock_http_get)

    p = Provider(root=workspace.root, config=c)
    p.update(None)

    workspace.assert_result_snapshots()
