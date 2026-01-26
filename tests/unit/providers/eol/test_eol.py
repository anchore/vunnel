import json
import os

import pytest

from vunnel import result
from vunnel.providers import eol


@pytest.mark.parametrize(
    ("mock_data_path", "expected_written_entries"),
    [
        ("test-fixtures/valid-eol-response.json", 6),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries, disable_get_requests, mocker):
    """Test that the provider writes valid schema entries."""
    workspace = helpers.provider_workspace_helper(name=eol.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        mock_response = json.load(f)

    c = eol.Config()
    p = eol.Provider(root=workspace.root, config=c)
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE

    # Mock the manager's get method to yield test data
    def mock_get():
        for product in mock_response.get("result", []):
            product_name = product["name"]
            for release in product.get("releases", []):
                cycle_name = release["name"]
                cycle_data = {
                    "product": product_name,
                    **release,
                    "identifiers": product.get("identifiers", []),
                }
                yield product_name, cycle_name, cycle_data

    p.manager.get = mock_get

    p.update(None)

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)


@pytest.mark.parametrize(
    ("mock_data_path",),
    [
        ("test-fixtures/valid-eol-response.json",),
    ],
)
def test_provider_via_snapshot(helpers, mock_data_path, disable_get_requests, mocker):
    """Test provider output against snapshot."""
    snapshot_name = os.path.basename(mock_data_path).split(".")[0]

    workspace = helpers.provider_workspace_helper(
        name=eol.Provider.name(),
        snapshot_prefix=snapshot_name,
    )

    c = eol.Config()
    p = eol.Provider(
        root=workspace.root,
        config=c,
    )
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE

    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        mock_response = json.load(f)

    # Mock the manager's get method to yield test data
    def mock_get():
        for product in mock_response.get("result", []):
            product_name = product["name"]
            for release in product.get("releases", []):
                cycle_name = release["name"]
                cycle_data = {
                    "product": product_name,
                    **release,
                    "identifiers": product.get("identifiers", []),
                }
                yield product_name, cycle_name, cycle_data

    p.manager.get = mock_get

    p.update(None)

    workspace.assert_result_snapshots()
