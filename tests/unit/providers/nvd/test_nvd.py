from __future__ import annotations

import json

import pytest
from vunnel import provider, result
from vunnel.providers import nvd


@pytest.mark.parametrize(
    ("policy", "should_raise"),
    (
        (provider.ResultStatePolicy.KEEP, False),
        (provider.ResultStatePolicy.DELETE_BEFORE_WRITE, True),
        (provider.ResultStatePolicy.DELETE, True),
    ),
)
def test_incremental_update_with_existing_results(policy, should_raise):
    def make():
        nvd.Provider("/tmp/doesntmatter", nvd.Config(runtime=provider.RuntimeConfig(existing_results=policy)))

    if should_raise:
        with pytest.raises(Exception):
            make()
    else:
        make()


@pytest.mark.parametrize(
    ("mock_data_path", "expected_written_entries"),
    [
        ("test-fixtures/single-entry.json", 1),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries, mocker):
    workspace = helpers.provider_workspace_helper(name=nvd.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    c = nvd.Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = nvd.Provider(root=workspace.root, config=c)
    p.manager.api.cve = mocker.Mock(return_value=[json_dict])

    p.update(None)

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)
