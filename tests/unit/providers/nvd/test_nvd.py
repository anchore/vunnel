from __future__ import annotations

import os
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
        nvd.Provider(
            "/tmp/doesntmatter",
            nvd.Config(runtime=provider.RuntimeConfig(existing_results=policy, result_store=result.StoreStrategy.SQLITE)),
        )

    if should_raise:
        with pytest.raises(Exception):
            make()
    else:
        make()


@pytest.mark.parametrize(
    ("store", "should_raise"),
    (
        (result.StoreStrategy.FLAT_FILE, True),
        (result.StoreStrategy.SQLITE, False),
    ),
)
def test_require_sqlite_store(store, should_raise):
    def make():
        nvd.Provider("/tmp/doesntmatter", nvd.Config(runtime=provider.RuntimeConfig(result_store=store)))

    if should_raise:
        with pytest.raises(Exception):
            make()
    else:
        make()


@pytest.mark.parametrize(
    ("overrides_enabled", "overrides_url", "should_raise"),
    (
        (True, "something", False),
        (False, "something", False),
        (True, "", True),
        (False, "", False),
    ),
)
def test_require_override_configuration(overrides_enabled, overrides_url, should_raise):
    def make():
        nvd.Provider(
            "/tmp/doesntmatter",
            nvd.Config(
                overrides_enabled=overrides_enabled,
                overrides_url=overrides_url,
                runtime=provider.RuntimeConfig(result_store=result.StoreStrategy.SQLITE),
            ),
        )

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
def test_provider_schema(helpers, mock_data_path, expected_written_entries, disable_get_requests, mocker):
    workspace = helpers.provider_workspace_helper(name=nvd.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    c = nvd.Config()
    p = nvd.Provider(root=workspace.root, config=c)
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p.manager.api.cve = mocker.Mock(return_value=[json_dict])

    p.update(None)

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)


@pytest.mark.parametrize(
    ("mock_data_path",),
    [
        ("test-fixtures/single-entry.json",),
        ("test-fixtures/full-page.json",),
    ],
)
def test_provider_via_snapshot(helpers, mock_data_path, disable_get_requests, mocker):
    snapshot_name = os.path.basename(mock_data_path).split(".")[0]

    workspace = helpers.provider_workspace_helper(
        name=nvd.Provider.name(),
        snapshot_prefix=snapshot_name,
    )

    c = nvd.Config()
    p = nvd.Provider(
        root=workspace.root,
        config=c,
    )
    # keep all of the default values for the result store, but override the strategy
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE

    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    p.manager.api.cve = mocker.Mock(return_value=[json_dict])

    p.update(None)

    workspace.assert_result_snapshots()
