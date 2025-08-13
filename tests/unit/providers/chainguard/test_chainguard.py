from __future__ import annotations

import json
import os
import shutil

import pytest
from vunnel import result, workspace, schema
from vunnel.providers.chainguard import Config, Provider


def test_provider_schema(helpers, disable_get_requests):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    p.update(None)

    assert workspace.num_result_entries() == 189
    assert workspace.result_schemas_valid(require_entries=True)


def test_wolfi_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="secdb"
    )

    c = Config(
        chainguard_provider_type='wolfi'
    )
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()

# TODO this is not passing, how do these tests work? What is this helpers object?
def test_vex_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="vex"
    )
    c = Config(
        chainguard_provider_type='vex',
        target_url='https://packages.cgr.dev/chainguard/vex/all.json',
        schema=schema.OpenVEXSchema(),
    )
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )
    def mock_download(filename: str):
        return None
    monkeypatch.setattr(p.parser, "_download", mock_download)
    # def mock_index_path():
    #     return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test-fixtures/input/vex/all.json')
    # monkeypatch.setattr(p.parser, "_get_index_path", mock_index_path)
    p.update(None)
    # TODO this is comparing to OSV output, which is different
    workspace.assert_result_snapshots()
