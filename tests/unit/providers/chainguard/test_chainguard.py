from __future__ import annotations

import json
import os
import shutil

import pytest
from vunnel import result, workspace, schema
from vunnel.providers.chainguard import Config, Provider


def test_provider_schema(helpers, disable_get_requests):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(
        # turn off openvex
        openvex_url=''
    )
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
        # turn off openvex
        openvex_url=''
    )
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    def mock_download():
        return None

    monkeypatch.setattr(p.parsers['secdb'], "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()


def test_openvex_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="openvex"
    )
    c = Config(
        # turn off wofli
        secdb_url=''
    )
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )
    def mock_download(filename: str):
        return None
    monkeypatch.setattr(p.parsers['openvex'], "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
