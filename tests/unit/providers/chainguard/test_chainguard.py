from __future__ import annotations

import os
import shutil

import pytest
from vunnel import result
from vunnel.providers.chainguard import Config, Provider
from vunnel.providers.wolfi.parser import OSVParser, SecDBParser


@pytest.mark.parametrize(
    ("use_osv", "expected_parser_cls", "expected_url_attr", "expected_schema_name"),
    [
        (False, SecDBParser, "secdb_url", "vulnerability/os"),
        (True, OSVParser, "osv_url", "vulnerability/osv"),
    ],
)
def test_parser_selection(
    helpers,
    auto_fake_fixdate_finder,
    use_osv,
    expected_parser_cls,
    expected_url_attr,
    expected_schema_name,
):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=use_osv)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    expected_url = getattr(c, expected_url_attr)
    assert isinstance(p.parser, expected_parser_cls)
    assert p.parser.url == expected_url
    assert p.schema.name == expected_schema_name


def test_provider_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    p.update(None)

    assert workspace.num_result_entries() == 189
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="secdb",
    )

    c = Config()
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


def test_provider_osv_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert p.schema.version == "1.7.0"

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    # all.json is the upstream OSV index (a list), not an advisory record;
    # OSVParser._load loads every *.json, so drop it to leave only records.
    os.remove(workspace.input_dir / "osv" / "all.json")

    p.update(None)

    assert workspace.num_result_entries() == 3
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_osv_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="osv",
    )
    os.remove(workspace.input_dir / "osv" / "all.json")

    c = Config(use_osv=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert p.schema.version == "1.7.0"

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
