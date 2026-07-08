from __future__ import annotations

import os
import shutil
import tarfile

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
    assert p._schema.name == expected_schema_name


@pytest.mark.parametrize(
    ("use_osv", "expected_parser_cls"),
    [
        (False, SecDBParser),
        (True, OSVParser),
    ],
)
def test_config_propagates_to_parser(helpers, auto_fake_fixdate_finder, use_osv, expected_parser_cls):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=use_osv)
    c.runtime.skip_download = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert isinstance(p.parser, expected_parser_cls)
    assert p.parser.skip_download is True


def test_config_defaults():
    c = Config()
    assert c.runtime.skip_download is False


def test_provider_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
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


def _make_osv_tar(helpers, workspace):
    """Package OSV fixture JSON files into the tar.gz that OSVParser._load() expects."""
    osv_input_dir = os.path.join(str(workspace.input_dir), "osv")
    os.makedirs(osv_input_dir, exist_ok=True)
    fixture_osv_dir = helpers.local_dir("test-fixtures/input/osv")
    tar_path = os.path.join(osv_input_dir, "chainguard.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tf:
        for entry in sorted(os.scandir(fixture_osv_dir), key=lambda e: e.name):
            if entry.name.startswith("CGA-") and entry.name.endswith(".json"):
                tf.add(entry.path, arcname=entry.name)


def test_provider_osv_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)

    assert p._schema.version == "1.7.0"

    _make_osv_tar(helpers, workspace)

    p.update(None)

    assert workspace.num_result_entries() == 3
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_osv_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        snapshot_prefix="osv",
    )

    _make_osv_tar(helpers, workspace)

    c = Config(use_osv=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert p._schema.version == "1.7.0"

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
