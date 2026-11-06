from __future__ import annotations

import os
import shutil
import tarfile

import pytest
from vunnel import result
from vunnel.providers.chainguard import Config, Provider
from vunnel.providers.wolfi.parser import OSVParser, SecDBParser


@pytest.mark.parametrize(
    ("use_osv", "expected"),
    [
        (False, [(SecDBParser, "secdb_url", "vulnerability/os")]),
        (
            True,
            [
                (SecDBParser, "secdb_url", "vulnerability/os"),
                (OSVParser, "osv_url", "vulnerability/osv"),
            ],
        ),
    ],
)
def test_parser_selection(helpers, auto_fake_fixdate_finder, use_osv, expected):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=use_osv)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert len(p.parsers) == len(expected)
    for (parser, record_schema), (expected_parser_cls, expected_url_attr, expected_schema_name) in zip(p.parsers, expected):
        assert isinstance(parser, expected_parser_cls)
        assert parser.url == getattr(c, expected_url_attr)
        assert record_schema.name == expected_schema_name


@pytest.mark.parametrize("use_osv", [False, True])
def test_config_propagates_to_parser(helpers, auto_fake_fixdate_finder, use_osv):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=use_osv)
    c.runtime.skip_download = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert p.parsers
    for parser, _ in p.parsers:
        assert parser.skip_download is True


def test_config_defaults():
    c = Config()
    assert c.runtime.skip_download is False


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


def _copy_secdb_input(helpers, workspace):
    shutil.copytree(helpers.local_dir("test-fixtures/input/secdb"), os.path.join(str(workspace.input_dir), "secdb"))


def _result_namespaces(workspace):
    return {os.path.basename(os.path.dirname(f)) for f in workspace.result_files()}


def test_provider_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=False)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)

    _copy_secdb_input(helpers, workspace)

    urls, count = p.update(None)

    assert urls == [c.secdb_url]
    assert count == 192
    assert workspace.num_result_entries() == 192
    assert _result_namespaces(workspace) == {"chainguard:rolling"}
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_osv_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)

    _copy_secdb_input(helpers, workspace)
    _make_osv_tar(helpers, workspace)

    urls, count = p.update(None)

    # both feeds are written: secdb under chainguard:rolling, osv under chainguard:cga
    assert urls == [c.secdb_url, c.osv_url]
    assert count == 192 + 3
    assert workspace.num_result_entries() == 192 + 3
    assert _result_namespaces(workspace) == {"chainguard:rolling", "chainguard:cga"}
    assert {os.path.basename(f) for f in workspace.result_files() if "chainguard:cga" in f} == {
        "CGA-224q-ccj5-2p53.json",
        "CGA-22hv-wp9q-4779.json",
        "CGA-xcpc-gm23-prj9.json",
    }
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="secdb",
    )

    c = Config(use_osv=False)
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    def mock_download():
        return None

    for parser, _ in p.parsers:
        monkeypatch.setattr(parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()


def test_provider_osv_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        snapshot_prefix="osv",
    )

    _make_osv_tar(helpers, workspace)

    c = Config(use_osv=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    # only snapshot the OSV feed here; secdb output is covered by test_provider_via_snapshot
    p.parsers = [(parser, record_schema) for parser, record_schema in p.parsers if isinstance(parser, OSVParser)]

    def mock_download():
        return None

    for parser, _ in p.parsers:
        monkeypatch.setattr(parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
