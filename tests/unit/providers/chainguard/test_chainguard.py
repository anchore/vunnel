from __future__ import annotations

import json
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

    assert workspace.num_result_entries() == 192
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


def test_include_secdb_requires_osv(helpers, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=False, include_secdb=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    with pytest.raises(ValueError, match="include_secdb requires use_osv"):
        Provider(root=workspace.root, config=c)


@pytest.mark.parametrize(
    ("use_osv", "include_secdb", "expect_secdb_parser"),
    [
        (False, False, False),
        (True, False, False),
        (True, True, True),
    ],
)
def test_secdb_parser_selection(helpers, auto_fake_fixdate_finder, use_osv, include_secdb, expect_secdb_parser):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=use_osv, include_secdb=include_secdb)
    c.runtime.skip_download = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    if not expect_secdb_parser:
        assert p.secdb_parser is None
        return

    assert isinstance(p.parser, OSVParser)
    assert isinstance(p.secdb_parser, SecDBParser)
    assert p.secdb_parser.url == c.secdb_url
    # the same namespace a secdb-only run writes
    assert p.secdb_parser.namespace == "chainguard"
    assert p.secdb_parser.skip_download is True


def _run(helpers, root: str, config: Config, secdb: bool, osv: bool) -> tuple[list[str], int, dict[str, dict]]:
    """Run the provider in a workspace of its own under root; returns its urls, count and records by identifier."""
    config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    config.runtime.skip_download = True
    p = Provider(root=root, config=config)
    input_dir = p.workspace.input_path
    if secdb:
        shutil.copytree(helpers.local_dir("test-fixtures/input/secdb"), os.path.join(input_dir, "secdb"))
    if osv:
        osv_dir = os.path.join(input_dir, "osv")
        os.makedirs(osv_dir, exist_ok=True)
        fixture_osv_dir = helpers.local_dir("test-fixtures/input/osv")
        with tarfile.open(os.path.join(osv_dir, "chainguard.tar.gz"), "w:gz") as tf:
            for entry in sorted(os.scandir(fixture_osv_dir), key=lambda e: e.name):
                if entry.name.startswith("CGA-") and entry.name.endswith(".json"):
                    tf.add(entry.path, arcname=entry.name)
    urls, count = p.update(None)

    records = {}
    for dirpath, _, files in os.walk(p.workspace.results_path):
        for name in files:
            with open(os.path.join(dirpath, name)) as f:
                envelope = json.load(f)
            records[envelope["identifier"]] = envelope
    return urls, count, records


def test_provider_osv_with_secdb(helpers, disable_get_requests, auto_fake_fixdate_finder, tmp_path):
    _, _, secdb_only = _run(helpers, str(tmp_path / "secdb"), Config(), secdb=True, osv=False)
    _, _, osv_only = _run(helpers, str(tmp_path / "osv"), Config(use_osv=True), secdb=False, osv=True)

    c = Config(use_osv=True, include_secdb=True)
    urls, count, both = _run(helpers, str(tmp_path / "both"), c, secdb=True, osv=True)

    assert urls == [c.osv_url, c.secdb_url]
    assert (len(secdb_only), len(osv_only)) == (192, 3)
    assert count == len(both) == 192 + 3
    assert set(both) == set(secdb_only) | set(osv_only)
    assert {i.split("/")[0] for i in both} == {"chainguard:rolling"}

    # every record is exactly what the single-feed run writes: same identifier, schema and payload
    for identifier, envelope in both.items():
        expected = secdb_only.get(identifier) or osv_only[identifier]
        assert envelope["schema"] == expected["schema"], identifier
        assert envelope["item"] == expected["item"], identifier


def test_provider_osv_with_secdb_rejects_shared_identifier(helpers, disable_get_requests, auto_fake_fixdate_finder, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(use_osv=True, include_secdb=True)
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)
    shutil.copytree(helpers.local_dir("test-fixtures/input/secdb"), os.path.join(str(workspace.input_dir), "secdb"))
    _make_osv_tar(helpers, workspace)

    # a secdb record named like an OSV record would overwrite it in the results store
    original = SecDBParser._normalize

    def normalize_with_osv_id(self, release, data):
        out = original(self, release, data)
        out["CGA-224q-ccj5-2p53"] = next(iter(out.values()))
        return out

    monkeypatch.setattr(SecDBParser, "_normalize", normalize_with_osv_id)

    with pytest.raises(ValueError, match="in both the OSV and the secdb feed"):
        p.update(None)
