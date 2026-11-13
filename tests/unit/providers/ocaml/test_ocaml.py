import os
import shutil
import zipfile
from unittest.mock import MagicMock, patch

import pytest
from vunnel import result, schema
from vunnel.providers.ocaml import Config, Provider
from vunnel.providers.ocaml.parser import Parser


def _stage(helpers):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    shutil.copytree(helpers.local_dir("test-fixtures"), workspace.input_dir, dirs_exist_ok=True)
    return workspace


@patch("vunnel.providers.ocaml.parser.Parser._extract")
@patch("vunnel.providers.ocaml.parser.Parser._download")
def test_provider_schema(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = _stage(helpers)
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    assert 3 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)


@patch("vunnel.providers.ocaml.parser.Parser._extract")
@patch("vunnel.providers.ocaml.parser.Parser._download")
def test_parser(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = _stage(helpers)
    parser = Parser(ws=workspace, logger=None)

    vuln_tuples = list(parser.get())

    assert [(vuln_id, vuln_schema) for vuln_id, vuln_schema, _ in vuln_tuples] == [
        ("OSEC-2017-01", "1.7.4"),
        ("OSEC-2026-01", "1.7.4"),
        ("OSEC-2026-28", "1.7.4"),
    ]
    mock_download.assert_called_once()
    mock_extract.assert_called_once()


@patch("vunnel.providers.ocaml.parser.Parser._extract")
@patch("vunnel.providers.ocaml.parser.Parser._download")
def test_parser_patches_fix_dates_for_opam_ranges_only(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = _stage(helpers)
    parser = Parser(ws=workspace, logger=None)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    opam_affected, git_affected = records["OSEC-2026-01"]["affected"]
    assert opam_affected["package"]["ecosystem"] == "opam"
    for r in opam_affected["ranges"]:
        assert "anchore" in r["database_specific"]
    # the GIT ranges are in an entry without a package, which is left untouched
    for r in git_affected["ranges"]:
        assert "database_specific" not in r


def test_extract(helpers, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    parser = Parser(ws=workspace, logger=None)
    os.makedirs(workspace.input_dir, exist_ok=True)

    with zipfile.ZipFile(parser.zip_path, "w") as zf:
        zf.writestr("security-advisories-generated-osv/2026/OSEC-2026-01.json", '{"id": "OSEC-2026-01"}')
        zf.writestr("../escape.json", "{}")

    parser._extract()

    assert os.path.exists(os.path.join(parser.extract_dir, "security-advisories-generated-osv", "2026", "OSEC-2026-01.json"))
    assert not os.path.exists(os.path.join(workspace.input_dir, "escape.json"))
    assert [record["id"] for record in parser._load()] == ["OSEC-2026-01"]


def test_load_without_extracted_data(helpers, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    parser = Parser(ws=workspace, logger=None)

    assert list(parser._load()) == []


@pytest.mark.parametrize(
    ("schema_version", "expected"),
    [
        ("1.7.4", schema.OSVSchema("1.7.4")),
        ("1.7.5", schema.OSVSchema("1.7.5")),
        ("2.0.0", None),
    ],
)
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


@patch("vunnel.providers.ocaml.parser.Parser._extract")
@patch("vunnel.providers.ocaml.parser.Parser._download")
def test_provider_via_snapshot(mock_download, mock_extract, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = _stage(helpers)
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    workspace.assert_result_snapshots()


def test_provider_skip_download(helpers, auto_fake_fixdate_finder, monkeypatch):
    """With skip_download=True, no HTTP request should be made and pre-staged input is used."""
    workspace = _stage(helpers)
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)

    def _fail_on_http(*args, **kwargs):
        raise AssertionError("HTTP request attempted during skip_download test")

    monkeypatch.setattr("vunnel.utils.http_wrapper.get", _fail_on_http)
    monkeypatch.setattr("vunnel.utils.http_wrapper.download_to_file", _fail_on_http)

    p.update(None)

    assert 3 == workspace.num_result_entries()


def test_parser_default_finder_gets_skip_download(monkeypatch, helpers):
    default_finder = MagicMock()
    monkeypatch.setattr("vunnel.providers.ocaml.parser.fixdate.default_finder", default_finder)
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    Parser(ws=workspace, logger=None, skip_download=True)

    default_finder.assert_called_once_with(workspace, skip_download=True)
