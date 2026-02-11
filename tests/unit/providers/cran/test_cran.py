import shutil
from unittest.mock import patch

import pytest

from vunnel import result, schema
from vunnel.providers.cran import Config, Provider
from vunnel.providers.cran.parser import Parser


@patch("vunnel.providers.cran.git.GitWrapper.clone_repo")
@patch("vunnel.providers.cran.git.GitWrapper.delete_repo")
def test_provider_schema(mock_git_delete, mock_git_clone, helpers, auto_fake_fixdate_finder, disable_get_requests):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    assert 2 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)


@patch("vunnel.providers.cran.git.GitWrapper.clone_repo")
@patch("vunnel.providers.cran.git.GitWrapper.delete_repo")
def test_parser(mock_git_delete, mock_git_clone, helpers, disable_get_requests, auto_fake_fixdate_finder):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())
    assert len(vuln_tuples) == 2
    # sorted by directory name (jsonlite < readxl)
    assert vuln_tuples[0][0] == "RSEC-2023-3"
    assert vuln_tuples[0][1] == "1.6.1"
    assert vuln_tuples[1][0] == "RSEC-2023-2"
    assert vuln_tuples[1][1] == "1.6.1"


@patch("vunnel.providers.cran.git.GitWrapper.clone_repo")
@patch("vunnel.providers.cran.git.GitWrapper.delete_repo")
def test_parser_upstream_normalization(mock_git_delete, mock_git_clone, helpers, disable_get_requests, auto_fake_fixdate_finder):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())

    # Both fixtures have "upstream" fields - verify they were moved to "aliases"
    for _vuln_id, _schema_ver, record in vuln_tuples:
        assert "upstream" not in record, "upstream field should be normalized to aliases"
        assert "aliases" in record, "aliases field should be present after normalization"


@pytest.mark.parametrize(
    "schema_version,expected",
    [
        ("1.5.0", schema.OSVSchema(version="1.5.0")),
        ("1.6.1", schema.OSVSchema(version="1.6.1")),
        ("0.6.0", None),
        ("2.4.0", None),
    ],
)
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


@patch("vunnel.providers.cran.git.GitWrapper.clone_repo")
@patch("vunnel.providers.cran.git.GitWrapper.delete_repo")
def test_provider_via_snapshot(mock_git_delete, mock_git_clone, helpers, auto_fake_fixdate_finder, disable_get_requests):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    workspace.assert_result_snapshots()
