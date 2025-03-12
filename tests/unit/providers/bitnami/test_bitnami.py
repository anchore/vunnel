
import shutil

import pytest
from vunnel import result, schema
from vunnel.providers.bitnami import Provider, Config

from unittest.mock import patch

from vunnel.providers.bitnami.parser import Parser

@patch("vunnel.providers.bitnami.git.GitWrapper.clone_repo")
@patch("vunnel.providers.bitnami.git.GitWrapper.delete_repo")
def test_provider_schema(mock_git_delete, mock_git_clone, helpers):
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

@patch("vunnel.providers.bitnami.git.GitWrapper.clone_repo")
@patch("vunnel.providers.bitnami.git.GitWrapper.delete_repo")
def test_parser(mock_git_delete, mock_git_clone, helpers):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())
    assert len(vuln_tuples) == 2
    assert vuln_tuples[0][0] == "BIT-brotli-2020-8927"
    assert vuln_tuples[0][1] == "1.5.0"
    assert vuln_tuples[1][0] == "BIT-consul-2021-37219"
    assert vuln_tuples[1][1] == "1.5.0"

@pytest.mark.parametrize("schema_version,expected",
                         [
                         ("1.5.0", schema.OSVSchema(version="1.5.0")),
                         ("1.6.1", schema.OSVSchema(version="1.6.1")),
                          ("0.6.0", None),
                          ("2.4.0", None),
                         ])
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected
