import shutil
from unittest.mock import patch

from vunnel import result
from vunnel.providers.alma import Config, Provider
from vunnel.providers.alma.parser import Parser


@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
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

    assert 4 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)

@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_parser(mock_git_delete, mock_git_clone, helpers):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())
    assert len(vuln_tuples) == 4
    assert vuln_tuples[0][0] == "almalinux8/ALBA-2021:4378"
    assert vuln_tuples[0][1] == "1.7.0"
    assert vuln_tuples[1][0] == "almalinux8/ALSA-2023:4520"
    assert vuln_tuples[1][1] == "1.7.0"
    assert vuln_tuples[2][0] == "almalinux9/ALSA-2022:8194"
    assert vuln_tuples[2][1] == "1.7.0"
    assert vuln_tuples[3][0] == "almalinux9/ALSA-2024:2433"
    assert vuln_tuples[3][1] == "1.7.0"
