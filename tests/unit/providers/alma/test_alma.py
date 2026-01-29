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

    assert 5 == workspace.num_result_entries()
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
    assert len(vuln_tuples) == 5
    assert vuln_tuples[0][0] == "almalinux8/ALBA-2021:4378"
    assert vuln_tuples[0][1] == "1.7.0"
    assert vuln_tuples[1][0] == "almalinux8/ALSA-2023:4520"
    assert vuln_tuples[1][1] == "1.7.0"
    assert vuln_tuples[2][0] == "almalinux8/ALSA-2023:5259"
    assert vuln_tuples[2][1] == "1.7.0"
    assert vuln_tuples[3][0] == "almalinux9/ALSA-2022:8194"
    assert vuln_tuples[3][1] == "1.7.0"
    assert vuln_tuples[4][0] == "almalinux9/ALSA-2024:2433"
    assert vuln_tuples[4][1] == "1.7.0"

    # Verify that ALSA-2023:5259 has modularity information extracted
    alsa_5259_record = vuln_tuples[2][2]  # Third record is ALSA-2023:5259
    assert alsa_5259_record["id"] == "ALSA-2023:5259"
    assert "affected" in alsa_5259_record

    # Check that both affected packages have modularity information
    for affected_pkg in alsa_5259_record["affected"]:
        assert "ecosystem_specific" in affected_pkg
        assert "rpm_modularity" in affected_pkg["ecosystem_specific"]
        assert affected_pkg["ecosystem_specific"]["rpm_modularity"] == "mariadb:10.3"


def test_modularity_parsing(helpers):
    """Test the _parse_modularity_from_summary method."""
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    parser = Parser(ws=workspace)

    # Test cases: (input_summary, expected_modularity)
    test_cases = [
        ("Moderate: mariadb:10.3 security update", "mariadb:10.3"),
        ("Important: nodejs:16 security update", "nodejs:16"),
        ("Critical: python38:3.8 security and bug fix update", "python38:3.8"),
        ("Low: httpd:2.4 security update", "httpd:2.4"),
        ("Moderate: mariadb:10.5 security, bug fix, and enhancement update", "mariadb:10.5"),

        # Edge cases that should return None
        ("No colon in module info", None),
        ("Moderate: just-text security update", None),  # no colon in module part
        ("Moderate security update", None),  # no second space
        ("Moderate:", None),  # no second space
        ("", None),  # empty string
        ("Moderate: :10.3 security update", None),  # starts with colon
        ("Moderate: mariadb: security update", None),  # ends with colon
        ("Single-word", None),  # no spaces at all
    ]

    for summary, expected in test_cases:
        result = parser._parse_modularity_from_summary(summary)
        assert result == expected, f"Failed for '{summary}': got '{result}', expected '{expected}'"
