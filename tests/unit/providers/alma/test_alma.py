import datetime
import os
import shutil
from unittest.mock import patch

from vunnel import result
from vunnel.providers.alma import Config, Provider
from vunnel.providers.alma.parser import Parser


@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_provider_schema(mock_git_delete, mock_git_clone, helpers, auto_fake_fixdate_finder):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    p.update(None)

    assert 6 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)

@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_parser(mock_git_delete, mock_git_clone, helpers, auto_fake_fixdate_finder):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_data_path = helpers.local_dir("test-fixtures")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())
    assert len(vuln_tuples) == 6
    assert vuln_tuples[0][0] == "almalinux8/ALBA-2021:4378"
    assert vuln_tuples[0][1] == "1.7.0"
    assert vuln_tuples[1][0] == "almalinux8/ALSA-2019:3706"
    assert vuln_tuples[1][1] == "1.7.0"
    assert vuln_tuples[2][0] == "almalinux8/ALSA-2023:4520"
    assert vuln_tuples[2][1] == "1.7.0"
    assert vuln_tuples[3][0] == "almalinux8/ALSA-2023:5259"
    assert vuln_tuples[3][1] == "1.7.0"
    assert vuln_tuples[4][0] == "almalinux9/ALSA-2022:8194"
    assert vuln_tuples[4][1] == "1.7.0"
    assert vuln_tuples[5][0] == "almalinux9/ALSA-2024:2433"
    assert vuln_tuples[5][1] == "1.7.0"

    # Verify that ALSA-2023:5259 has modularity information extracted
    alsa_5259_record = vuln_tuples[3][2]  # Fourth record is ALSA-2023:5259
    assert alsa_5259_record["id"] == "ALSA-2023:5259"
    assert "affected" in alsa_5259_record

    # Check that both affected packages have modularity information
    for affected_pkg in alsa_5259_record["affected"]:
        assert "ecosystem_specific" in affected_pkg
        assert "rpm_modularity" in affected_pkg["ecosystem_specific"]
        assert affected_pkg["ecosystem_specific"]["rpm_modularity"] == "mariadb:10.3"


def test_modularity_parsing(helpers, auto_fake_fixdate_finder):
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


def _parse_fixtures(helpers, mock_git_delete, mock_git_clone):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    shutil.copytree(helpers.local_dir("test-fixtures"), workspace.input_dir, dirs_exist_ok=True)
    return {vuln_id: record for vuln_id, _, record in Parser(ws=workspace).get()}


def _fixes(affected):
    return [f for r in affected["ranges"] for f in r["database_specific"]["anchore"]["fixes"]]


@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_published_date_becomes_fix_date(mock_git_delete, mock_git_clone, helpers, fake_fixdate_finder):
    fake_fixdate_finder(responses=[])
    records = _parse_fixtures(helpers, mock_git_delete, mock_git_clone)
    record = records["almalinux9/ALSA-2022:8194"]

    for affected in record["affected"]:
        fixed = [e["fixed"] for r in affected["ranges"] for e in r["events"] if "fixed" in e]
        assert _fixes(affected) == [{"version": v, "date": "2022-11-15", "kind": "advisory"} for v in fixed]


@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_library_clone_carries_fix_dates(mock_git_delete, mock_git_clone, helpers, fake_fixdate_finder):
    fake_fixdate_finder(responses=[])
    record = _parse_fixtures(helpers, mock_git_delete, mock_git_clone)["almalinux8/ALSA-2019:3706"]
    by_name = {a["package"]["name"]: a for a in record["affected"]}

    assert "lua-libs" in by_name
    assert _fixes(by_name["lua-libs"]) == _fixes(by_name["lua"])
    assert _fixes(by_name["lua"]) == [{"version": "5.3.4-11.el8", "date": "2019-11-05", "kind": "advisory"}]


@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_record_level_advisory_marker_kept(mock_git_delete, mock_git_clone, helpers, auto_fake_fixdate_finder):
    for record in _parse_fixtures(helpers, mock_git_delete, mock_git_clone).values():
        assert record["database_specific"]["anchore"] == {"record_type": "advisory"}


def _offline_download(self):
    # act as if ghcr has no alma dataset, without a network call
    self._downloaded = True
    self._not_found = True


@patch("vunnel.tool.fixdate.grype_db_first_observed.Store.download", _offline_download)
@patch("vunnel.providers.alma.git.GitWrapper.clone_repo")
@patch("vunnel.providers.alma.git.GitWrapper.delete_repo")
def test_fix_dates_stable_across_runs(mock_git_delete, mock_git_clone, helpers):
    mock_git_clone.return_value = None
    mock_git_delete.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    p = Provider(root=workspace.root, config=Config())
    shutil.copytree(helpers.local_dir("test-fixtures"), workspace.input_dir, dirs_exist_ok=True)

    def run(day):
        with patch("vunnel.tool.fixdate.first_observed.datetime") as dt:
            dt.now.return_value = datetime.datetime(2030, 1, day, tzinfo=datetime.timezone.utc)
            p.update(None)
        with result.SQLiteReader(os.path.join(workspace.results_dir, "results.db")) as reader:
            return {e.item["id"]: (e.item["published"][:10], [_fixes(a) for a in e.item["affected"]]) for e in reader.each()}

    first = run(1)
    second = run(15)

    assert len(first) == 6
    assert first == second
    for published, fixes in first.values():
        assert fixes
        for affected_fixes in fixes:
            assert {f["date"] for f in affected_fixes} == {published}
