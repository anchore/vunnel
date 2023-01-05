import json

import pytest

from vunnel import workspace
from vunnel.providers import nvd
from vunnel.providers.nvd import manager


@pytest.mark.parametrize(
    "mock_data_path",
    [
        "test-fixtures/single-entry.json",
    ],
)
def test_parser(tmpdir, helpers, mock_data_path, mocker):
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    expected_vulns = []
    for v in json_dict["vulnerabilities"]:
        cve_id = v["cve"]["id"]
        year = cve_id.split("-")[1]
        identity = f"{year}/{cve_id}"
        expected_vulns.append((identity, v))

    subject = manager.Manager(workspace=workspace.Workspace(tmpdir, "test", create=True))
    subject.api.cve = mocker.Mock(return_value=[json_dict])
    actual_vulns = [v for v in subject.get()]

    assert expected_vulns == actual_vulns


@pytest.mark.parametrize(
    "mock_data_path,expected_written_entries",
    [
        ("test-fixtures/single-entry.json", 1),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries, mocker):
    workspace = helpers.provider_workspace_helper(name=nvd.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    provider = nvd.Provider(root=workspace.root, config=nvd.Config())
    provider.manager.api.cve = mocker.Mock(return_value=[json_dict])

    provider.update()

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)
