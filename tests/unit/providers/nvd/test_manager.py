from __future__ import annotations

import json

import pytest
from vunnel import workspace, schema
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

    subject = manager.Manager(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        schema=schema.NVDSchema(),
        overrides_url="http://example.com",
    )
    subject.api.cve = mocker.Mock(return_value=[json_dict])
    actual_vulns = list(subject.get(None))

    assert expected_vulns == actual_vulns
    for vuln in actual_vulns:
        assert subject._sqlite_reader().read(vuln[0].lower()) is not None
