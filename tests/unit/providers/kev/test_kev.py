import json
import os

import pytest

from vunnel import result, workspace, schema
from vunnel.providers import kev
from vunnel.providers.kev import manager


@pytest.mark.parametrize(
    "mock_data_path",
    [
        "test-fixtures/single-entry/example1.json",
    ],
)
def test_parser(tmpdir, helpers, mock_data_path, mocker):
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    catalog = {
        "vulnerabilities": [json_dict],
    }

    expected_vulns = []
    for v in catalog["vulnerabilities"]:
        cve_id = v["cveID"]
        expected_vulns.append((cve_id, v))

    subject = manager.Manager(
        url="http://localhost/nowhere",
        workspace=workspace.Workspace(tmpdir, "test", create=True),
    )
    subject._download = mocker.Mock(return_value=catalog)
    actual_vulns = list(subject.get())

    assert expected_vulns == actual_vulns

@pytest.mark.parametrize(
    ("mock_data_path", "expected_written_entries"),
    [
        ("test-fixtures/valid-catalog-1.json", 3),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries, disable_get_requests, mocker):
    workspace = helpers.provider_workspace_helper(name=kev.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        mock_response = json.load(f)

    c = kev.Config()
    p = kev.Provider(root=workspace.root, config=c)
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE

    mock_response_obj = mocker.Mock()
    mock_response_obj.text = json.dumps(mock_response)
    mock_response_obj.json.return_value = mock_response

    mocker.patch('vunnel.utils.http_wrapper.get', return_value=mock_response_obj)

    p.update(None)

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)


@pytest.mark.parametrize(
    ("mock_data_path",),
    [
        ("test-fixtures/valid-catalog-1.json",),
    ],
)
def test_provider_via_snapshot(helpers, mock_data_path, disable_get_requests, mocker):
    snapshot_name = os.path.basename(mock_data_path).split(".")[0]

    workspace = helpers.provider_workspace_helper(
        name=kev.Provider.name(),
        snapshot_prefix=snapshot_name,
    )

    c = kev.Config()
    p = kev.Provider(
        root=workspace.root,
        config=c,
    )
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE

    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        mock_response = json.load(f)

    mock_response_obj = mocker.Mock()
    mock_response_obj.text = json.dumps(mock_response)
    mock_response_obj.json.return_value = mock_response

    mocker.patch('vunnel.utils.http_wrapper.get', return_value=mock_response_obj)

    p.update(None)

    workspace.assert_result_snapshots()
