import json
import os

import pytest

from vunnel import result, workspace
from vunnel.providers import epss
from vunnel.providers.epss import manager


@pytest.mark.parametrize(
    ("mock_data_path", "expected_vulns"),
    [
        ("test-fixtures/example-1.csv",
            [
                ('CVE-1999-0001',{'cve': 'CVE-1999-0001','date': '2025-02-20','epss': 0.00383,'percentile': 0.73075}),
                ('CVE-1999-0002',{'cve': 'CVE-1999-0002','date': '2025-02-20','epss': 0.01328,'percentile': 0.85996}),
                ('CVE-1999-0003',{'cve': 'CVE-1999-0003','date': '2025-02-20','epss': 0.04409,'percentile': 0.9244}),
                ('CVE-1999-0004',{'cve': 'CVE-1999-0004','date': '2025-02-20','epss': 0.00917,'percentile': 0.82963}),
                ('CVE-1999-0005',{'cve': 'CVE-1999-0005','date': '2025-02-20','epss': 0.91963,'percentile': 0.99214}),
            ],
        ),
    ],
)
def test_parser(tmpdir, helpers, mocker,  mock_data_path, expected_vulns):
    mock_data_path = helpers.local_dir(mock_data_path)

    subject = manager.Manager(
        dataset="current",
        ws=workspace.Workspace(tmpdir, "test", create=True),
        url_template="http://localhost/nowhere/epss_scores-{}.csv.gz",
    )

    subject._download = mocker.Mock(return_value=mock_data_path)

    actual_vulns = list(subject.get())

    assert expected_vulns == actual_vulns


@pytest.mark.parametrize(
    ("mock_data_path", "expected_written_entries"),
    [
        ("test-fixtures/example-1.csv", 5),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries, disable_get_requests, mocker):
    workspace = helpers.provider_workspace_helper(name=epss.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    # Setup provider
    c = epss.Config()
    p = epss.Provider(root=workspace.root, config=c)
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p.manager._download = mocker.Mock(return_value=mock_data_path)

    p.update(None)

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)


@pytest.mark.parametrize(
    ("mock_data_path",),
    [
        ("test-fixtures/example-1.csv",),
    ],
)
def test_provider_via_snapshot(helpers, mock_data_path, disable_get_requests, mocker):
    snapshot_name = os.path.basename(mock_data_path).split(".")[0]

    workspace = helpers.provider_workspace_helper(
        name=epss.Provider.name(),
        snapshot_prefix=snapshot_name,
    )
    mock_data_path = helpers.local_dir(mock_data_path)

    c = epss.Config()
    p = epss.Provider(
        root=workspace.root,
        config=c,
    )
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p.manager._download = mocker.Mock(return_value=mock_data_path)

    p.update(None)

    workspace.assert_result_snapshots()


@pytest.mark.parametrize(
    ("test_file", "exception_type"),
    [
        pytest.param(
            "test-fixtures/missing-date.csv",
            ValueError,
            id="missing-date-header",
        ),
        pytest.param(
            "test-fixtures/invalid-header.csv",
            ValueError,
            id="invalid-csv-header",
        ),
    ],
)
def test_manager_normalize_invalid_data(
    tmpdir, helpers, test_file, exception_type
):
    ws = workspace.Workspace(tmpdir, "test", create=True)
    subject = manager.Manager(dataset="current", ws=ws)

    test_file_path = helpers.local_dir(test_file)

    with pytest.raises(exception_type):
        list(subject._normalize(test_file_path))


def test_count_lines(tmpdir):
    test_file = os.path.join(tmpdir, "test.txt")
    content = "line1\nline2\nline3"

    with open(test_file, "w") as f:
        f.write(content)

    assert manager._count_lines(test_file) == 3
