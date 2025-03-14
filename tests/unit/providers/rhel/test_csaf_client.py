import os

import pytest
from pathlib import Path
from unittest.mock import MagicMock
from vunnel.providers.rhel.csaf_client import CSAFClient

@pytest.fixture()
def fixture_dir():
    return Path(__file__).parent / "test-fixtures"

@pytest.fixture()
def mock_workspace(helpers, fixture_dir):
    input_path = fixture_dir / "csaf" / "input"
    os.makedirs(input_path, exist_ok=True)

    return helpers.provider_workspace_helper(
            name="rhel",
            input_fixture=input_path,
        )

@pytest.fixture
def mock_http_get(mocker, fixture_dir):
    mock = mocker.patch('vunnel.utils.http_wrapper.get')

    fs = fixture_dir / "csaf/server"

    def request_side_effect(url, *args, **kwargs):
        requested_file = fs / url.removeprefix("https://example.com/advisories/")
        if not requested_file.exists():
            return MagicMock(status_code=404)
        if kwargs.get('stream'):
            response_mock = MagicMock(status_code=200)
            response_mock.iter_content = lambda chunk_size=65536: (
                requested_file.read_bytes()[i:i+chunk_size] for i in range(0, len(requested_file.read_bytes()), chunk_size)
            )
            response_mock.__enter__.return_value = response_mock # support "with"
            return response_mock
        return MagicMock(status_code=200, text=requested_file.read_text())

    mock.side_effect = request_side_effect
    return mock

@pytest.fixture
def mock_os_remove(mocker):
    return mocker.patch('os.remove')

@pytest.fixture
def mock_tar_extract(mocker):
    return mocker.patch('vunnel.providers.rhel.csaf_client.extract', autospec=True)

@pytest.fixture()
def latest_file_name(fixture_dir):
    return (fixture_dir / "csaf/server/archive_latest.txt").read_text()

def test_process_changes_and_deletions(mock_workspace, mock_http_get, mock_os_remove, mock_tar_extract, latest_file_name):
    latest_url = "https://example.com/advisories/archive_latest.txt"
    expected_tar_url = latest_url.replace(latest_file_name, "archive_latest.txt")
    changes_url = latest_url.replace("archive_latest.txt", "changes.csv")
    deletions_url = latest_url.replace("archive_latest.txt", "deletions.csv")
    changed_rhsa_url = latest_url.replace("archive_latest.txt", "2024/rhsa-2024_11255.json")
    other_changed_rhsa_url = latest_url.replace("archive_latest.txt", "2024/rhsa-2024_0010.json")
    deleted_rhsa_path = mock_workspace.input_path / "advisories" / "2024/rhsa-2024_2106.json"

    client = CSAFClient(workspace=mock_workspace, logger=MagicMock(), latest_url=latest_url)
    # Extract only the first argument (URL) from all calls
    called_urls = [args[0] for args, _ in mock_http_get.call_args_list]

    # Assert the expected URLs were requested
    assert latest_url in called_urls
    assert expected_tar_url in called_urls
    assert changes_url in called_urls
    assert deletions_url in called_urls
    # assert both changed files get re-downloaded
    assert changed_rhsa_url in called_urls
    assert other_changed_rhsa_url in called_urls

    # assert that it stops processing rows of changes.csv after encountering a data
    # before the archive latest date
    too_old_entries = [
        "2024/rhsa-2024_4444.json",
        "2024/rhsa-2024_5555.json",
        "2024/rhsa-2024_6666.json",
    ]
    too_old_changes_urls = [latest_url.replace("archive_latest.txt", entry) for entry in too_old_entries]
    assert not any(url in called_urls for url in too_old_changes_urls)

    # Check that os.remove was called for the deleted advisory
    called_paths = [args[0] for args, _ in mock_os_remove.call_args_list]
    assert deleted_rhsa_path in called_paths

    # assert that we can fetch the correct RHSA by ID
    doc = client.csaf_doc_for_rhsa("RHSA-2024:0010")
    assert doc.document.aggregate_severity.text == "Important"
    doc_self_link = next((r.url for r in doc.document.references if r.category == "self"), None)
    assert doc_self_link.endswith("RHSA-2024:0010")
