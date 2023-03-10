from __future__ import annotations

import shutil

import pytest
from vunnel import result, workspace
from vunnel.providers import centos
from vunnel.providers.centos import Parser, parser


@pytest.mark.parametrize(
    ("mock_data_path", "full_entry"),
    [
        (
            "test-fixtures/centos-3-entry",
            {
                "Vulnerability": {
                    "Severity": "",
                    "NamespaceName": "centos:3",
                    "FixedIn": [
                        {
                            "Name": "htdig",
                            "Version": "2:3.1.6-7.el3",
                            "VersionFormat": "rpm",
                            "NamespaceName": "centos:3",
                            "Module": None,
                        },
                    ],
                    "Link": "https://access.redhat.com/errata/RHSA-0000-0000",
                    "Description": "",
                    "Metadata": {
                        "Issued": "2007-06-07",
                        "Updated": "2008-03-20",
                        "RefId": "RHSA-0000-0000",
                        "CVE": [{"Name": "CVE-2000-1191", "Link": "https://access.redhat.com/security/cve/CVE-2000-1191"}],
                    },
                    "Name": "RHSA-0000-0000",
                    "CVSS": [],
                },
            },
        ),
        (
            "test-fixtures/centos-7-entry",
            {
                "Vulnerability": {
                    "Severity": "",
                    "NamespaceName": "centos:7",
                    "FixedIn": [
                        {
                            "Name": "htdig",
                            "Version": "2:3.1.6-7.el3",
                            "VersionFormat": "rpm",
                            "NamespaceName": "centos:7",
                            "Module": None,
                        },
                    ],
                    "Link": "https://access.redhat.com/errata/RHSA-0000-0000",
                    "Description": "",
                    "Metadata": {
                        "Issued": "2007-06-07",
                        "Updated": "2008-03-20",
                        "RefId": "RHSA-0000-0000",
                        "CVE": [{"Name": "CVE-2000-1191", "Link": "https://access.redhat.com/security/cve/CVE-2000-1191"}],
                    },
                    "Name": "RHSA-0000-0000",
                    "CVSS": [],
                },
            },
        ),
    ],
)
def test_parser(tmpdir, helpers, mock_data_path, full_entry):
    mock_data_path = helpers.local_dir(mock_data_path)

    parser = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
    shutil.copy(mock_data_path, parser.xml_file_path)
    vuln_dict = parser.parse()

    assert vuln_dict is not None
    _, (_, vuln) = vuln_dict.popitem()

    assert vuln == full_entry


@pytest.fixture()
def disable_get_requests(monkeypatch):
    def disabled(*args, **kwargs):
        raise RuntimeError("requests disabled but HTTP GET attempted")

    monkeypatch.setattr(parser.requests, "get", disabled)


@pytest.mark.parametrize(
    ("mock_data_path", "expected_written_entries"),
    [
        ("test-fixtures/centos-3-entry", 0),
        ("test-fixtures/centos-7-entry", 1),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=centos.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    c = centos.Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = centos.Provider(
        root=workspace.root,
        config=c,
    )
    shutil.copy(mock_data_path, p.parser.xml_file_path)

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)
