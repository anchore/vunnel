from __future__ import annotations

import os
import shutil

import pytest
from vunnel import result, workspace
from vunnel.providers import centos
from vunnel.providers.centos import Parser, parser


@pytest.mark.parametrize(
    ("mock_data_path", "full_entry"),
    [
        (
            "test-fixtures/oval-v1-centos-3-entry",
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
            "test-fixtures/oval-v2-rhel-7-entry",
            {
                "Vulnerability": {
                    "CVSS": [],
                    "Description": "",
                    "FixedIn": [
                        {
                            "Module": None,
                            "Name": "firefox",
                            "NamespaceName": "centos:7",
                            "Version": "0:102.9.0-3.el7_9",
                            "VersionFormat": "rpm",
                        },
                    ],
                    "Link": "https://access.redhat.com/errata/RHSA-2023:1333",
                    "Metadata": {
                        "CVE": [
                            {"Link": "https://access.redhat.com/security/cve/CVE-2023-25751", "Name": "CVE-2023-25751"},
                            {"Link": "https://access.redhat.com/security/cve/CVE-2023-25752", "Name": "CVE-2023-25752"},
                            {"Link": "https://access.redhat.com/security/cve/CVE-2023-28162", "Name": "CVE-2023-28162"},
                            {"Link": "https://access.redhat.com/security/cve/CVE-2023-28164", "Name": "CVE-2023-28164"},
                            {"Link": "https://access.redhat.com/security/cve/CVE-2023-28176", "Name": "CVE-2023-28176"},
                        ],
                        "Issued": "2023-03-20",
                        "RefId": "RHSA-2023:1333",
                        "Updated": "2023-03-20",
                    },
                    "Name": "RHSA-2023:1333",
                    "NamespaceName": "centos:7",
                    "Severity": "High",
                }
            },
        ),
    ],
)
def test_parser(tmpdir, mocker, helpers, mock_data_path, full_entry):
    mock_data_path = helpers.local_dir(mock_data_path)

    ws = workspace.Workspace(tmpdir, "test", create=True)
    parser = Parser(workspace=ws)
    xml_path = os.path.join(ws.input_path, "mock.xml")
    shutil.copy(mock_data_path, xml_path)
    mocker.patch.object(parser, "xml_paths", return_value=[xml_path])

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
        ("test-fixtures/oval-v1-centos-3-entry", 0),
        ("test-fixtures/oval-v2-rhel-7-entry", 1),
    ],
)
def test_provider_schema(helpers, mocker, mock_data_path, expected_written_entries, disable_get_requests, monkeypatch):
    ws = helpers.provider_workspace_helper(name=centos.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    c = centos.Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = centos.Provider(
        root=ws.root,
        config=c,
    )
    xml_path = os.path.join(ws.input_dir, "mock.xml")
    shutil.copy(mock_data_path, xml_path)
    mocker.patch.object(p.parser, "xml_paths", return_value=[xml_path])

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    assert expected_written_entries == ws.num_result_entries()
    assert ws.result_schemas_valid(require_entries=expected_written_entries > 0)
