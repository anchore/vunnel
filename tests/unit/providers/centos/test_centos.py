import shutil

import pytest

from vunnel.providers import centos
from vunnel.providers.centos.parser import Parser


@pytest.mark.parametrize(
    "mock_data_path,full_entry",
    [
        (
            "test-fixtures/centos-3-entry",
            {
                "Vulnerability": {
                    "Severity": "",
                    "NamespaceName": "centos:3",
                    "FixedIn": [
                        {"Name": "htdig", "Version": "2:3.1.6-7.el3", "VersionFormat": "rpm", "NamespaceName": "centos:3"}
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
                }
            },
        ),
        (
            "test-fixtures/centos-7-entry",
            {
                "Vulnerability": {
                    "Severity": "",
                    "NamespaceName": "centos:7",
                    "FixedIn": [
                        {"Name": "htdig", "Version": "2:3.1.6-7.el3", "VersionFormat": "rpm", "NamespaceName": "centos:7"}
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
                }
            },
        ),
    ],
)
def test_parser(tmpdir, helpers, mock_data_path, full_entry):
    mock_data_path = helpers.local_dir(mock_data_path)

    parser = Parser(workspace=tmpdir)
    shutil.copy(mock_data_path, parser.xml_file_path)
    vuln_dict = parser.parse()

    assert vuln_dict is not None
    _, (_, vuln) = vuln_dict.popitem()

    assert vuln == full_entry


@pytest.mark.parametrize(
    "mock_data_path,expected_written_entries",
    [
        ("test-fixtures/centos-3-entry", 0),
        ("test-fixtures/centos-7-entry", 1),
    ],
)
def test_provider_schema(helpers, mock_data_path, expected_written_entries):
    workspace = helpers.provider_workspace(name=centos.Provider.name())
    mock_data_path = helpers.local_dir(mock_data_path)

    provider = centos.Provider(root=workspace.root, config=centos.Config())
    shutil.copy(mock_data_path, provider.parser.xml_file_path)
    provider.update()

    assert expected_written_entries == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=expected_written_entries > 0)
