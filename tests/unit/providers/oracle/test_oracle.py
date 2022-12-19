import shutil

import pytest
from pytest_unordered import unordered

from vunnel.providers.oracle import Config, Provider, parser


@pytest.mark.parametrize(
    "input_file,expected",
    [
        # TEST 1 ############################################################
        (
            "test-fixtures/mock_ksplice_data",
            {
                ("ELSA-2021-9151", "ol:8"): (
                    "501",
                    {
                        "Vulnerability": {
                            "Severity": "High",
                            "NamespaceName": "ol:8",
                            "FixedIn": [],
                            "Link": "https://linux.oracle.com/errata/ELSA-2021-9151.html",
                            "Description": "",
                            "Metadata": {
                                "Issued": "2021-04-01",
                                "RefId": "ELSA-2021-9151",
                                "CVE": [
                                    {
                                        "Name": "CVE-2021-3449",
                                        "Link": "https://linux.oracle.com/cve/CVE-2021-3449.html",
                                    },
                                    {
                                        "Name": "CVE-2021-3450",
                                        "Link": "https://linux.oracle.com/cve/CVE-2021-3450.html",
                                    },
                                ],
                            },
                            "Name": "ELSA-2021-9151",
                            "CVSS": [],
                        }
                    },
                )
            },
        ),
        # TEST 2 ############################################################
        (
            "test-fixtures/mock_data",
            {
                ("ELSA-2007-0057", "ol:5"): (
                    "501",
                    {
                        "Vulnerability": {
                            "Severity": "Medium",
                            "NamespaceName": "ol:5",
                            "FixedIn": unordered(
                                [
                                    {
                                        "Name": "bind-utils",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "bind-devel",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "bind-sdb",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "bind-libbind-devel",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "bind",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "caching-nameserver",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "bind-chroot",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                    {
                                        "Name": "bind-libs",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                    },
                                ]
                            ),
                            "Link": "http://linux.oracle.com/errata/ELSA-2007-0057.html",
                            "Description": "",
                            "Metadata": {
                                "Issued": "2007-06-26",
                                "RefId": "ELSA-2007-0057",
                                "CVE": [
                                    {
                                        "Name": "CVE-2007-0493",
                                        "Link": "http://linux.oracle.com/cve/CVE-2007-0493.html",
                                    },
                                    {
                                        "Name": "CVE-2007-0494",
                                        "Link": "http://linux.oracle.com/cve/CVE-2007-0494.html",
                                    },
                                ],
                            },
                            "Name": "ELSA-2007-0057",
                            "CVSS": [],
                        }
                    },
                ),
                ("ELSA-2018-4250", "ol:6"): (
                    "501",
                    {
                        "Vulnerability": {
                            "Severity": "High",
                            "NamespaceName": "ol:6",
                            "FixedIn": unordered(
                                [
                                    {
                                        "Name": "kernel-uek-doc",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                    },
                                    {
                                        "Name": "kernel-uek",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                    },
                                    {
                                        "Name": "kernel-uek-firmware",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                    },
                                    {
                                        "Name": "kernel-uek-debug-devel",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                    },
                                    {
                                        "Name": "kernel-uek-devel",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                    },
                                    {
                                        "Name": "kernel-uek-debug",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                    },
                                ]
                            ),
                            "Link": "http://linux.oracle.com/errata/ELSA-2018-4250.html",
                            "Description": "",
                            "Metadata": {
                                "Issued": "2018-10-12",
                                "RefId": "ELSA-2018-4250",
                                "CVE": [
                                    {
                                        "Name": "CVE-2018-7566",
                                        "Link": "http://linux.oracle.com/cve/CVE-2018-7566.html",
                                    },
                                    {
                                        "Name": "CVE-2017-13695",
                                        "Link": "http://linux.oracle.com/cve/CVE-2017-13695.html",
                                    },
                                    {
                                        "Name": "CVE-2018-16658",
                                        "Link": "http://linux.oracle.com/cve/CVE-2018-16658.html",
                                    },
                                    {
                                        "Name": "CVE-2018-7492",
                                        "Link": "http://linux.oracle.com/cve/CVE-2018-7492.html",
                                    },
                                ],
                            },
                            "Name": "ELSA-2018-4250",
                            "CVSS": [],
                        }
                    },
                ),
            },
        ),
    ],
)
def test_parse(tmpdir, helpers, input_file, expected):
    subject = parser.Parser(workspace=tmpdir)

    mock_data_path = helpers.local_dir(input_file)

    vuln_dict = subject._parse_oval_data(mock_data_path, subject.config)

    assert vuln_dict == expected


class TestKspliceFilterer:
    @pytest.mark.parametrize(
        ["input_vulnerability", "expected_output"],
        [
            (
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.ksplice1.el8_3",
                                    }
                                ],
                            }
                        },
                    )
                },
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [],
                            }
                        },
                    )
                },
            ),
            (
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.1.el8_3",
                                    }
                                ],
                            }
                        },
                    )
                },
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.1.el8_3",
                                    }
                                ],
                            }
                        },
                    )
                },
            ),
            (
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.ksplice1.el8_3",
                                    },
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.1.el8_3",
                                    },
                                ],
                            }
                        },
                    )
                },
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.1.el8_3",
                                    }
                                ],
                            }
                        },
                    )
                },
            ),
        ],
    )
    def test_filterer(self, input_vulnerability, expected_output):
        f = parser.KspliceFilterer()
        assert f.filter(input_vulnerability) == expected_output


@pytest.fixture
def disable_get_requests(monkeypatch):
    def disabled(*args, **kwargs):
        raise RuntimeError("requests disabled but HTTP GET attempted")

    monkeypatch.setattr(parser.requests, "get", disabled)


def test_provider_schema(helpers, disable_get_requests):
    workspace = helpers.provider_workspace(name=Provider.name)

    provider = Provider(root=workspace.root, config=Config())

    mock_data_path = helpers.local_dir("test-fixtures/mock_data")
    shutil.copy(mock_data_path, workspace.input_dir / "com.oracle.elsa-all.xml")

    provider.update()

    assert 2 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)
