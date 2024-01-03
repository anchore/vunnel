from __future__ import annotations

import shutil

import pytest
from pytest_unordered import unordered
from vunnel import result, workspace
from vunnel.providers.oracle import Config, Provider, parser


@pytest.mark.parametrize(
    ("input_file", "expected"),
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
                            "Description": "[1.1.1g-15] - version bump [1.1.1g-14] - CVE-2021-3450 openssl: CA certificate check bypass with X509_V_FLAG_X509_STRICT [1.1.1g-13] - Fix CVE-2021-3449 NULL pointer deref in signature_algorithms processing",
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
                        },
                    },
                ),
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
                                        "Module": None,
                                    },
                                    {
                                        "Name": "bind-devel",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "bind-sdb",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "bind-libbind-devel",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "bind",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "caching-nameserver",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "bind-chroot",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "bind-libs",
                                        "Version": "30:9.3.3-8.el5",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:5",
                                        "Module": None,
                                    },
                                ],
                            ),
                            "Link": "http://linux.oracle.com/errata/ELSA-2007-0057.html",
                            "Description": """[30:9.3.3-8]
 - added fix for #224445 - CVE-2007-0493 BIND might crash after
   attempting to read free()-ed memory
 - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service
 - Resolves: rhbz#224445
 - Resolves: rhbz#225229""",
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
                        },
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
                                        "Module": None,
                                    },
                                    {
                                        "Name": "kernel-uek",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "kernel-uek-firmware",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "kernel-uek-debug-devel",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "kernel-uek-devel",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                        "Module": None,
                                    },
                                    {
                                        "Name": "kernel-uek-debug",
                                        "Version": "0:2.6.39-400.302.2.el6uek",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:6",
                                        "Module": None,
                                    },
                                ],
                            ),
                            "Link": "http://linux.oracle.com/errata/ELSA-2018-4250.html",
                            "Description": """[2.6.39-400.302.2]
- Revert 'Fix up non-directory creation in SGID directories' (Brian Maly)  [Orabug: 28781234]

[2.6.39-400.302.1]
- Fix up non-directory creation in SGID directories (Linus Torvalds)  [Orabug: 28459479]  {CVE-2018-13405}
- ALSA: seq: Make ioctls race-free (Takashi Iwai)  [Orabug: 28459730]  {CVE-2018-7566}
- rds: CVE-2018-7492: Fix NULL pointer dereference in __rds_rdma_map (Hakon Bugge)  [Orabug: 28539910]  {CVE-2018-7492}
- cdrom: Fix info leak/OOB read in cdrom_ioctl_drive_status (Scott Bauer)  [Orabug: 28664549]  {CVE-2018-16658}
- ACPICA: acpi: acpica: fix acpi operand cache leak in nseval.c (Seunghun Han)  [Orabug: 28664580]  {CVE-2017-13695}
- exec: Limit arg stack to at most 75% of _STK_LIM (Kees Cook)  [Orabug: 28710024]  {CVE-2018-14634}""",
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
                        },
                    },
                ),
            },
        ),
    ],
)
def test_parse(tmpdir, helpers, input_file, expected):
    subject = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))

    mock_data_path = helpers.local_dir(input_file)

    vuln_dict = subject._parse_oval_data(mock_data_path, subject.config)

    assert vuln_dict == expected


class TestKspliceFilterer:
    @pytest.mark.parametrize(
        ("input_vulnerability", "expected_output"),
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
                                        "Module": None,
                                    },
                                ],
                            },
                        },
                    ),
                },
                {
                    ("ELSA-123", "ol:8"): (
                        "1",
                        {
                            "Vulnerability": {
                                "Name": "ELSA-123",
                                "FixedIn": [],
                            },
                        },
                    ),
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
                                        "Module": None,
                                    },
                                ],
                            },
                        },
                    ),
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
                                        "Module": None,
                                    },
                                ],
                            },
                        },
                    ),
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
                                        "Module": None,
                                    },
                                    {
                                        "Name": "openssl",
                                        "VersionFormat": "rpm",
                                        "NamespaceName": "ol:8",
                                        "Version": "2:1.1.1g-15.1.el8_3",
                                        "Module": None,
                                    },
                                ],
                            },
                        },
                    ),
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
                                        "Module": None,
                                    },
                                ],
                            },
                        },
                    ),
                },
            ),
        ],
    )
    def test_filterer(self, input_vulnerability, expected_output):
        f = parser.KspliceFilterer()
        assert f.filter(input_vulnerability) == expected_output


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/mock_data")
    shutil.copy(mock_data_path, workspace.input_dir / "com.oracle.elsa-all.xml")

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    assert workspace.num_result_entries() == 2
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    mock_data_path = helpers.local_dir("test-fixtures/mock_data")
    shutil.copy(mock_data_path, workspace.input_dir / "com.oracle.elsa-all.xml")

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
