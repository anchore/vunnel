from __future__ import annotations

import os
import shutil

import pytest

from vunnel import result, workspace
from vunnel.providers.rhel import Config, Provider, parser
from vunnel.providers.rhel.parser import Advisory, FixedIn, Parser


class TestParser:
    # flake8: noqa: E501
    @pytest.fixture
    def mock_cve(self):
        return {
            "threat_severity": "Low",
            "public_date": "2019-03-21T00:00:00Z",
            "bugzilla": {
                "description": "CVE-2019-9755 ntfs-3g: heap-based buffer overflow leads to local root privilege escalation",
                "id": "1691624",
                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1691624",
            },
            "cvss3": {
                "cvss3_base_score": "3.3",
                "cvss3_scoring_vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
                "status": "verified",
            },
            "cwe": "CWE-122",
            "details": [
                "An integer underflow issue exists in ntfs-3g 2017.3.23. A local attacker could potentially exploit this by running /bin/ntfs-3g with specially crafted arguments from a specially crafted directory to cause a heap buffer overflow, resulting in a crash or the ability to execute arbitrary code. In installations where /bin/ntfs-3g is a setuid-root binary, this could lead to a local escalation of privileges."
            ],
            "statement": "This flaw has a lower impact on Red Hat Enterprise Linux because the ntfs-3g tool is run in a supermin appliance, which is similar to a virtual machine instantiated on the fly, and it does not have the SUID bit set. Thus an attacker is very limited on what he can do to the vulnerable system.",
            "affected_release": [
                {
                    "product_name": "Advanced Virtualization for RHEL 8.1.0",
                    "release_date": "2019-11-06T00:00:00Z",
                    "advisory": "RHBA-2019:3723",
                    "cpe": "cpe:/a:redhat:advanced_virtualization:8.1::el8",
                },
                {
                    "product_name": "Red Hat Enterprise Linux 7",
                    "release_date": "2019-08-06T00:00:00Z",
                    "advisory": "RHSA-2019:2308",
                    "cpe": "cpe:/o:redhat:enterprise_linux:7",
                    "package": "libguestfs-winsupport-7.2-3.el7",
                },
                {
                    "product_name": "Red Hat Enterprise Linux 8",
                    "release_date": "2019-11-05T00:00:00Z",
                    "advisory": "RHSA-2019:3345",
                    "cpe": "cpe:/a:redhat:enterprise_linux:8",
                    "package": "virt:rhel-8010020190916153839.cdc1202b",
                },
            ],
            "package_state": [
                {
                    "product_name": "Red Hat Enterprise Linux 8 Advanced Virtualization",
                    "fix_state": "Affected",
                    "package_name": "virt:8.0.0/libguestfs-winsupport",
                    "cpe": "cpe:/a:redhat:advanced_virtualization:8::el8",
                },
                {
                    "product_name": "Red Hat Enterprise Linux 6",
                    "fix_state": "Will not fix",
                    "package_name": "libguestfs-winsupport",
                    "cpe": "cpe:/o:redhat:enterprise_linux:6",
                },
            ],
            "references": ["https://www.debian.org/security/2019/dsa-4413"],
            "name": "CVE-2019-9755",
        }

    # noqa: E501
    @pytest.fixture
    def mock_rhsa_dict(self):
        return {
            ("RHSA-2019:2308", "7"): (
                "632",
                {
                    "Vulnerability": {
                        "Severity": "Low",
                        "NamespaceName": "7",
                        "FixedIn": [
                            {
                                "Name": "libguestfs-winsupport",
                                "Version": "0:7.2-3.el7",
                                "VersionFormat": "rpm",
                                "NamespaceName": "7",
                            }
                        ],
                        "Link": "https://access.redhat.com/errata/RHSA-2019:2308",
                        "Description": "",
                        "Metadata": {
                            "Issued": "2019-08-06",
                            "Updated": "2019-08-06",
                            "RefId": "RHSA-2019:2308",
                            "CVE": [
                                {
                                    "Name": "CVE-2019-9755",
                                    "Link": "https://access.redhat.com/security/cve/CVE-2019-9755",
                                }
                            ],
                        },
                        "Name": "RHSA-2019:2308",
                        "CVSS": [],
                    }
                },
            )
        }

    # flake8: noqa: E501
    @pytest.fixture
    def mock_rhsa_dict_2(self):
        return {
            ("RHSA-2019:2308", "7"): (
                "632",
                {
                    "Vulnerability": {
                        "Severity": "Low",
                        "NamespaceName": "7",
                        "FixedIn": [
                            {
                                "Name": "libguestfs-winsupport",
                                "Version": "0:7.2-3.el7",
                                "VersionFormat": "rpm",
                                "NamespaceName": "7",
                            }
                        ],
                        "Link": "https://access.redhat.com/errata/RHSA-2019:2308",
                        "Name": "RHSA-2019:2308",
                    }
                },
            ),
            ("RHSA-2019:3345", "8"): (
                "765",
                {
                    "Vulnerability": {
                        "Severity": "Low",
                        "NamespaceName": "8",
                        "FixedIn": [
                            {
                                "Name": "libguestfs-winsupport",
                                "Version": "0:7.2-3.el8",
                                "VersionFormat": "rpm",
                                "NamespaceName": "8",
                            }
                        ],
                        "Link": "https://access.redhat.com/errata/RHSA-2019:3345",
                        "Name": "RHSA-2019:3345",
                    }
                },
            ),
        }

    # flake8: noqa: E501
    @pytest.fixture
    def mock_cve_partial_fix(self):
        return {
            "threat_severity": "Important",
            "public_date": "2017-11-24T00:00:00Z",
            "bugzilla": {
                "description": "CVE-2017-16939 Kernel: ipsec: xfrm: use-after-free leading to potential privilege escalation",
                "id": "1517220",
                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1517220",
            },
            "cvss": {
                "cvss_base_score": "6.2",
                "cvss_scoring_vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
                "status": "verified",
            },
            "cvss3": {
                "cvss3_base_score": "8.1",
                "cvss3_scoring_vector": "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "status": "verified",
            },
            "cwe": "CWE-416",
            "details": [
                "The XFRM dump policy implementation in net/xfrm/xfrm_user.c in the Linux kernel before 4.13.11 allows local users to gain privileges or cause a denial of service (use-after-free) via a crafted SO_RCVBUF setsockopt system call in conjunction with XFRM_MSG_GETPOLICY Netlink messages.",
                "The Linux kernel is vulerable to a use-after-free flaw when Transformation User configuration interface(CONFIG_XFRM_USER) compile-time configuration were enabled. This vulnerability occurs while closing a xfrm netlink socket in xfrm_dump_policy_done. A user/process could  abuse this flaw to potentially escalate their privileges on a system.",
            ],
            "statement": "This issue does not affect the versions of Linux kernel as shipped with Red Hat Enterprise Linux 5 and Red Hat Enterprise Linux 6.\nThis issue affects the version of the kernel package as shipped with Red Hat Enterprise Linux 7 and Red Hat Enterprise MRG 2. Future kernel updates for Red Hat Enterprise Linux 7 and Red Hat Enterprise MRG 2 may address this issue.",
            "affected_release": [
                {
                    "product_name": "Red Hat Enterprise Linux 7",
                    "release_date": "2018-05-08T00:00:00Z",
                    "advisory": "RHSA-2018:1355",
                    "cpe": "cpe:/a:redhat:rhel_extras_rt:7",
                    "package": "kernel-rt-0:3.10.0-862.2.3.rt56.806.el7",
                },
                {
                    "product_name": "Red Hat Enterprise Linux 7",
                    "release_date": "2018-05-08T00:00:00Z",
                    "advisory": "RHSA-2018:1318",
                    "cpe": "cpe:/o:redhat:enterprise_linux:7",
                    "package": "kernel-0:3.10.0-862.2.3.el7",
                },
            ],
            "package_state": [
                {
                    "product_name": "Red Hat Enterprise Linux 7",
                    "fix_state": "Affected",
                    "package_name": "kernel",
                    "cpe": "cpe:/o:redhat:enterprise_linux:7",
                }
            ],
            "name": "CVE-2017-16939",
        }

    def test_parse_affected_releases_0(self, mock_cve, tmpdir):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_dict = dict()

        results = driver._parse_affected_release(mock_cve.get("name"), mock_cve)

        assert results and isinstance(results, list) and len(results) == 1
        fixed_in = results[0]
        assert fixed_in.platform == "7"
        assert fixed_in.package == "libguestfs-winsupport"
        assert fixed_in.version == "7.2-3.el7"
        assert fixed_in.advisory.rhsa_id == "RHSA-2019:2308"

    @pytest.mark.parametrize(
        "affected_releases,fixed_ins",
        [
            (
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 7",
                            "advisory": "RHSA-2019:2308",
                            "package": "libguestfs-winsupport-7.2-3.el7",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "advisory": "RHSA-2019:3345",
                            # "package": "virt:rhel-8010020190916153839.cdc1202b" Deliberately skipping version
                        },
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="libguestfs-winsupport",
                        platform="7",
                        version="0:7.2-3.el7",
                        advisory=Advisory(
                            wont_fix=False,
                            rhsa_id="RHSA-2019:2308",
                            severity=None,
                            link="https://access.redhat.com/errata/RHSA-2019:2308",
                        ),
                    ),
                    FixedIn(
                        module=None,
                        package="libguestfs-winsupport",
                        platform="8",
                        version="0:7.2-3.el8",
                        advisory=Advisory(
                            wont_fix=False,
                            rhsa_id="RHSA-2019:3345",
                            severity=None,
                            link="https://access.redhat.com/errata/RHSA-2019:3345",
                        ),
                    ),
                ],
            ),
            (
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 7",
                            "advisory": "RHSA-2019:2308",
                            "package": "libguestfs-winsupport-7.2-3.el7",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "advisory": "RHSA-2019:3345",
                            "package": "virt:rhel-8010020190916153839.cdc1202b"
                            # package name lookup using RHSA and other packages shouldn't yield any results
                        },
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="libguestfs-winsupport",
                        platform="7",
                        version="0:7.2-3.el7",
                        advisory=Advisory(
                            wont_fix=False,
                            rhsa_id="RHSA-2019:2308",
                            severity=None,
                            link="https://access.redhat.com/errata/RHSA-2019:2308",
                        ),
                    )
                ],
            ),
            (
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 7",
                            "advisory": "RHSA-2019:1234",
                            "package": "libguestfs-winsupport-7.2-3.el7",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "advisory": "RHSA-2019:5678",
                            "package": "virt:rhel-8010020190916153839.cdc1202b"
                            # RHSA lookup shouldn't yield results
                        },
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="libguestfs-winsupport",
                        platform="7",
                        version="7.2-3.el7",
                        advisory=Advisory(
                            wont_fix=False,
                            rhsa_id="RHSA-2019:1234",
                            severity=None,
                            link="https://access.redhat.com/errata/RHSA-2019:1234",
                        ),
                    )
                ],
            ),
            (
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 7",
                            "package": "libguestfs-winsupport-7.2-3.el7",
                        }
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="libguestfs-winsupport",
                        platform="7",
                        version="7.2-3.el7",
                        advisory=Advisory(wont_fix=False, rhsa_id=None, link=None, severity=None),
                    )
                ],
            ),
            (
                # same package and platform, different versions - streams
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 7",
                            "package": "libguestfs-winsupport-7.2-3.el7",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 7",
                            "package": "libguestfs-winsupport-7.2-3.el7.1",
                        },
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="libguestfs-winsupport",
                        platform="7",
                        version="7.2-3.el7.1",
                        advisory=Advisory(wont_fix=False, rhsa_id=None, link=None, severity=None),
                    )
                ],
            ),
            (
                # same package and platform, different versions - major, minor
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "package": "nodejs-1:11.19.1-2.module+el8.1.0+6118+5aaa808b",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "package": "nodejs-1:10.19.0-2.module+el8.1.0+6118+5aaa808b",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 8",
                            "package": "nodejs-1:12.16.1-2.module+el8.1.0+6117+b25a342c",
                        },
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="nodejs",
                        platform="8",
                        version="1:12.16.1-2.module+el8.1.0+6117+b25a342c",
                        advisory=Advisory(wont_fix=False, rhsa_id=None, link=None, severity=None),
                    )
                ],
            ),
            (
                # same package and platform, different versions - release, stream
                {
                    "affected_release": [
                        {
                            "product_name": "Red Hat Enterprise Linux 6",
                            "package": "qemu-kvm-2:0.12.1.2-2.160.el6_1.9",
                        },
                        {
                            "product_name": "Red Hat Enterprise Linux 6",
                            "package": "qemu-kvm-2:0.12.1.2-2.209.el6_2.1",
                        },
                    ],
                    "name": "CVE-2019-9755",
                },
                [
                    FixedIn(
                        module=None,
                        package="qemu-kvm",
                        platform="6",
                        version="2:0.12.1.2-2.209.el6_2.1",
                        advisory=Advisory(wont_fix=False, rhsa_id=None, link=None, severity=None),
                    )
                ],
            ),
        ],
    )
    def test_parse_affected_releases(self, tmpdir, affected_releases, fixed_ins, mock_rhsa_dict_2):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_dict = mock_rhsa_dict_2

        results = driver._parse_affected_release(affected_releases.get("name"), affected_releases)
        assert isinstance(results, list) and len(results) == len(fixed_ins)
        results.sort(key=lambda x: x.platform)
        fixed_ins.sort(key=lambda x: x.platform)
        assert results == fixed_ins

    def test_parse_package_state(self, tmpdir, mock_cve):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        results = driver._parse_package_state(mock_cve.get("name"), mock_cve)

        assert results and isinstance(results, list) and len(results) == 1
        fixed_in = results[0]
        assert fixed_in.platform == "6"
        assert fixed_in.package == "libguestfs-winsupport"
        assert fixed_in.version == "None"
        assert fixed_in.advisory.wont_fix is True

    def test_parse_cve(self, tmpdir, mock_cve):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_dict = dict()

        results = driver._parse_cve(mock_cve.get("name"), mock_cve)
        assert results and isinstance(results, list) and len(results) == 2
        assert sorted([item.namespace for item in results]) == ["rhel:6", "rhel:7"]
        payloads = [item.payload.get("Vulnerability", {}) for item in results]
        assert all(payload.get("Name") == mock_cve.get("name") for payload in payloads)
        assert all(payload.get("Severity") == "Low" for payload in payloads)

    def test_parse_cve_partial_fix(self, tmpdir, mock_cve_partial_fix):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_dict = dict()

        results = driver._parse_cve(mock_cve_partial_fix.get("name"), mock_cve_partial_fix)
        assert results and isinstance(results, list) and len(results) == 1
        fixed_ins = results[0].payload.get("Vulnerability").get("FixedIn")
        assert fixed_ins and isinstance(fixed_ins, list) and len(fixed_ins) == 2
        assert sorted([item.get("Name") for item in fixed_ins]) == [
            "kernel",
            "kernel-rt",
        ]
        kernel_record = next(item for item in fixed_ins if item.get("Name") == "kernel")
        assert kernel_record and kernel_record.get("Version") == "None"

    @pytest.mark.parametrize(
        "test_id,test_p,test_pkg,expected",
        [
            ("RHSA-2019:2308", "7", "libguestfs-winsupport", ("0:7.2-3.el7", None)),
            ("foo", "0", "bar", (None, None)),
        ],
    )
    def test_fetch_rhsa_fix_version(self, tmpdir, mock_rhsa_dict, test_id, test_p, test_pkg, expected):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_dict = mock_rhsa_dict

        assert driver._fetch_rhsa_fix_version(test_id, test_p, test_pkg) == expected

    @pytest.mark.parametrize(
        "package,name,version",
        [
            ("haproxy-0:1.8.15-6.el8_1.1", "haproxy", "0:1.8.15-6.el8_1.1"),
            (
                "java-1.8.0-openjdk-1:1.8.0.252.b09-2.el8_1",
                "java-1.8.0-openjdk",
                "1:1.8.0.252.b09-2.el8_1",
            ),
            ("container-tools:rhel8-801002019092709091", "container-tools", None),
            ("0:libsndfile-1.0.28-10.el8", "libsndfile", "0:1.0.28-10.el8"),
            ("kernel-rt", "kernel-rt", None),
            ("libjpeg-6b-38", "libjpeg", "6b-38"),
        ],
    )
    def test_get_name_version(self, package, name, version):
        assert Parser._get_name_version(package) == (name, version)


@pytest.mark.parametrize(
    "affected, out_of_support, expected",
    [
        (
            [
                FixedIn(
                    module=None,
                    platform="6",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [
                FixedIn(
                    module=None,
                    platform="5",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [
                FixedIn(
                    module=None,
                    platform="6",
                    package="foobar",
                    advisory=None,
                    version=None,
                ),
                FixedIn(
                    module=None,
                    platform="5",
                    package="foobar",
                    advisory=None,
                    version=None,
                ),
            ],
        ),
        (
            [
                FixedIn(
                    module=None,
                    platform="5",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [
                FixedIn(
                    module=None,
                    platform="6",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [
                FixedIn(
                    module=None,
                    platform="5",
                    package="foobar",
                    advisory=None,
                    version=None,
                ),
            ],
        ),
        (
            [
                FixedIn(
                    module=None,
                    platform="7",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [],
            [
                FixedIn(
                    module=None,
                    platform="7",
                    package="foobar",
                    advisory=None,
                    version=None,
                ),
            ],
        ),
        (
            [],
            [
                FixedIn(
                    module=None,
                    platform="7",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [],
        ),
        (
            [
                FixedIn(
                    module=None,
                    platform="8",
                    package="foobar",
                    advisory=None,
                    version=None,
                )
            ],
            [
                FixedIn(
                    module=None,
                    platform="7",
                    package="foobar2",
                    advisory=None,
                    version=None,
                )
            ],
            [
                FixedIn(
                    module=None,
                    platform="8",
                    package="foobar",
                    advisory=None,
                    version=None,
                ),
            ],
        ),
    ],
)
def test_out_of_support(affected, out_of_support, expected):
    assert Parser._merge_out_of_support_affected(affected, out_of_support) == expected


@pytest.fixture
def disable_get_requests(monkeypatch):
    def disabled(*args, **kwargs):
        raise RuntimeError("requests disabled but HTTP GET attempted")

    monkeypatch.setattr(parser.requests, "get", disabled)


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    def mock_sync_cves(*args, **kwargs):
        return os.path.join(p.parser.cve_dir_path, p.parser.__full_dir_name__)

    def mock_init_rhsa_data(*args, **kwargs):
        return {}

    monkeypatch.setattr(p.parser, "_sync_cves", mock_sync_cves)
    monkeypatch.setattr(p.parser, "_init_rhsa_data", mock_init_rhsa_data)

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    p.update(None)

    assert 18 == workspace.num_result_entries()
    # list of 18 entries:
    #   "CVE-2017-3539" (rhel 5)
    #   "CVE-2017-3539" (rhel 6)
    #   "CVE-2017-3539" (rhel 7)
    #   "CVE-2017-3509" (rhel 5)
    #   "CVE-2017-3509" (rhel 6)
    #   "CVE-2017-3509" (rhel 7)
    #   "CVE-2017-3533" (rhel 5)
    #   "CVE-2017-3533" (rhel 6)
    #   "CVE-2017-3533" (rhel 7)
    #   "CVE-2017-3526" (rhel 5)
    #   "CVE-2017-3526" (rhel 6)
    #   "CVE-2017-3526" (rhel 7)
    #   "CVE-2017-3544" (rhel 5)
    #   "CVE-2017-3544" (rhel 6)
    #   "CVE-2017-3544" (rhel 7)
    #   "CVE-2017-3511" (rhel 5)
    #   "CVE-2017-3511" (rhel 6)
    #   "CVE-2017-3511" (rhel 7)

    assert workspace.result_schemas_valid(require_entries=True)
