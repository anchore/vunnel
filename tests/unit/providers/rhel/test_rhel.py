from __future__ import annotations

import os
import shutil
from unittest.mock import patch

import pytest

from vunnel import result, workspace
from vunnel.providers.rhel import Config, Provider, parser
from vunnel.providers.rhel.parser import Advisory, AffectedRelease, FixedIn, Parser
from vunnel.providers.rhel.rhsa_provider import OVALRHSAProvider


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

    # flake8: noqa: E501
    @pytest.fixture
    def mock_eus_cve(self):
        return {
            "threat_severity" : "Moderate",
            "public_date" : "2024-01-18T00:00:00Z",
            "bugzilla" : {
                "description" : "kernel: ext4: kernel bug in ext4_write_inline_data_end()",
                "id" : "2261976",
                "url" : "https://bugzilla.redhat.com/show_bug.cgi?id=2261976"
            },
            "cvss3" : {
                "cvss3_base_score" : "6.7",
                "cvss3_scoring_vector" : "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
                "status" : "verified"
            },
            "cwe" : "CWE-190",
            "details" : [ "Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from 5.10.0-60.18.0 before 5.10.0-183.0.0.", "A flaw was found in the openEuler kernel in Linux filesystem modules that allows an integer overflow via mounting a corrupted filesystem. This issue affects the openEuler kernel in versions from 4.19.90 through 4.19.90-2401.3 and 5.10.0-60.18.0 through 5.10.0-183.0.0." ],
            "statement" : "Red Hat has protection mechanisms in place against buffer overflows, such as FORTIFY_SOURCE, Position Independent Executables or Stack Smashing Protection.",
            "affected_release" : [ {
                "product_name" : "Red Hat Enterprise Linux 8",
                "release_date" : "2024-04-02T00:00:00Z",
                "advisory" : "RHSA-2024:1614",
                "cpe" : "cpe:/a:redhat:enterprise_linux:8::nfv",
                "package" : "kernel-rt-0:4.18.0-513.24.1.rt7.326.el8_9"
            }, {
                "product_name" : "Red Hat Enterprise Linux 8",
                "release_date" : "2024-04-02T00:00:00Z",
                "advisory" : "RHSA-2024:1607",
                "cpe" : "cpe:/o:redhat:enterprise_linux:8",
                "package" : "kernel-0:4.18.0-513.24.1.el8_9"
            }, {
                "product_name" : "Red Hat Enterprise Linux 8.6 Extended Update Support",
                "release_date" : "2024-04-03T00:00:00Z",
                "advisory" : "RHSA-2024:1653",
                "cpe" : "cpe:/o:redhat:rhel_eus:8.6",
                "package" : "kernel-0:4.18.0-372.98.1.el8_6"
            }, {
                "product_name" : "Red Hat Enterprise Linux 8.8 Extended Update Support",
                "release_date" : "2024-04-30T00:00:00Z",
                "advisory" : "RHSA-2024:2621",
                "cpe" : "cpe:/o:redhat:rhel_eus:8.8",
                "package" : "kernel-0:4.18.0-477.55.1.el8_8"
            }, {
                "product_name" : "Red Hat Enterprise Linux 9",
                "release_date" : "2023-05-09T00:00:00Z",
                "advisory" : "RHSA-2023:2458",
                "cpe" : "cpe:/a:redhat:enterprise_linux:9",
                "package" : "kernel-0:5.14.0-284.11.1.el9_2"
            }, {
                "product_name" : "Red Hat Enterprise Linux 9",
                "release_date" : "2023-05-09T00:00:00Z",
                "advisory" : "RHSA-2023:2148",
                "cpe" : "cpe:/a:redhat:enterprise_linux:9::nfv",
                "package" : "kernel-rt-0:5.14.0-284.11.1.rt14.296.el9_2"
            }, {
                "product_name" : "Red Hat Enterprise Linux 9",
                "release_date" : "2023-05-09T00:00:00Z",
                "advisory" : "RHSA-2023:2458",
                "cpe" : "cpe:/o:redhat:enterprise_linux:9",
                "package" : "kernel-0:5.14.0-284.11.1.el9_2"
            }, {
                "product_name" : "Red Hat Enterprise Linux 9.0 Extended Update Support",
                "release_date" : "2024-04-16T00:00:00Z",
                "advisory" : "RHSA-2024:1836",
                "cpe" : "cpe:/a:redhat:rhel_eus:9.0",
                "package" : "kernel-0:5.14.0-70.97.1.el9_0"
            }, {
                "product_name" : "Red Hat Enterprise Linux 9.0 Extended Update Support",
                "release_date" : "2024-04-16T00:00:00Z",
                "advisory" : "RHSA-2024:1840",
                "cpe" : "cpe:/a:redhat:rhel_eus:9.0::nfv",
                "package" : "kernel-rt-0:5.14.0-70.97.1.rt21.169.el9_0"
            }, {
                "product_name" : "Red Hat Virtualization 4 for Red Hat Enterprise Linux 8",
                "release_date" : "2024-04-03T00:00:00Z",
                "advisory" : "RHSA-2024:1653",
                "cpe" : "cpe:/o:redhat:rhev_hypervisor:4.4::el8",
                "package" : "kernel-0:4.18.0-372.98.1.el8_6"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/cluster-logging-operator-bundle:v5.7.13-16"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/cluster-logging-rhel8-operator:v5.7.13-7"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/elasticsearch6-rhel8:v6.8.1-408"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/elasticsearch-operator-bundle:v5.7.13-19"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/elasticsearch-proxy-rhel8:v1.0.0-480"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/elasticsearch-rhel8-operator:v5.7.13-9"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/eventrouter-rhel8:v0.4.0-248"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/fluentd-rhel8:v1.14.6-215"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/kibana6-rhel8:v6.8.1-431"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/log-file-metric-exporter-rhel8:v1.1.0-228"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/logging-curator5-rhel8:v5.8.1-471"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/logging-loki-rhel8:v2.9.6-15"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/logging-view-plugin-rhel8:v5.7.13-3"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/loki-operator-bundle:v5.7.13-27"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/loki-rhel8-operator:v5.7.13-12"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/lokistack-gateway-rhel8:v0.1.0-527"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/opa-openshift-rhel8:v0.1.0-225"
            }, {
                "product_name" : "RHOL-5.7-RHEL-8",
                "release_date" : "2024-05-01T00:00:00Z",
                "advisory" : "RHSA-2024:2093",
                "cpe" : "cpe:/a:redhat:logging:5.7::el8",
                "package" : "openshift-logging/vector-rhel8:v0.28.1-57"
            } ],
            "package_state" : [ {
                "product_name" : "Red Hat Enterprise Linux 6",
                "fix_state" : "Out of support scope",
                "package_name" : "kernel",
                "cpe" : "cpe:/o:redhat:enterprise_linux:6"
            }, {
                "product_name" : "Red Hat Enterprise Linux 7",
                "fix_state" : "Out of support scope",
                "package_name" : "kernel",
                "cpe" : "cpe:/o:redhat:enterprise_linux:7"
            }, {
                "product_name" : "Red Hat Enterprise Linux 7",
                "fix_state" : "Out of support scope",
                "package_name" : "kernel-rt",
                "cpe" : "cpe:/o:redhat:enterprise_linux:7"
            } ],
            "references" : [ "https://www.cve.org/CVERecord?id=CVE-2021-33631\nhttps://nvd.nist.gov/vuln/detail/CVE-2021-33631\nhttps://seclists.org/oss-sec/2024/q1/65" ],
            "name" : "CVE-2021-33631",
            "mitigation" : {
                "value" : "Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base or stability.",
                "lang" : "en:us"
            },
            "csaw" : False
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

    def test_parse_affected_releases_eus(self, mock_eus_cve, tmpdir):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_provider = OVALRHSAProvider.from_rhsa_dict({})

        results = driver._parse_affected_release(mock_eus_cve.get("name"), mock_eus_cve)

        assert results and isinstance(results, list) and len(results) == 8

        # see https://access.redhat.com/security/cve/cve-2021-33631
        expected = [
            FixedIn(package='kernel-rt', platform='8', version='0:4.18.0-513.24.1.rt7.326.el8_9', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2024:1614', link='https://access.redhat.com/errata/RHSA-2024:1614', severity=None)),
            FixedIn(package='kernel', platform='8', version='0:4.18.0-513.24.1.el8_9', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2024:1607', link='https://access.redhat.com/errata/RHSA-2024:1607', severity=None)),
            FixedIn(package='kernel', platform='8.6+eus', version='0:4.18.0-372.98.1.el8_6', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2024:1653', link='https://access.redhat.com/errata/RHSA-2024:1653', severity=None)),
            FixedIn(package='kernel', platform='8.8+eus', version='0:4.18.0-477.55.1.el8_8', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2024:2621', link='https://access.redhat.com/errata/RHSA-2024:2621', severity=None)),
            FixedIn(package='kernel', platform='9', version='0:5.14.0-284.11.1.el9_2', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2023:2458', link='https://access.redhat.com/errata/RHSA-2023:2458', severity=None)),
            FixedIn(package='kernel-rt', platform='9', version='0:5.14.0-284.11.1.rt14.296.el9_2', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2023:2148', link='https://access.redhat.com/errata/RHSA-2023:2148', severity=None)),
            FixedIn(package='kernel', platform='9.0+eus', version='0:5.14.0-70.97.1.el9_0', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2024:1836', link='https://access.redhat.com/errata/RHSA-2024:1836', severity=None)),
            FixedIn(package='kernel-rt', platform='9.0+eus', version='0:5.14.0-70.97.1.rt21.169.el9_0', module=None, advisory=Advisory(wont_fix=False, rhsa_id='RHSA-2024:1840', link='https://access.redhat.com/errata/RHSA-2024:1840', severity=None)),
        ]

        assert expected == results

    def test_parse_affected_releases_0(self, mock_cve, tmpdir):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_provider = OVALRHSAProvider.from_rhsa_dict({})

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
                            "package": "virt:rhel-8010020190916153839.cdc1202b",
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
                            "package": "virt:rhel-8010020190916153839.cdc1202b",
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
        ids=["case1" , "case2", "case3", "case4", "case5", "case6", "case7"],
    )
    def test_parse_affected_releases(self, tmpdir, affected_releases, fixed_ins, mock_rhsa_dict_2):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_provider = OVALRHSAProvider.from_rhsa_dict(mock_rhsa_dict_2)

        results = driver._parse_affected_release(affected_releases.get("name"), affected_releases)
        assert isinstance(results, list)
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
        driver.rhsa_provider = OVALRHSAProvider.from_rhsa_dict({})

        results = driver._parse_cve(mock_cve.get("name"), mock_cve)
        assert results and isinstance(results, list) and len(results) == 2
        assert sorted([item.namespace for item in results]) == ["rhel:6", "rhel:7"]
        payloads = [item.payload.get("Vulnerability", {}) for item in results]
        assert all(payload.get("Name") == mock_cve.get("name") for payload in payloads)
        assert all(payload.get("Severity") == "Low" for payload in payloads)

    def test_parse_cve_partial_fix(self, tmpdir, mock_cve_partial_fix):
        driver = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        driver.rhsa_provider = OVALRHSAProvider.from_rhsa_dict({})

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
        driver.rhsa_provider = OVALRHSAProvider.from_rhsa_dict(mock_rhsa_dict)

        ar_obj = AffectedRelease(rhsa_id=test_id, platform=test_p, name=test_pkg)

        assert driver._fetch_rhsa_fix_version("cve-123-123", ar_obj) == expected

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


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/oval/input",
    )

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    def mock_sync_cves(*args, **kwargs):
        return os.path.join(p.parser.cve_dir_path, p.parser.__full_dir_name__)

    def mock_init_rhsa_data(*args, **kwargs):
        p.parser.rhsa_provider = OVALRHSAProvider.from_rhsa_dict({})

    monkeypatch.setattr(p.parser, "_sync_cves", mock_sync_cves)
    monkeypatch.setattr(p.parser, "_init_rhsa_data", mock_init_rhsa_data)

    p.update(None)

    assert workspace.num_result_entries() == 70
    # < test results directory >
    # ├── rhel:5
    # │   ├── cve-2017-3509.json
    # │   ├── cve-2017-3511.json
    # │   ├── cve-2017-3526.json
    # │   ├── cve-2017-3533.json
    # │   ├── cve-2017-3539.json
    # │   └── cve-2017-3544.json
    # ├── rhel:6
    # │   ├── cve-2017-3509.json
    # │   ├── cve-2017-3511.json
    # │   ├── cve-2017-3526.json
    # │   ├── cve-2017-3533.json
    # │   ├── cve-2017-3539.json
    # │   ├── cve-2017-3544.json
    # │   ├── cve-2020-16587.json
    # │   ├── cve-2020-16588.json
    # │   ├── cve-2021-20298.json
    # │   ├── cve-2021-20299.json
    # │   ├── cve-2022-1921.json
    # │   ├── cve-2022-1922.json
    # │   ├── cve-2022-1923.json
    # │   ├── cve-2022-1924.json
    # │   ├── cve-2022-1925.json
    # │   ├── cve-2023-4863.json
    # │   ├── cve-2023-5129.json
    # │   └── cve-2023-5217.json
    # ├── rhel:7
    # │   ├── cve-2017-3509.json
    # │   ├── cve-2017-3511.json
    # │   ├── cve-2017-3526.json
    # │   ├── cve-2017-3533.json
    # │   ├── cve-2017-3539.json
    # │   ├── cve-2017-3544.json
    # │   ├── cve-2020-16587.json
    # │   ├── cve-2020-16588.json
    # │   ├── cve-2021-20298.json
    # │   ├── cve-2021-20299.json
    # │   ├── cve-2022-1921.json
    # │   ├── cve-2022-1922.json
    # │   ├── cve-2022-1923.json
    # │   ├── cve-2022-1924.json
    # │   ├── cve-2022-1925.json
    # │   ├── cve-2023-4863.json
    # │   ├── cve-2023-5129.json
    # │   └── cve-2023-5217.json
    # ├── rhel:8
    # │   ├── cve-2019-25059.json
    # │   ├── cve-2020-16587.json
    # │   ├── cve-2021-20298.json
    # │   ├── cve-2021-20299.json
    # │   ├── cve-2022-1921.json
    # │   ├── cve-2022-1922.json
    # │   ├── cve-2022-1923.json
    # │   ├── cve-2022-1924.json
    # │   ├── cve-2022-1925.json
    # │   ├── cve-2023-4863.json
    # │   ├── cve-2023-5129.json
    # │   └── cve-2023-5217.json
    # ├── rhel:8.6+eus
    # │   ├── cve-2023-4863.json
    # │   ├── cve-2023-5129.json
    # │   └── cve-2023-5217.json
    # ├── rhel:9
    # │   ├── cve-2019-25059.json
    # │   ├── cve-2022-1921.json
    # │   ├── cve-2022-1922.json
    # │   ├── cve-2022-1923.json
    # │   ├── cve-2022-1924.json
    # │   ├── cve-2022-1925.json
    # │   ├── cve-2022-2309.json
    # │   ├── cve-2023-4863.json
    # │   ├── cve-2023-5129.json
    # │   └── cve-2023-5217.json
    # └── rhel:9.0+eus
    #     ├── cve-2023-4863.json
    #     ├── cve-2023-5129.json
    #     └── cve-2023-5217.json

    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/oval/input",
    )

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.rhsa_source = "OVAL"
    p = Provider(root=workspace.root, config=c)

    def mock_sync_cves(*args, **kwargs):
        return os.path.join(p.parser.cve_dir_path, p.parser.__full_dir_name__)

    def mock_init_rhsa_data(*args, **kwargs):
        p.parser.rhsa_provider = OVALRHSAProvider.from_rhsa_dict({})

        return {}

    monkeypatch.setattr(p.parser, "_sync_cves", mock_sync_cves)
    monkeypatch.setattr(p.parser, "_init_rhsa_data", mock_init_rhsa_data)

    p.update(None)

    workspace.assert_result_snapshots()


@patch("vunnel.providers.rhel.Parser._sync_cves")
def test_rhel_provider_supports_skip_download(mock_sync_cves, helpers):
    assert Provider.supports_skip_download()

    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/csaf/input",
    )

    mock_sync_cves.side_effect = RuntimeError("should not be called")

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    c.rhsa_source = "CSAF"
    p = Provider(root=workspace.root, config=c)

    with pytest.raises(RuntimeError) as e:
        p.update(None)
        assert e.match("skip download used on empty workspace")
    assert mock_sync_cves.call_count == 0
