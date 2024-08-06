from __future__ import annotations

import shutil

import defusedxml.ElementTree as ET
import pytest

from vunnel import result
from vunnel.providers.sles import Config, Provider
from vunnel.providers.sles.parser import (
    PARSER_CONFIG,
    Parser,
    SLESOVALVulnerability,
    SLESVulnerabilityParser,
)
from vunnel.utils.oval_v2 import (
    ArtifactParser,
    OVALElementEnum,
    OVALParserFactory,
    TestParser,
    VersionParser,
    iter_parse_vulnerability_file,
)
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics, FixedIn, Vulnerability, VendorAdvisory


class TestSLESVulnerabilityParser:
    # flake8: noqa: E501
    @pytest.fixture
    def valid_element(self):
        def generate(with_namespace):
            content = (
                "<metadata>"
                + "<title>CVE-2021-29154</title>"
                + '<affected family="unix">'
                + "<platform>SUSE Linux Enterprise Server 15 SP1-BCL</platform>"
                + "<platform>SUSE Linux Enterprise Server 15 SP1-LTSS</platform>"
                + "<platform>SUSE Linux Enterprise Server 15 SP2</platform>"
                + "<platform>SUSE Linux Enterprise Server 15 SP3</platform>"
                + "<platform>SUSE Linux Enterprise Server 15-LTSS</platform>"
                + "</affected>"
                + '<reference ref_id="Mitre CVE-2021-29154" ref_url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29154" source="CVE"/>'
                + '<reference ref_id="SUSE CVE-2021-29154" ref_url="https://www.suse.com/security/cve/CVE-2021-29154" source="SUSE CVE"/>'
                + "<description>    BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements, allowing them to execute arbitrary code within the kernel context. This affects arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c.    </description>"
                + '<advisory from="security@suse.de">'
                + '<issued date="2021-04-30"/>'
                + '<updated date="2021-07-14"/>'
                + "<severity>Important</severity>"
                + '<cve impact="important" cvss3="7/CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" href="https://www.suse.com/security/cve/CVE-2021-29154/">CVE-2021-29154</cve>'
                + '<bugzilla href="https://bugzilla.suse.com/1184391">SUSE bug 1184391</bugzilla>'
                + "<affected_cpe_list>"
                + "<cpe>cpe:/o:suse:sles-ltss:15:sp1</cpe>"
                + "<cpe>cpe:/o:suse:sles:15:sp2</cpe>"
                + "<cpe>cpe:/o:suse:sles:15:sp3</cpe>"
                + "<cpe>cpe:/o:suse:sles_bcl:15:sp1</cpe>"
                + "</affected_cpe_list>"
                + "</advisory>"
                + "</metadata>"
                + '<criteria operator="OR">'
                + '<criteria operator="AND">'
                + '<criterion test_ref="oval:org.opensuse.security:tst:2009302033" comment="SUSE Linux Enterprise Server 15-LTSS is installed"/>'
                + '<criteria operator="OR">'
                + '<criterion test_ref="oval:org.opensuse.security:tst:2009504818" comment="kernel-default-4.12.14-150.72.1 is installed"/>'
                + "</criteria>"
                + "</criteria>"
                + '<criteria operator="AND">'
                + '<criterion test_ref="oval:org.opensuse.security:tst:2009303869" comment="SUSE Linux Enterprise Server 15 SP1-BCL is installed"/>'
                + '<criteria operator="OR">'
                + '<criterion test_ref="oval:org.opensuse.security:tst:2009505291" comment="kernel-default-4.12.14-197.89.2 is installed"/>'
                + "</criteria>"
                + "</criteria>"
                + '<criteria operator="AND">'
                + '<criterion test_ref="oval:org.opensuse.security:tst:2009341508" comment="SUSE Linux Enterprise Server 15 SP1-LTSS is installed"/>'
                + '<criteria operator="OR">'
                + '<criterion test_ref="oval:org.opensuse.security:tst:2009505825" comment="kernel-default-4.12.14-197.89.2 is installed"/>'
                + "</criteria>"
                + "</criteria>"
                + "</criteria>"
                + "</definition>"
            )

            if with_namespace:
                beginning = '<definition id="oval:org.opensuse.security:def:202129154" version="1" class="vulnerability" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'
            else:
                beginning = '<definition id="oval:org.opensuse.security:def:202129154" version="1" class="vulnerability">'

            return beginning + content

        return generate

    @pytest.mark.parametrize("with_namespace", [True, False])
    def test_happy_paths(self, valid_element, with_namespace):
        xml_element = ET.fromstring(valid_element(with_namespace))
        result = SLESVulnerabilityParser.parse(xml_element, PARSER_CONFIG)
        assert result and isinstance(result, SLESOVALVulnerability)
        assert result.identity == "oval:org.opensuse.security:def:202129154"
        assert result.name == "CVE-2021-29154"
        assert result.severity == "High"
        assert (
            result.description
            == "BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements, allowing them to execute arbitrary code within the kernel context. This affects arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c."  # noqa: E501
        )
        assert result.link == "https://www.suse.com/security/cve/CVE-2021-29154"
        assert result.cvss_v3_vectors == ["CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"]

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="blank"),
            pytest.param(ET.fromstring('<rpminfo_state id="dummy"/>'), id="not-vulnerability"),
            pytest.param(
                ET.fromstring('<definition id="dummy" version="1" class="vulnerability"/>'),
                id="invalid-vulnerability",
            ),
        ],
    )
    def test_unhappy_paths(self, element):
        assert SLESVulnerabilityParser.parse(element, PARSER_CONFIG) is None


class TestSLESParser:
    @pytest.fixture
    def parsed_vulnerabilities(self):
        return [
            Vulnerability(
                Name="CVE-2021-29154",
                NamespaceName="sles:15",
                Description="BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements, allowing them to execute arbitrary code within the kernel context. This affects arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c.",  # noqa: E501
                Severity="High",
                Link="https://www.suse.com/security/cve/CVE-2021-29154",
                CVSS=[
                    CVSS(
                        version="3.1",
                        vector_string="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        base_metrics=CVSSBaseMetrics(
                            base_score=7.0,
                            exploitability_score=1.0,
                            impact_score=5.9,
                            base_severity="High",
                        ),
                        status="N/A",
                    )
                ],
                FixedIn=[
                    FixedIn(
                        Name="kernel-default",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:4.12.14-150.72.1",
                        Module=None,
                        VendorAdvisory=None,
                    )
                ],
                Metadata={},
            ),
            Vulnerability(
                Name="CVE-2010-1323",
                NamespaceName="sles:15",
                Description="MIT Kerberos 5 (aka krb5) 1.3.x, 1.4.x, 1.5.x, 1.6.x, 1.7.x, and 1.8.x through 1.8.3 does not properly determine the acceptability of checks\n                  ums, which might allow remote attackers to modify user-visible prompt text, modify a response to a Key Distribution Center (KDC), or forge a KRB-SAFE message via certain\n                  checksums that (1) are unkeyed or (2) use RC4 keys.",
                Severity="Medium",
                Link="https://www.suse.com/security/cve/CVE-2010-1323",
                CVSS=[
                    CVSS(
                        version="3.0",
                        vector_string="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        base_metrics=CVSSBaseMetrics(
                            base_score=3.7, exploitability_score=2.2, impact_score=1.4, base_severity="Low"
                        ),
                        status="N/A",
                    )
                ],
                FixedIn=[
                    FixedIn(
                        Name="krb5-plugin-kdb-ldap",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5-server",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5-32bit",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5-client",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5-devel",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5-plugin-preauth-otp",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                    FixedIn(
                        Name="krb5-plugin-preauth-pkinit",
                        NamespaceName="sles:15",
                        VersionFormat="rpm",
                        Version="0:1.15.2-4.25",
                        Module="",
                        VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
                        VulnerableRange=None,
                    ),
                ],
                Metadata={},
            ),
            Vulnerability(
                Name="CVE-2021-29154",
                NamespaceName="sles:15.1",
                Description="BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements, allowing them to execute arbitrary code within the kernel context. This affects arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c.",  # noqa: E501
                Severity="High",
                Link="https://www.suse.com/security/cve/CVE-2021-29154",
                CVSS=[
                    CVSS(
                        version="3.1",
                        vector_string="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        base_metrics=CVSSBaseMetrics(
                            base_score=7.0,
                            exploitability_score=1.0,
                            impact_score=5.9,
                            base_severity="High",
                        ),
                        status="N/A",
                    )
                ],
                FixedIn=[
                    FixedIn(
                        Name="kernel-default",
                        NamespaceName="sles:15.1",
                        VersionFormat="rpm",
                        Version="0:4.12.14-197.89.2",
                        Module=None,
                        VendorAdvisory=None,
                    )
                ],
                Metadata={},
            ),
        ]

    @pytest.mark.parametrize(
        "cvss_vector, expected",
        [
            pytest.param(
                "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                CVSS(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    base_metrics=CVSSBaseMetrics(
                        base_score=7.0,
                        exploitability_score=1.0,
                        impact_score=5.9,
                        base_severity="High",
                    ),
                    status="N/A",
                ),
                id="valid",
            )
        ],
    )
    def test_make_cvss_valid(self, cvss_vector, expected):
        assert Parser._make_cvss(cvss_vector, "NA") == expected

    @pytest.mark.parametrize(
        "cvss_vector",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="blank"),
            pytest.param(12345, id="invalid-type"),
        ],
    )
    def test_make_cvss_invalid(self, cvss_vector):
        assert Parser._make_cvss(cvss_vector, "NA") is None

    @pytest.mark.parametrize(
        "test_input, expected",
        [
            pytest.param(
                {"15": {"sles-release": "a", "sles-ltss-release": "b"}},
                ["a"],
                id="priority",
            ),
            pytest.param(
                {"15": {"sles-release": "c", "unknown": "b"}},
                ["c"],
                id="sles",
            ),
            pytest.param(
                {"15": {"unknown": "a", "sles-ltss-release": "d"}},
                ["d"],
                id="sles-ltss",
            ),
            pytest.param(
                {"15": {"foo": "a", "bar": "d"}},
                [],
                id="multiple-unsupported",
            ),
            pytest.param(
                {"15": {"foo": "f"}},
                ["f"],
                id="single",
            ),
        ],
    )
    def test_release_resolver(self, test_input, expected):
        actual = Parser._release_resolver(test_input, "NA")
        assert sorted(actual) == sorted(expected)

    def test_transform_oval_vulnerabilities(self, parsed_vulnerabilities, helpers):
        mock_data_path = helpers.local_dir("test-fixtures/suse_truncated.xml")

        parser_factory = OVALParserFactory(
            parsers=[
                SLESVulnerabilityParser,
                TestParser,
                ArtifactParser,
                VersionParser,
            ],
            element_enum=OVALElementEnum,
        )

        parsed_dict = iter_parse_vulnerability_file(
            mock_data_path,
            parser_config=PARSER_CONFIG,
            parser_factory=parser_factory,
        )

        actual = Parser._transform_oval_vulnerabilities("15", parsed_dict)
        actual.sort(key=lambda x: x.NamespaceName)
        parsed_vulnerabilities.sort(key=lambda x: x.NamespaceName)

        assert actual == parsed_vulnerabilities


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(allow_versions=["15"])
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/suse_truncated.xml")
    shutil.copy(mock_data_path, workspace.input_dir / "suse-linux-enterprise-server-15.xml")

    def mock_download(self, *args, **kwargs):
        return mock_data_path

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    assert 3 == workspace.num_result_entries()
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

    mock_data_path = helpers.local_dir("test-fixtures/suse_truncated.xml")
    shutil.copy(mock_data_path, workspace.input_dir / "suse-linux-enterprise-server-15.xml")

    def mock_download(self, *args, **kwargs):
        return mock_data_path

    monkeypatch.setattr(p.parser, "_download", mock_download)
    p.update(None)

    workspace.assert_result_snapshots()
