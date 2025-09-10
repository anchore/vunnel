"""
Test cases for the 4 AlmaLinux inheritance scenarios described:

1. AlmaLinux has A-prefixed advisory (always takes precedence) - use Alma version
2. AlmaLinux has corresponding advisory with package entry - use Alma version
3. AlmaLinux advisory exists but no package entry, with consensus version - use consensus version
4. Fall back to RHEL version - inherit RHEL version and advisory information
"""

import copy
import os
import tempfile
from unittest.mock import patch

import pytest

from vunnel.providers.rhel import Config, Provider
from vunnel.workspace import Workspace


class TestAlmaInheritanceCases:
    @pytest.fixture
    def rhel_config_with_alma(self):
        return Config(include_alma_fixes=True)

    @pytest.fixture
    def mock_alma_workspace_with_scenarios(self):
        """Create mock AlmaLinux errata data covering all 4 test scenarios"""
        with tempfile.TemporaryDirectory() as tmpdir:
            rhel_input_dir = os.path.join(tmpdir, "rhel", "input")
            alma_dir = os.path.join(rhel_input_dir, "alma-errata-data")
            os.makedirs(alma_dir, exist_ok=True)

            import orjson

            mock_errata_8 = [
                {
                    "updateinfo_id": "ALSA-2025:A004",
                    "type": "security",
                    "severity": "Critical",
                    "title": "Critical: vulnerable-pkg security update",
                    "pkglist": {"packages": [{"name": "vulnerable-pkg", "epoch": "0", "version": "2.1.0", "release": "1.el8.alma"}]},
                    "references": [],
                },
                {
                    "updateinfo_id": "ALSA-2025:A005",
                    "type": "security",
                    "severity": "Critical",
                    "title": "Critical: libblockdev security update",
                    "pkglist": {"packages": [{"name": "libblockdev", "epoch": "0", "version": "2.28", "release": "6.el8.alma.1"}]},
                    "references": [],
                },
                {
                    "updateinfo_id": "ALSA-2022:6158",
                    "type": "security",
                    "severity": "Moderate",
                    "title": "Moderate: php:7.4 security update",
                    "pkglist": {"packages": [{"name": "php", "epoch": "0", "version": "7.4.19", "release": "4.module_el8.6.0+3238+624bf8b8"}]},
                    "references": [{"type": "rhsa", "id": "RHSA-2022:6158"}],
                },
                {
                    "updateinfo_id": "ALSA-2021:1809",
                    "type": "security",
                    "severity": "Important",
                    "title": "Important: httpd security update",
                    "pkglist": {
                        "packages": [
                            {
                                "name": "httpd-devel",
                                "epoch": "0",
                                "version": "2.4.37",
                                "release": "21.el8.alma.1",
                            },
                            {
                                "name": "httpd-tools",
                                "epoch": "0",
                                "version": "2.4.37",
                                "release": "21.el8.alma.1",
                            }
                        ]
                    },
                    "references": [{"type": "rhsa", "id": "RHSA-2021:1809"}],
                },
                {
                    "updateinfo_id": "ALSA-2025:9878",
                    "type": "security",
                    "severity": "Critical",
                    "title": "Critical: libblockdev security update",
                    "pkglist": {"packages": [{"name": "libblockdev", "epoch": "0", "version": "2.28", "release": "7.el8_10"}]},
                    "references": [{"type": "rhsa", "id": "RHSA-2025:9878"}],
                },
                {
                    "updateinfo_id": "ALSA-2022:7704",
                    "type": "security",
                    "severity": "Important",
                    "title": "Important: webkit2gtk3 security update",
                    "pkglist": {
                        "packages": [
                            {
                                "name": "webkit2gtk3",
                                "epoch": "0",
                                "version": "2.36.7",
                                "release": "1.el8",
                            },
                            {
                                "name": "webkit2gtk3-jsc",
                                "epoch": "0",
                                "version": "2.36.7",
                                "release": "1.el8",
                            },
                            {
                                "name": "webkit2gtk3-jsc-devel",
                                "epoch": "0",
                                "version": "2.36.7",
                                "release": "1.el8",
                            }
                        ]
                    },
                    "references": [{"type": "rhsa", "id": "RHSA-2022:7704"}],
                },
            ]

            errata_file = os.path.join(alma_dir, "errata-8.json")
            with open(errata_file, "wb") as f:
                f.write(orjson.dumps(mock_errata_8))

            class MockWorkspace:
                def __init__(self, root):
                    self._root = root

            yield MockWorkspace(tmpdir)

    def test_case_1_alma_specific_fix_for_rhel_no_fix(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Case 1: AlmaLinux has a fix for a vulnerability that RHEL marked as no fix.
        - RHEL record has VendorAdvisory.NoAdvisory = True or Version = "None"
        - AlmaLinux has an A-prefixed advisory with a fix
        - Should use AlmaLinux version and convert advisory ID
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record_no_fix = {
            "Vulnerability": {
                "Name": "CVE-2025-1234",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "vulnerable-pkg",
                        "Version": "None",
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {
                            "NoAdvisory": True
                        },
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record_no_fix, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "0:2.1.0-1.el8.alma"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

        advisory = fixed_in["VendorAdvisory"]["AdvisorySummary"][0]
        assert advisory["ID"] == "ALSA-2025:A004"
        assert advisory["Link"] == "https://errata.almalinux.org/8/ALSA-2025-A004.html"

    def test_case_3_alma_advisory_consensus_version(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Case 3: AlmaLinux has corresponding advisory but no entry for this specific package, with consensus version.
        - RHEL has RHSA-2021:1809 with httpd package
        - AlmaLinux has ALSA-2021:1809 with packages at consensus version 0:2.4.37-21.el8.alma.1
        - Should use consensus version from Alma advisory
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record = {
            "Vulnerability": {
                "Name": "CVE-2020-11984",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "httpd",
                        "Version": "0:2.4.37-21.module+el8.2.0+5059+3eb3af25",
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {
                            "NoAdvisory": False,
                            "AdvisorySummary": [{"ID": "RHSA-2021:1809", "Link": "https://access.redhat.com/errata/RHSA-2021:1809"}],
                        },
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "0:2.4.37-21.el8.alma.1"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

        advisory = fixed_in["VendorAdvisory"]["AdvisorySummary"][0]
        assert advisory["ID"] == "ALSA-2021:1809"
        assert advisory["Link"] == "https://errata.almalinux.org/8/ALSA-2021-1809.html"

    def test_case_2_alma_advisory_with_package_entry(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Case 2: AlmaLinux has corresponding advisory with package entry - use Alma version.
        - RHEL has RHSA-2022:6158 with php package
        - AlmaLinux has ALSA-2022:6158 with php package and specific version
        - Should use AlmaLinux version
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record = {
            "Vulnerability": {
                "Name": "CVE-2022-31625",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "php",
                        "Version": "0:7.4.19-4.module+el8.6.0+16316+906f6c6d",  # RHEL version
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {
                            "NoAdvisory": False,
                            "AdvisorySummary": [{"ID": "RHSA-2022:6158", "Link": "https://access.redhat.com/errata/RHSA-2022:6158"}],
                        },
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "0:7.4.19-4.module_el8.6.0+3238+624bf8b8"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

        advisory = fixed_in["VendorAdvisory"]["AdvisorySummary"][0]
        assert advisory["ID"] == "ALSA-2022:6158"
        assert advisory["Link"] == "https://errata.almalinux.org/8/ALSA-2022-6158.html"

    def test_case_4_alma_no_corresponding_advisory(self, rhel_config_with_alma):
        """
        Case 4: AlmaLinux has no corresponding advisory.
        - RHEL has RHSA-2023:9999 with some-package
        - AlmaLinux has no ALSA-2023:9999
        - Should inherit RHEL version constraint since AlmaLinux likely uses same fix
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Workspace(tmpdir, "test")
            provider = Provider(workspace._root, rhel_config_with_alma)

            rhel_record = {
                "Vulnerability": {
                    "Name": "CVE-2023-5678",
                    "NamespaceName": "rhel:8",
                    "FixedIn": [
                        {
                            "Name": "missing-package",
                            "Version": "0:1.0.0-1.el8",
                            "VersionFormat": "rpm",
                            "NamespaceName": "rhel:8",
                            "VendorAdvisory": {
                                "NoAdvisory": False,
                                "AdvisorySummary": [{"ID": "RHSA-2023:9999", "Link": "https://access.redhat.com/errata/RHSA-2023:9999"}],
                            },
                        }
                    ],
                }
            }

            with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
                provider.parser.alma_parser.errata_client._build_index()
                alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

            assert alma_record is not None
            fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

            assert fixed_in["Version"] == "0:1.0.0-1.el8"

            assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

            assert "AdvisorySummary" not in fixed_in["VendorAdvisory"] or len(fixed_in["VendorAdvisory"].get("AdvisorySummary", [])) == 0

    def test_alma_specific_advisory_lookup(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Test that AlmaLinux-specific advisories (with A prefix) can be found
        even when RHEL has no advisory for the vulnerability.
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()

            alma_version = provider.parser.alma_parser.get_alma_fix_version(
                "ALSA-2025:A004",  # Using Alma-specific advisory directly
                "8",
                "vulnerable-pkg",
            )

            assert alma_version == "0:2.1.0-1.el8.alma"

    def test_updated_logic_covers_all_cases(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Integration test to verify the updated logic handles all cases correctly.
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()

            test_cases = [
                # Case 1: RHEL no fix, Alma has A-prefixed fix
                {
                    "rhel": {"Vulnerability": {"FixedIn": [{"Name": "vulnerable-pkg", "Version": "None", "VendorAdvisory": {"NoAdvisory": True}}]}},
                    "expected_version": "0:2.1.0-1.el8.alma",
                    "expected_advisory": "ALSA-2025:A004",
                    "expected_no_advisory": False,
                },
                # Case 3: Alma advisory exists, no package entry, with consensus version
                {
                    "rhel": {
                        "Vulnerability": {
                            "FixedIn": [
                                {
                                    "Name": "httpd",
                                    "Version": "0:2.4.37-21.el8",
                                    "VendorAdvisory": {"NoAdvisory": False, "AdvisorySummary": [{"ID": "RHSA-2021:1809"}]},
                                }
                            ]
                        }
                    },
                    "expected_version": "0:2.4.37-21.el8.alma.1",
                    "expected_advisory": "ALSA-2021:1809",
                    "expected_no_advisory": False,
                },
                # Case 2: Alma advisory with package entry
                {
                    "rhel": {
                        "Vulnerability": {
                            "FixedIn": [
                                {
                                    "Name": "php",
                                    "Version": "0:7.4.19-4.rhel",
                                    "VendorAdvisory": {"NoAdvisory": False, "AdvisorySummary": [{"ID": "RHSA-2022:6158"}]},
                                }
                            ]
                        }
                    },
                    "expected_version": "0:7.4.19-4.module_el8.6.0+3238+624bf8b8",
                    "expected_advisory": "ALSA-2022:6158",
                    "expected_no_advisory": False,
                },
                # Case 4: No corresponding Alma advisory - fall back to RHEL
                {
                    "rhel": {
                        "Vulnerability": {
                            "FixedIn": [
                                {
                                    "Name": "missing-pkg",
                                    "Version": "0:1.2.3-4.el8",
                                    "VendorAdvisory": {"NoAdvisory": False, "AdvisorySummary": [{"ID": "RHSA-2023:9999"}]},
                                }
                            ]
                        }
                    },
                    "expected_version": "0:1.2.3-4.el8",
                    "expected_advisory": "ALSA-2023:9999",
                    "expected_no_advisory": False,
                },
            ]

            for i, case in enumerate(test_cases):
                case["rhel"]["Vulnerability"].update({"Name": f"CVE-2025-{i}", "NamespaceName": "rhel:8"})
                case["rhel"]["Vulnerability"]["FixedIn"][0].update({"VersionFormat": "rpm", "NamespaceName": "rhel:8"})

                alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", case["rhel"], rhel_config_with_alma.include_alma_fixes)

                assert alma_record is not None, f"Case {i + 1} failed: no alma record created"
                fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

                assert fixed_in["Version"] == case["expected_version"], (
                    f"Case {i + 1} failed: expected {case['expected_version']}, got {fixed_in['Version']}"
                )

                assert fixed_in["VendorAdvisory"]["NoAdvisory"] == case["expected_no_advisory"], (
                    f"Case {i + 1} failed: expected NoAdvisory={case['expected_no_advisory']}, got {fixed_in['VendorAdvisory']['NoAdvisory']}"
                )

                if not case["expected_no_advisory"] and "AdvisorySummary" in fixed_in.get("VendorAdvisory", {}):
                    advisory = fixed_in["VendorAdvisory"]["AdvisorySummary"][0]
                    assert advisory["ID"] == case["expected_advisory"], (
                        f"Case {i + 1} failed: expected {case['expected_advisory']}, got {advisory['ID']}"
                    )

    def test_alma_specific_fix_with_lower_version_than_rhel(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Test case for the issue where AlmaLinux has a specific advisory with a lower version number
        than the RHEL advisory, but the alma-specific fix should still be preferred.

        This addresses the scenario where:
        - CVE-2025-6019 has RHSA-2025:9878 with libblockdev-2.28-7.el8_10
        - CVE-2025-6019 has ALSA-2025:A004 with libblockdev-2.28-6.el8.alma.1
        - The alma-specific fix should be used even though it has a "lower" version number
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record = {
            "Vulnerability": {
                "Name": "CVE-2025-6019",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "libblockdev",
                        "Version": "0:2.28-7.el8_10",
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {
                            "NoAdvisory": False,
                            "AdvisorySummary": [{"ID": "RHSA-2025:9878", "Link": "https://access.redhat.com/errata/RHSA-2025:9878"}],
                        },
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "0:2.28-6.el8.alma.1"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

        advisory = fixed_in["VendorAdvisory"]["AdvisorySummary"][0]
        assert advisory["ID"] == "ALSA-2025:A005"
        assert advisory["Link"] == "https://errata.almalinux.org/8/ALSA-2025-A005.html"

    def test_inherit_rhel_version_when_no_alma_advisory(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Test case for CVE-2019-18276 bash scenario where:
        - RHEL has RHSA-2021:1679 with bash fix version 0:4.4.19-14.el8
        - AlmaLinux has no corresponding ALSA-2021:1679 advisory
        - AlmaLinux should inherit the RHEL version constraint
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record = {
            "Vulnerability": {
                "Name": "CVE-2019-18276",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "bash",
                        "Version": "0:4.4.19-14.el8",
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {
                            "NoAdvisory": False,
                            "AdvisorySummary": [{"ID": "RHSA-2021:1679", "Link": "https://access.redhat.com/errata/RHSA-2021:1679"}],
                        },
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "0:4.4.19-14.el8"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

        assert "AdvisorySummary" not in fixed_in["VendorAdvisory"]

    def test_inherit_rhel_no_fix_status(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Test case where RHEL has no fix (Version="None", NoAdvisory=True) and no AlmaLinux advisory exists.
        Should inherit RHEL's "no fix" status completely.
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record = {
            "Vulnerability": {
                "Name": "CVE-2025-NOFIXTEST",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "vulnerable-package",
                        "Version": "None",
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {"NoAdvisory": True, "AdvisorySummary": []},
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "None"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is True

        assert fixed_in["VendorAdvisory"]["AdvisorySummary"] == []

    def test_case_3_consensus_version_no_substring_commonality(self, mock_alma_workspace_with_scenarios, rhel_config_with_alma):
        """
        Test case for CVE-2022-32891 scenario where consensus version exists but should not be used
        due to lack of package substring commonality.

        - RHEL has RHSA-2022:7704 fixing both glib2 and webkit2gtk3
        - AlmaLinux has ALSA-2022:7704 with only webkit2gtk3 variants (consensus version 0:2.36.7-1.el8)
        - glib2 should NOT get the consensus version because there's no substring commonality
          between "glib2" and packages like "webkit2gtk3-jsc-devel"
        - Should fall back to Case 4: inherit RHEL version
        """
        provider = Provider(mock_alma_workspace_with_scenarios._root, rhel_config_with_alma)

        rhel_record = {
            "Vulnerability": {
                "Name": "CVE-2022-32891",
                "NamespaceName": "rhel:8",
                "FixedIn": [
                    {
                        "Name": "glib2",
                        "Version": "0:2.56.4-159.el8",
                        "VersionFormat": "rpm",
                        "NamespaceName": "rhel:8",
                        "VendorAdvisory": {
                            "NoAdvisory": False,
                            "AdvisorySummary": [{"ID": "RHSA-2022:7704", "Link": "https://access.redhat.com/errata/RHSA-2022:7704"}],
                        },
                    }
                ],
            }
        }

        with patch("vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file"):
            provider.parser.alma_parser.errata_client._build_index()
            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy("rhel:8", rhel_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record["Vulnerability"]["FixedIn"][0]

        assert fixed_in["Version"] == "0:2.56.4-159.el8"
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False

        assert "AdvisorySummary" not in fixed_in["VendorAdvisory"]
