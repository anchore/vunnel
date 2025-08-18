import os
import tempfile
from unittest.mock import patch

import pytest

from vunnel.providers.rhel import Config, Provider
from vunnel.workspace import Workspace


class TestRHELWithAlmaIntegration:
    @pytest.fixture
    def rhel_config_with_alma(self):
        return Config(include_alma_fixes=True)

    @pytest.fixture
    def rhel_config_without_alma(self):
        return Config(include_alma_fixes=False)

    @pytest.fixture
    def mock_alma_advisory_data(self):
        return {
            "id": "ALSA-2022:6158",
            "summary": "Moderate: php:7.4 security update",
            "affected": [
                {
                    "package": {"ecosystem": "AlmaLinux:8", "name": "php"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "7.4.19-4.module_el8.6.0+3238+624bf8b8"}
                            ]
                        }
                    ]
                }
            ],
            "related": ["CVE-2022-31625"],
            "published": "2022-08-24T00:00:00Z",
            "modified": "2022-11-23T22:19:30Z"
        }

    @pytest.fixture
    def rhel_vulnerability_record(self):
        return {
            'Vulnerability': {
                'Severity': 'Medium',
                'NamespaceName': 'rhel:8',
                'FixedIn': [{
                    'Name': 'php',
                    'Version': '0:7.4.19-4.module+el8.6.0+16316+906f6c6d',
                    'Module': 'php:7.4',
                    'VersionFormat': 'rpm',
                    'NamespaceName': 'rhel:8',
                    'VendorAdvisory': {
                        'NoAdvisory': False,
                        'AdvisorySummary': [{'ID': 'RHSA-2022:6158', 'Link': 'https://access.redhat.com/errata/RHSA-2022:6158'}]
                    }
                }],
                'Link': 'https://access.redhat.com/security/cve/CVE-2022-31625',
                'Description': 'A vulnerability was found in PHP due to an uninitialized array in pg_query_params() function.',
                'Metadata': {},
                'Name': 'CVE-2022-31625',
                'CVSS': []
            }
        }

    @pytest.fixture
    def mock_alma_workspace(self, mock_alma_advisory_data):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create the directory structure for HTTP-based errata files
            rhel_input_dir = os.path.join(tmpdir, "rhel", "input")
            alma_dir = os.path.join(rhel_input_dir, "alma-errata-data")
            os.makedirs(alma_dir, exist_ok=True)

            import orjson

            # Create mock errata-8.json file with AlmaLinux advisory format
            mock_errata_8 = [
                {
                    "updateinfo_id": "ALSA-2022:6158",
                    "type": "security",
                    "severity": "Moderate",
                    "title": "Moderate: php:7.4 security update",
                    "pkglist": {
                        "packages": [
                            {
                                "name": "php",
                                "epoch": "0",
                                "version": "7.4.19",
                                "release": "4.module_el8.6.0+3238+624bf8b8"
                            }
                        ]
                    },
                    "references": [
                        {
                            "type": "rhsa",
                            "id": "RHSA-2022:6158"
                        }
                    ]
                },
                {
                    "updateinfo_id": "ALSA-2024:10953",
                    "type": "security",
                    "severity": "Important",
                    "title": "Test advisory",
                    "pkglist": {
                        "packages": [
                            {
                                "name": "php",
                                "epoch": "0",
                                "version": "8.0.0",
                                "release": "1.el8"
                            }
                        ]
                    },
                    "references": [
                        {
                            "type": "rhsa",
                            "id": "RHSA-2024:10953"
                        }
                    ]
                }
            ]

            errata_file = os.path.join(alma_dir, "errata-8.json")
            with open(errata_file, "wb") as f:
                f.write(orjson.dumps(mock_errata_8))

            # Return a mock workspace that just has the _root attribute
            class MockWorkspace:
                def __init__(self, root):
                    self._root = root

            yield MockWorkspace(tmpdir)

    def test_config_includes_alma_fixes_flag(self, rhel_config_with_alma, rhel_config_without_alma):
        assert rhel_config_with_alma.include_alma_fixes is True
        assert rhel_config_without_alma.include_alma_fixes is False

    def test_provider_initializes_alma_parser_when_enabled(self, mock_alma_workspace, rhel_config_with_alma):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)

        assert provider.config.include_alma_fixes is True
        assert provider.parser.include_alma_fixes is True
        assert provider.parser.alma_parser is not None

    def test_provider_does_not_initialize_alma_parser_when_disabled(self, mock_alma_workspace, rhel_config_without_alma):
        provider = Provider(mock_alma_workspace._root, rhel_config_without_alma)

        assert provider.config.include_alma_fixes is False
        assert provider.parser.include_alma_fixes is False
        assert provider.parser.alma_parser is None

    def test_alma_copy_creation_disabled_when_config_false(self, mock_alma_workspace, rhel_config_without_alma, rhel_vulnerability_record):
        provider = Provider(mock_alma_workspace._root, rhel_config_without_alma)

        alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy(
            'rhel:8', rhel_vulnerability_record, rhel_config_without_alma.include_alma_fixes
        )
        assert alma_record is None

    def test_alma_copy_creation_skips_non_target_versions(self, mock_alma_workspace, rhel_config_with_alma, rhel_vulnerability_record):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)

        assert provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:7', rhel_vulnerability_record, rhel_config_with_alma.include_alma_fixes) is None
        assert provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:5', rhel_vulnerability_record, rhel_config_with_alma.include_alma_fixes) is None
        assert provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:8', rhel_vulnerability_record, rhel_config_with_alma.include_alma_fixes) is not None

    def test_alma_copy_transforms_namespace_and_identifier(self, mock_alma_workspace, rhel_config_with_alma, rhel_vulnerability_record):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)

        alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:8', rhel_vulnerability_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        assert alma_record['Vulnerability']['NamespaceName'] == 'almalinux:8'
        assert alma_record['Vulnerability']['FixedIn'][0]['NamespaceName'] == 'almalinux:8'


    def test_alma_copy_preserves_vulnerability_metadata(self, mock_alma_workspace, rhel_config_with_alma, rhel_vulnerability_record):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)

        alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:8', rhel_vulnerability_record, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        alma_vuln = alma_record['Vulnerability']
        rhel_vuln = rhel_vulnerability_record['Vulnerability']

        assert alma_vuln['Name'] == rhel_vuln['Name']
        assert alma_vuln['Severity'] == rhel_vuln['Severity']
        assert alma_vuln['Link'] == rhel_vuln['Link']
        assert alma_vuln['Description'] == rhel_vuln['Description']
        assert alma_vuln['CVSS'] == rhel_vuln['CVSS']
        assert alma_vuln['Metadata'] == rhel_vuln['Metadata']

    def test_alma_copy_handles_no_advisory_case(self, mock_alma_workspace, rhel_config_with_alma):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)

        rhel_record_no_advisory = {
            'Vulnerability': {
                'Name': 'CVE-2005-2541',
                'NamespaceName': 'rhel:8',
                'FixedIn': [{
                    'Name': 'tar',
                    'Version': 'None',
                    'NamespaceName': 'rhel:8',
                    'VendorAdvisory': {'NoAdvisory': True}
                }]
            }
        }

        alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:8', rhel_record_no_advisory, rhel_config_with_alma.include_alma_fixes)

        assert alma_record is not None
        fixed_in = alma_record['Vulnerability']['FixedIn'][0]

        assert fixed_in['NamespaceName'] == 'almalinux:8'
        assert fixed_in['Version'] == 'None'
        assert fixed_in['VendorAdvisory']['NoAdvisory'] is True

    def test_rhsa_to_alsa_conversion(self, mock_alma_workspace, rhel_config_with_alma):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)
        alma_parser = provider.parser.alma_parser

        assert alma_parser._rhsa_to_alsa('RHSA-2022:6158') == 'ALSA-2022:6158'
        assert alma_parser._rhsa_to_alsa('RHBA-2022:1234') == 'ALBA-2022:1234'
        assert alma_parser._rhsa_to_alsa('RHEA-2022:5678') == 'ALEA-2022:5678'
        assert alma_parser._rhsa_to_alsa('RHXX-2022:9999') == 'ALXX-2022:9999'

    def test_rpm_version_normalization(self, mock_alma_workspace, rhel_config_with_alma):
        provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)
        alma_parser = provider.parser.alma_parser

        # Test that versions without epoch get '0:' prepended
        assert alma_parser._normalize_rpm_version('1.2.3-4.el8') == '0:1.2.3-4.el8'
        assert alma_parser._normalize_rpm_version('7.4.19-4.module_el8.6.0+3238+624bf8b8') == '0:7.4.19-4.module_el8.6.0+3238+624bf8b8'

        # Test that versions with epoch are left unchanged
        assert alma_parser._normalize_rpm_version('1:1.2.3-4.el8') == '1:1.2.3-4.el8'
        assert alma_parser._normalize_rpm_version('0:7.4.19-4.module_el8.6.0+3238+624bf8b8') == '0:7.4.19-4.module_el8.6.0+3238+624bf8b8'

        # Test edge cases
        assert alma_parser._normalize_rpm_version('') == ''
        assert alma_parser._normalize_rpm_version(None) == None

    def test_alma_advisory_url_format(self, mock_alma_workspace, rhel_config_with_alma):
        with patch('vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file'):
            provider = Provider(mock_alma_workspace._root, rhel_config_with_alma)
            # Manually trigger the index building since we skipped download
            provider.parser.alma_parser.errata_client._build_index()

            rhel_record_with_different_id = {
                'Vulnerability': {
                    'NamespaceName': 'rhel:8',
                    'FixedIn': [{
                        'Name': 'php',
                        'Version': '1.0.0-1.el8',
                        'NamespaceName': 'rhel:8',
                        'VendorAdvisory': {
                            'NoAdvisory': False,
                            'AdvisorySummary': [{'ID': 'RHSA-2024:10953', 'Link': 'https://access.redhat.com/errata/RHSA-2024:10953'}]
                        }
                    }]
                }
            }

            alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:8', rhel_record_with_different_id, rhel_config_with_alma.include_alma_fixes)

            assert alma_record is not None
            fixed_in = alma_record['Vulnerability']['FixedIn'][0]

            assert fixed_in['Version'] == '0:8.0.0-1.el8'
            assert fixed_in['VendorAdvisory']['AdvisorySummary'][0]['ID'] == 'ALSA-2024:10953'
            assert fixed_in['VendorAdvisory']['AdvisorySummary'][0]['Link'] == 'https://errata.almalinux.org/8/ALSA-2024-10953.html'


def test_rhel_to_alma_conversion(helpers, disable_get_requests):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/oval/input",
    )

    config = Config(include_alma_fixes=True)
    provider = Provider(root=workspace.root, config=config)

    # Mock the HTTP download since we're using test fixtures
    with patch('vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file'):
        # Manually trigger the index building since we skipped download
        provider.parser.alma_parser.errata_client._build_index()

        rhel_record = {
            'Vulnerability': {
                'Severity': 'Medium',
                'NamespaceName': 'rhel:8',
                'FixedIn': [{
                    'Name': 'php',
                    'Version': '0:7.4.19-4.module+el8.6.0+16316+906f6c6d',
                    'Module': 'php:7.4',
                    'VersionFormat': 'rpm',
                    'NamespaceName': 'rhel:8',
                    'VendorAdvisory': {
                        'NoAdvisory': False,
                        'AdvisorySummary': [{'ID': 'RHSA-2022:6158', 'Link': 'https://access.redhat.com/errata/RHSA-2022:6158'}]
                    }
                }],
                'Link': 'https://access.redhat.com/security/cve/CVE-2022-31625',
                'Description': 'A vulnerability was found in PHP...',
                'Metadata': {},
                'Name': 'CVE-2022-31625',
                'CVSS': []
            }
        }

        alma_record = provider.alma_vulnerability_creator.create_alma_vulnerability_copy('rhel:8', rhel_record, config.include_alma_fixes)

        assert alma_record is not None
        assert alma_record['Vulnerability']['NamespaceName'] == 'almalinux:8'

        fixed_in = alma_record['Vulnerability']['FixedIn'][0]

        # Should find the actual alma fix from test fixtures
        assert fixed_in['Version'] == '0:7.4.19-4.module_el8.6.0+3238+624bf8b8'
        assert fixed_in['VendorAdvisory']['NoAdvisory'] is False
        assert fixed_in['VendorAdvisory']['AdvisorySummary'][0]['ID'] == 'ALSA-2022:6158'
        assert fixed_in['VendorAdvisory']['AdvisorySummary'][0]['Link'] == 'https://errata.almalinux.org/8/ALSA-2022-6158.html'
