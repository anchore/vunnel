import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from vunnel.providers.rhel.alma_parser import AlmaParser
from vunnel.workspace import Workspace


class TestAlmaParser:
    @pytest.fixture
    def mock_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rhel_input_dir = os.path.join(tmpdir, "rhel", "input")
            alma_dir = os.path.join(rhel_input_dir, "alma-errata-data")
            os.makedirs(alma_dir, exist_ok=True)

            class MockWorkspace:
                def __init__(self, root):
                    self._root = root
                    self.input_path = os.path.join(root, "rhel", "input")

            yield MockWorkspace(tmpdir)

    @pytest.fixture
    def alma_parser(self, mock_workspace):
        workspace = Workspace(mock_workspace._root, "rhel")
        return AlmaParser(workspace=workspace, alma_linux_versions=["8", "9"])

    def test_rhsa_to_alsa_conversion(self, alma_parser):
        assert alma_parser._rhsa_to_alsa("RHSA-2022:6158") == "ALSA-2022:6158"
        assert alma_parser._rhsa_to_alsa("RHBA-2022:1234") == "ALBA-2022:1234"
        assert alma_parser._rhsa_to_alsa("RHEA-2022:5678") == "ALEA-2022:5678"
        assert alma_parser._rhsa_to_alsa("RHXX-2022:9999") == "ALXX-2022:9999"

    def test_normalize_rpm_version(self, alma_parser):
        # Test adding epoch prefix
        assert alma_parser._normalize_rpm_version("1.2.3-4.el8") == "0:1.2.3-4.el8"
        assert alma_parser._normalize_rpm_version("7.4.19-4.module_el8.6.0+3238+624bf8b8") == "0:7.4.19-4.module_el8.6.0+3238+624bf8b8"

        # Test preserving existing epoch
        assert alma_parser._normalize_rpm_version("1:1.2.3-4.el8") == "1:1.2.3-4.el8"
        assert alma_parser._normalize_rpm_version("0:7.4.19-4.module_el8.6.0+3238+624bf8b8") == "0:7.4.19-4.module_el8.6.0+3238+624bf8b8"

        # Test edge cases
        assert alma_parser._normalize_rpm_version("") == ""
        assert alma_parser._normalize_rpm_version(None) == None

    def test_get_alma_fix_version_found(self, alma_parser):
        # Mock the errata client
        alma_parser.errata_client.get_package_version = Mock(return_value="7.4.19-4.module_el8.6.0+3238+624bf8b8")

        result = alma_parser.get_alma_fix_version("RHSA-2022:6158", "8", "php")

        assert result == "0:7.4.19-4.module_el8.6.0+3238+624bf8b8"
        alma_parser.errata_client.get_package_version.assert_called_once_with(
            alsa_id="ALSA-2022:6158", version="8", package_name="php"
        )

    def test_get_alma_fix_version_not_found(self, alma_parser):
        alma_parser.errata_client.get_package_version = Mock(return_value=None)

        result = alma_parser.get_alma_fix_version("RHSA-2022:9999", "8", "nonexistent")

        assert result is None

    def test_consensus_version_same_versions(self, alma_parser):
        # Mock advisory data with all packages having the same version
        alma_parser.errata_client.get_advisory_data = Mock(return_value={
            "package1": "1.0.0-1.el8",
            "package2": "1.0.0-1.el8",
            "package3": "1.0.0-1.el8"
        })

        result = alma_parser.consensus_version("ALSA-2022:1234")

        assert result == "0:1.0.0-1.el8"

    def test_consensus_version_different_versions(self, alma_parser):
        # Mock advisory data with packages having different versions
        alma_parser.errata_client.get_advisory_data = Mock(return_value={
            "package1": "1.0.0-1.el8",
            "package2": "1.1.0-1.el8",
            "package3": "1.0.0-1.el8"
        })

        result = alma_parser.consensus_version("ALSA-2022:5678")

        assert result is None

    def test_consensus_version_advisory_not_found(self, alma_parser):
        # Mock no advisory found
        alma_parser.errata_client.get_advisory_data = Mock(return_value=None)

        result = alma_parser.consensus_version("ALSA-2022:9999")

        assert result is None

    def test_consensus_version_empty_advisory(self, alma_parser):
        # Mock empty advisory data
        alma_parser.errata_client.get_advisory_data = Mock(return_value={})

        result = alma_parser.consensus_version("ALSA-2022:0000")

        assert result is None

    def test_consensus_version_rhsa_conversion(self, alma_parser):
        # Test that RHSA gets converted to ALSA
        alma_parser.errata_client.get_advisory_data = Mock(return_value={
            "package1": "2.0.0-1.el8",
            "package2": "2.0.0-1.el8"
        })

        result = alma_parser.consensus_version("RHSA-2022:1111")

        assert result == "0:2.0.0-1.el8"
        # Verify it called with converted ALSA ID
        alma_parser.errata_client.get_advisory_data.assert_called_with("ALSA-2022:1111", "8")

    def test_consensus_version_checks_multiple_versions(self, alma_parser):
        # Test that it checks multiple AlmaLinux versions
        def mock_get_advisory_data(alsa_id, version):
            if version == "8":
                return None  # Not found in version 8
            elif version == "9":
                return {"package1": "3.0.0-1.el9", "package2": "3.0.0-1.el9"}
            return None

        alma_parser.errata_client.get_advisory_data = Mock(side_effect=mock_get_advisory_data)

        result = alma_parser.consensus_version("ALSA-2023:1234")

        assert result == "0:3.0.0-1.el9"
        # Verify it was called for both versions
        assert alma_parser.errata_client.get_advisory_data.call_count == 2

    def test_consensus_version_with_epochs(self, alma_parser):
        # Test with versions that already have epochs
        alma_parser.errata_client.get_advisory_data = Mock(return_value={
            "package1": "1:5.0.0-1.el8",
            "package2": "1:5.0.0-1.el8",
            "package3": "1:5.0.0-1.el8"
        })

        result = alma_parser.consensus_version("ALSA-2022:7890")

        assert result == "1:5.0.0-1.el8"

    def test_consensus_version_mixed_epochs(self, alma_parser):
        # Test with mixed versions (some with epochs, some without) that normalize to same
        alma_parser.errata_client.get_advisory_data = Mock(return_value={
            "package1": "0:2.0.0-1.el8",  # Already has epoch
            "package2": "2.0.0-1.el8",    # Will get 0: added
            "package3": "0:2.0.0-1.el8"   # Already has epoch
        })

        result = alma_parser.consensus_version("ALSA-2022:4567")

        assert result == "0:2.0.0-1.el8"

    def test_consensus_version_mixed_epochs_different(self, alma_parser):
        # Test with mixed epochs that result in different versions
        alma_parser.errata_client.get_advisory_data = Mock(return_value={
            "package1": "1:2.0.0-1.el8",  # Different epoch
            "package2": "2.0.0-1.el8",    # Will get 0: added
            "package3": "0:2.0.0-1.el8"   # Same as normalized package2 but different from package1
        })

        result = alma_parser.consensus_version("ALSA-2022:3456")

        assert result is None  # Different after normalization


class TestAlmaParserIntegration:
    def test_consensus_version_with_real_fixtures(self, helpers, disable_get_requests):
        """Test consensus_version with actual test fixture data"""
        workspace = helpers.provider_workspace_helper(
            name="rhel",
            input_fixture="test-fixtures/oval/input",
        )

        alma_parser = AlmaParser(workspace=workspace, alma_linux_versions=["8", "9"])

        with patch('vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file'):
            # Build index from test fixture data
            alma_parser.errata_client._build_index()

            # Test with advisory that has only one package (should return consensus)
            result = alma_parser.consensus_version("ALSA-2022:6158")
            assert result == "0:7.4.19-4.module_el8.6.0+3238+624bf8b8"

            # Test with advisory that has multiple packages with same version (should return consensus)
            result = alma_parser.consensus_version("ALSA-2023:1111")
            assert result == "1:2.0.0-1.el8"

            # Test with advisory that has multiple packages with different versions (should return None)
            result = alma_parser.consensus_version("ALSA-2023:2222")
            assert result is None

            # Test with RHSA conversion
            result = alma_parser.consensus_version("RHSA-2023:1111")
            assert result == "1:2.0.0-1.el8"

            # Test with non-existent advisory
            result = alma_parser.consensus_version("ALSA-2023:9999")
            assert result is None

    def test_get_alma_fix_version_with_real_fixtures(self, helpers, disable_get_requests):
        """Test get_alma_fix_version with actual test fixture data"""
        workspace = helpers.provider_workspace_helper(
            name="rhel",
            input_fixture="test-fixtures/oval/input",
        )

        alma_parser = AlmaParser(workspace=workspace, alma_linux_versions=["8", "9"])

        with patch('vunnel.providers.rhel.alma_errata_client.AlmaErrataClient._download_errata_file'):
            # Build index from test fixture data
            alma_parser.errata_client._build_index()

            # Test with known advisory and package from fixtures
            result = alma_parser.get_alma_fix_version("RHSA-2022:6158", "8", "php")

            assert result == "0:7.4.19-4.module_el8.6.0+3238+624bf8b8"

            # Test with non-existent package
            result = alma_parser.get_alma_fix_version("RHSA-2022:6158", "8", "nonexistent")

            assert result is None
