from __future__ import annotations

import os
import json
from unittest.mock import MagicMock, patch, mock_open

import pytest
from vunnel import result, workspace
from vunnel.providers.rootio import Config, Provider, parser


class TestRootIoProvider:
    @pytest.fixture()
    def mock_vulnerability_data(self):
        """Returns sample vulnerability data that would be fetched from Root.io API"""
        return {
            "CVE-2023-1234": {
                "cve_id": "CVE-2023-1234",
                "packages": [
                    {
                        "package": "curl",
                        "distro": "alpine",
                        "distro_version": "3.17",
                        "fixed_version": "7.88.1-r1",
                        "has_rootio_fix": True
                    },
                    {
                        "package": "openssl",
                        "distro": "debian",
                        "distro_version": "11",
                        "fixed_version": None,
                        "has_rootio_fix": True
                    }
                ],
                "severity": "HIGH",
                "description": "Test vulnerability description",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"]
            },
            "CVE-2023-5678": {
                "cve_id": "CVE-2023-5678",
                "packages": [
                    {
                        "package": "requests",
                        "language": "python",
                        "fixed_version": "2.31.0",
                        "has_rootio_fix": True
                    }
                ],
                "severity": "MEDIUM",
                "description": "Another test vulnerability",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-5678"]
            }
        }

    @pytest.fixture()
    def workspace_dir(self, tmp_path):
        ws = workspace.Workspace(root=str(tmp_path / "rootio"), name="rootio")
        ws.create()
        return ws

    def test_parser_emit_unaffected_for_os_packages(self, workspace_dir, mock_vulnerability_data):
        """Test that parser emits ROOTIO_UNAFFECTED markers for OS packages"""
        p = parser.Parser(workspace=workspace_dir)
        
        # Mock the API response
        with patch.object(parser.Parser, "_fetch_vulnerabilities", return_value=mock_vulnerability_data):
            p._process_vulnerabilities(mock_vulnerability_data)
            
            # Check that results were written
            results_path = workspace_dir.results_path
            assert os.path.exists(results_path)
            
            # Verify the output contains ROOTIO_UNAFFECTED markers
            vuln_files = list(results_path.glob("*.json"))
            assert len(vuln_files) > 0
            
            # Check for CVE-2023-1234 (OS package vulnerability)
            found_unaffected = False
            for vuln_file in vuln_files:
                with open(vuln_file) as f:
                    data = json.load(f)
                    if data.get("Vulnerability", {}).get("Name") == "CVE-2023-1234":
                        for fixed_in in data["Vulnerability"].get("FixedIn", []):
                            if fixed_in.get("Version") == "ROOTIO_UNAFFECTED":
                                found_unaffected = True
                                assert fixed_in.get("VulnerableRange") == "NOT version_contains .root.io"
            
            assert found_unaffected, "Should have ROOTIO_UNAFFECTED marker for OS packages"

    def test_parser_emit_unaffected_for_language_packages(self, workspace_dir, mock_vulnerability_data):
        """Test that parser emits ROOTIO_UNAFFECTED markers for language packages"""
        p = parser.Parser(workspace=workspace_dir)
        
        # Mock the API response
        with patch.object(parser.Parser, "_fetch_vulnerabilities", return_value=mock_vulnerability_data):
            p._process_vulnerabilities(mock_vulnerability_data)
            
            # Check for CVE-2023-5678 (Python package vulnerability)
            results_path = workspace_dir.results_path
            vuln_files = list(results_path.glob("*.json"))
            
            found_python_unaffected = False
            for vuln_file in vuln_files:
                with open(vuln_file) as f:
                    data = json.load(f)
                    if data.get("Vulnerability", {}).get("Name") == "CVE-2023-5678":
                        namespace = data["Vulnerability"].get("NamespaceName", "")
                        if namespace == "rootio:language:python":
                            for fixed_in in data["Vulnerability"].get("FixedIn", []):
                                if fixed_in.get("Version") == "ROOTIO_UNAFFECTED":
                                    found_python_unaffected = True
            
            assert found_python_unaffected, "Should have ROOTIO_UNAFFECTED marker for language packages"

    def test_parser_namespace_format(self, workspace_dir):
        """Test that parser generates correct namespace formats"""
        p = parser.Parser(workspace=workspace_dir)
        
        # Test OS namespace
        os_namespace = p._get_namespace("alpine", "3.17", None)
        assert os_namespace == "rootio:distro:alpine:3.17"
        
        # Test language namespace
        lang_namespace = p._get_namespace(None, None, "python")
        assert lang_namespace == "rootio:language:python"

    def test_parser_version_format_mapping(self, workspace_dir):
        """Test that parser maps to correct version formats"""
        p = parser.Parser(workspace=workspace_dir)
        
        # Test OS mappings
        assert p._get_version_format("alpine") == "apk"
        assert p._get_version_format("debian") == "dpkg"
        assert p._get_version_format("ubuntu") == "dpkg"
        assert p._get_version_format("centos") == "rpm"
        
        # Test language mappings
        assert p._get_version_format(None, "python") == "python"
        assert p._get_version_format(None, "javascript") == "semver"
        assert p._get_version_format(None, "java") == "maven"

    def test_provider_name(self):
        """Test that provider returns correct name"""
        p = Provider(root="/tmp", config=Config())
        assert p.name == "rootio"

    def test_provider_update(self, workspace_dir, mock_vulnerability_data):
        """Test the provider update process"""
        config = Config(runtime=Config.RuntimeConfig(existing_results="keep"))
        p = Provider(root=str(workspace_dir.path), config=config)
        
        # Mock the API fetch
        with patch.object(parser.Parser, "_fetch_vulnerabilities", return_value=mock_vulnerability_data):
            # Run update
            update_count, urls = p.update()
            
            # Verify results
            assert isinstance(update_count, int)
            assert update_count > 0
            
            # Check that metadata was written
            metadata_path = workspace_dir.metadata_path
            assert metadata_path.exists()
            
            with open(metadata_path) as f:
                metadata = json.load(f)
                assert metadata["provider"] == "rootio"
                assert metadata["listing"]["digest"]
                assert metadata["listing"]["algorithm"]

    def test_parser_handles_empty_response(self, workspace_dir):
        """Test that parser handles empty API responses gracefully"""
        p = parser.Parser(workspace=workspace_dir)
        
        # Mock empty API response
        with patch.object(parser.Parser, "_fetch_vulnerabilities", return_value={}):
            p._process_vulnerabilities({})
            
            # Should complete without errors
            results_path = workspace_dir.results_path
            assert results_path.exists()

    def test_parser_vulnerable_range_constraint(self, workspace_dir, mock_vulnerability_data):
        """Test that vulnerable range constraints are properly set"""
        p = parser.Parser(workspace=workspace_dir)
        
        with patch.object(parser.Parser, "_fetch_vulnerabilities", return_value=mock_vulnerability_data):
            p._process_vulnerabilities(mock_vulnerability_data)
            
            # Read results and check constraints
            results_path = workspace_dir.results_path
            vuln_files = list(results_path.glob("*.json"))
            
            for vuln_file in vuln_files:
                with open(vuln_file) as f:
                    data = json.load(f)
                    for fixed_in in data.get("Vulnerability", {}).get("FixedIn", []):
                        if fixed_in.get("Version") == "ROOTIO_UNAFFECTED":
                            # Should have the Root.io constraint
                            assert fixed_in.get("VulnerableRange") == "NOT version_contains .root.io"

    def test_config_defaults(self):
        """Test that Config has proper defaults"""
        config = Config()
        assert config.api_url == "https://api.root.io/v1/vulnerabilities"
        assert config.runtime.existing_results == "delete"


class TestRootIoParser:
    """Additional parser-specific tests"""
    
    def test_normalize_severity(self):
        """Test severity normalization"""
        p = parser.Parser(workspace=MagicMock())
        
        assert p._normalize_severity("CRITICAL") == "Critical"
        assert p._normalize_severity("HIGH") == "High"
        assert p._normalize_severity("MEDIUM") == "Medium"
        assert p._normalize_severity("LOW") == "Low"
        assert p._normalize_severity("unknown") == "Unknown"
        assert p._normalize_severity(None) == "Unknown"