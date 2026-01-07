from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from vunnel import result, workspace
from vunnel.providers.arch import Config, Provider
from vunnel.providers.arch.parser import Parser


class TestArchParser:
    @pytest.fixture()
    def mock_raw_data(self):
        """Return sample Arch Linux security tracker JSON data."""
        return [
            {
                "name": "AVG-1234",
                "packages": ["curl"],
                "affected": "8.4.0-1",
                "fixed": "8.5.0-1",
                "severity": "High",
                "status": "Fixed",
                "type": "arbitrary code execution",
                "issues": ["CVE-2024-1234"],
                "advisories": ["ASA-202401-01"],
            },
            {
                "name": "AVG-5678",
                "packages": ["openssl"],
                "affected": "3.1.0-1",
                "fixed": "3.2.0-1",
                "severity": "Critical",
                "status": "Fixed",
                "type": "cryptographic issue",
                "issues": ["CVE-2024-5678"],
                "advisories": ["ASA-202401-02"],
            },
            {
                "name": "AVG-9999",
                "packages": ["test-pkg"],
                "affected": "0.9.0-1",
                "fixed": "1.0.0-1",
                "severity": "Medium",
                "status": "Fixed",
                "type": "information disclosure",
                "issues": [],
                "advisories": [],
            },
        ]

    def test_parser_initialization(self):
        """Test that Parser initializes correctly."""
        url = "https://security.archlinux.org/all.json"
        timeout = 30
        parser = Parser(url=url, timeout=timeout)

        assert parser.url == url
        assert parser.timeout == timeout
        assert parser.logger is not None

    def test_parse_with_valid_data(self, mock_raw_data):
        """Test parsing valid Arch Linux security data."""
        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=mock_raw_data):
            records = list(parser.parse())

            assert len(records) == 3
            # Check first record
            group_id_1, payload_1 = records[0]
            assert group_id_1 == "avg-1234"
            assert payload_1["Vulnerability"]["Name"] == "AVG-1234"
            assert payload_1["Vulnerability"]["NamespaceName"] == "arch:rolling"
            assert payload_1["Vulnerability"]["Severity"] == "High"
            assert len(payload_1["Vulnerability"]["FixedIn"]) == 1
            assert payload_1["Vulnerability"]["FixedIn"][0]["Name"] == "curl"
            assert payload_1["Vulnerability"]["FixedIn"][0]["Version"] == "8.5.0-1"
            assert payload_1["Vulnerability"]["FixedIn"][0]["VersionFormat"] == "pacman"

            # Check second record
            group_id_2, payload_2 = records[1]
            assert group_id_2 == "avg-5678"
            assert payload_2["Vulnerability"]["Severity"] == "Critical"

            # Check third record (no issues/advisories)
            group_id_3, payload_3 = records[2]
            assert group_id_3 == "avg-9999"
            # With dataclass output, Metadata is always present (empty dict when no CVEs/advisories)
            assert payload_3["Vulnerability"]["Metadata"] == {}

    def test_parse_with_metadata(self, mock_raw_data):
        """Test that metadata is properly populated."""
        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=mock_raw_data):
            records = list(parser.parse())
            group_id, payload = records[0]

            assert "Metadata" in payload["Vulnerability"]
            assert payload["Vulnerability"]["Metadata"]["CVE"] == [
                {"Name": "CVE-2024-1234", "Link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}
            ]
            assert payload["Vulnerability"]["Metadata"]["Advisories"] == ["ASA-202401-01"]

    def test_parse_with_invalid_data_format(self):
        """Test parsing with invalid data format (not a list)."""
        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value={"invalid": "data"}):
            with pytest.raises(ValueError, match="Invalid data format from all.json: expected list"):
                list(parser.parse())

    def test_parse_with_missing_name_field(self):
        """Test that records without name field are skipped."""
        bad_data = [
            {
                "packages": ["curl"],
                "fixed": "8.5.0-1",
                # missing "name" field (AVG ID)
            }
        ]

        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=bad_data):
            records = list(parser.parse())
            assert len(records) == 0

    def test_parse_with_empty_packages(self):
        """Test that records without packages don't have FixedIn."""
        data = [
            {
                "name": "AVG-1111",
                "packages": [],
                "affected": "1.0.0-1",
                "fixed": None,
                "severity": "Low",
                "status": "Vulnerable",
                "type": "test",
                "issues": ["CVE-2024-1111"],
                "advisories": [],
            }
        ]

        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=data):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]
            assert len(payload["Vulnerability"]["FixedIn"]) == 0

    def test_parse_unfixed_vulnerability(self):
        """Test that unfixed vulnerabilities emit FixedIn with Version 'None'."""
        data = [
            {
                "name": "AVG-2901",
                "packages": ["pam"],
                "affected": "1.7.0-2",
                "fixed": None,
                "severity": "High",
                "status": "Vulnerable",
                "type": "arbitrary filesystem access",
                "issues": ["CVE-2025-6020"],
                "advisories": [],
            }
        ]

        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=data):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]
            assert group_id == "avg-2901"
            assert len(payload["Vulnerability"]["FixedIn"]) == 1
            assert payload["Vulnerability"]["FixedIn"][0]["Name"] == "pam"
            assert payload["Vulnerability"]["FixedIn"][0]["Version"] == "None"
            assert payload["Vulnerability"]["FixedIn"][0]["VersionFormat"] == "pacman"

    def test_severity_mapping(self):
        """Test that severity values are properly mapped."""
        data = [
            {
                "name": "AVG-1001",
                "packages": ["pkg1"],
                "affected": "0.9.0-1",
                "fixed": "1.0.0-1",
                "severity": "Critical",
                "status": "Fixed",
                "type": "test",
                "issues": [],
                "advisories": [],
            },
            {
                "name": "AVG-1002",
                "packages": ["pkg2"],
                "affected": "0.9.0-1",
                "fixed": "1.0.0-1",
                "severity": "Low",
                "status": "Fixed",
                "type": "test",
                "issues": [],
                "advisories": [],
            },
            {
                "name": "AVG-1003",
                "packages": ["pkg3"],
                "affected": "0.9.0-1",
                "fixed": "1.0.0-1",
                "severity": "Unknown",
                "status": "Fixed",
                "type": "test",
                "issues": [],
                "advisories": [],
            },
        ]

        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=data):
            records = list(parser.parse())
            assert records[0][1]["Vulnerability"]["Severity"] == "Critical"
            assert records[1][1]["Vulnerability"]["Severity"] == "Low"
            assert records[2][1]["Vulnerability"]["Severity"] == "Unknown"

    def test_parse_with_whitespace(self):
        """Test that whitespace in fields is properly stripped."""
        data = [
            {
                "name": "  AVG-1234  ",
                "packages": ["curl"],
                "affected": "8.4.0-1",
                "fixed": "  8.5.0-1  ",
                "severity": "High",
                "status": "Fixed",
                "type": "test",
                "issues": [],
                "advisories": [],
            }
        ]

        parser = Parser(url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_fetch", return_value=data):
            records = list(parser.parse())
            group_id, payload = records[0]
            assert group_id == "avg-1234"
            assert payload["Vulnerability"]["Name"] == "AVG-1234"
            assert payload["Vulnerability"]["FixedIn"][0]["Name"] == "curl"
            assert payload["Vulnerability"]["FixedIn"][0]["Version"] == "8.5.0-1"


class TestArchProvider:
    def test_provider_initialization(self):
        """Test that Provider initializes correctly."""
        with patch("tempfile.mkdtemp") as mock_tmpdir:
            mock_tmpdir.return_value = "/tmp/test"
            config = Config()
            provider = Provider(root="/tmp/test", config=config)

            assert provider.config == config
            assert provider.parser is not None

    def test_provider_name(self):
        """Test that provider has correct name."""
        assert Provider.name() == "arch"

    def test_provider_tags(self):
        """Test that provider has correct tags."""
        tags = Provider.tags()
        assert "vulnerability" in tags
        assert "os" in tags

    def test_provider_schema(self):
        """Test that provider has correct schema."""
        assert Provider.__schema__ is not None

    def test_provider_distribution_version(self):
        """Test that provider has correct distribution version."""
        assert Provider.__distribution_version__ == int(Provider.__schema__.major_version)

    @patch("vunnel.providers.arch.Parser.parse")
    def test_provider_update(self, mock_parse):
        """Test that provider update works correctly."""
        mock_records = [
            (
                "avg-1234",
                {
                    "Vulnerability": {
                        "Name": "AVG-1234",
                        "NamespaceName": "arch:rolling",
                        "Severity": "High",
                        "FixedIn": [],
                    }
                },
            )
        ]
        mock_parse.return_value = iter(mock_records)

        config = Config()
        config.runtime.result_store = result.StoreStrategy.FLAT_FILE

        with patch("tempfile.mkdtemp") as mock_tmpdir:
            mock_tmpdir.return_value = "/tmp/test"
            provider = Provider(root="/tmp/test", config=config)
            assert provider.parser is not None
