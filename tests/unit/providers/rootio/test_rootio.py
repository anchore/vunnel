from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from vunnel import result, workspace
from vunnel.providers.rootio import Config, Provider, parser


class TestRootIoProvider:
    @pytest.fixture
    def mock_root_io_feed(self):
        """Returns sample Root.io CVE feed data matching actual API format"""
        return {
            "alpine": [
                {
                    "distroversion": "3.17",
                    "packages": [
                        {
                            "pkg": {
                                "name": "libssl3",
                                "cves": {
                                    "CVE-2023-0464": {
                                        "fixed_versions": ["3.0.8-r4"],
                                    },
                                    "CVE-2023-0465": {
                                        "fixed_versions": ["3.0.8-r4"],
                                    },
                                },
                            },
                        },
                        {
                            "pkg": {
                                "name": "openssl",
                                "cves": {
                                    "CVE-2023-0464": {
                                        "fixed_versions": ["3.0.8-r4"],
                                    },
                                },
                            },
                        },
                    ],
                },
            ],
            "debian": [
                {
                    "distroversion": "11",
                    "packages": [
                        {
                            "pkg": {
                                "name": "libgcrypt20",
                                "cves": {
                                    "CVE-2021-40528": {
                                        "fixed_versions": ["1.8.7-6+deb11u1"],
                                    },
                                },
                            },
                        },
                        {
                            "pkg": {
                                "name": "curl",
                                "cves": {
                                    "CVE-2023-9999": {
                                        "fixed_versions": [],  # No fix available
                                    },
                                },
                            },
                        },
                    ],
                },
            ],
        }

    def test_provider_name(self):
        """Test that provider returns correct name"""
        assert Provider.name() == "rootio"

    def test_config_defaults(self):
        """Test that Config has proper defaults"""
        config = Config()
        assert config.request_timeout == 125
        assert config.runtime.result_store == result.StoreStrategy.SQLITE

    def test_parser_normalize_with_fixed_versions(self, tmpdir, mock_root_io_feed):
        """Test that parser emits actual fixed versions from Root.io"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        # Test Alpine data
        alpine_data = mock_root_io_feed["alpine"][0]
        vuln_records = p._normalize("alpine", alpine_data)

        # Should have 2 CVEs
        assert "CVE-2023-0464" in vuln_records
        assert "CVE-2023-0465" in vuln_records

        # Check CVE-2023-0464 structure
        cve_2023_0464 = vuln_records["CVE-2023-0464"]
        assert cve_2023_0464["Vulnerability"]["Name"] == "CVE-2023-0464"
        assert cve_2023_0464["Vulnerability"]["NamespaceName"] == "rootio:distro:alpine:3.17"

        # Should have FixedIn entries with actual versions (NOT sentinel values)
        fixed_in = cve_2023_0464["Vulnerability"]["FixedIn"]
        assert len(fixed_in) == 2  # libssl3 and openssl

        # Verify actual versions are emitted
        versions = [fi["Version"] for fi in fixed_in]
        assert "3.0.8-r4" in versions
        assert "ROOTIO_UNAFFECTED" not in versions  # Should NOT use sentinel

        # Verify version format
        for fi in fixed_in:
            assert fi["VersionFormat"] == "apk"
            assert fi["NamespaceName"] == "rootio:distro:alpine:3.17"

    def test_parser_normalize_with_empty_fixed_versions(self, tmpdir, mock_root_io_feed):
        """Test that parser handles empty fixed_versions correctly"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        # Test Debian data with empty fixed_versions
        debian_data = mock_root_io_feed["debian"][0]
        vuln_records = p._normalize("debian", debian_data)

        # Check CVE with no fix
        cve_no_fix = vuln_records["CVE-2023-9999"]
        fixed_in = cve_no_fix["Vulnerability"]["FixedIn"]

        # Should have entry with empty version
        assert len(fixed_in) == 1
        assert fixed_in[0]["Name"] == "curl"
        assert fixed_in[0]["Version"] == ""  # Empty indicates no fix
        assert fixed_in[0]["VersionFormat"] == "dpkg"

    def test_parser_version_format_mapping(self, tmpdir):
        """Test that parser maps distros to correct version formats"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        # Test version format mappings
        assert p._get_version_format("alpine") == "apk"
        assert p._get_version_format("debian") == "dpkg"
        assert p._get_version_format("ubuntu") == "dpkg"
        assert p._get_version_format("rhel") == "rpm"
        assert p._get_version_format("centos") == "rpm"
        assert p._get_version_format("rocky") == "rpm"
        assert p._get_version_format("alma") == "rpm"

    def test_parser_namespace_format(self, tmpdir, mock_root_io_feed):
        """Test that parser generates correct rootio namespace format"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        alpine_data = mock_root_io_feed["alpine"][0]
        vuln_records = p._normalize("alpine", alpine_data)

        # All records should have rootio namespace
        for record in vuln_records.values():
            namespace = record["Vulnerability"]["NamespaceName"]
            assert namespace == "rootio:distro:alpine:3.17"

    def test_parser_get_generator(self, tmpdir, mock_root_io_feed):
        """Test the parser.get() generator yields correct data"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        # Mock the download and file reading
        import orjson
        feed_path = Path(ws.input_path) / "rootio-data" / "cve_feed.json"
        os.makedirs(feed_path.parent, exist_ok=True)
        with open(feed_path, "wb") as f:
            f.write(orjson.dumps(mock_root_io_feed))

        # Mock download to avoid actual HTTP call
        with patch.object(p, "_download"):
            results = list(p.get())

        # Should yield (namespace, vuln_id, record) tuples
        assert len(results) > 0

        # Check structure
        for namespace, vuln_id, record in results:
            assert namespace.startswith("rootio:distro:")
            assert vuln_id.startswith("CVE-")
            assert "Vulnerability" in record
            assert record["Vulnerability"]["Name"] == vuln_id
            assert record["Vulnerability"]["NamespaceName"] == namespace

    def test_provider_update(self, tmpdir, mock_root_io_feed):
        """Test the provider update process"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        config = Config()
        p = Provider(root=str(tmpdir), config=config)

        # Mock the download and feed data
        import orjson
        feed_path = Path(ws.input_path) / "rootio-data" / "cve_feed.json"
        os.makedirs(feed_path.parent, exist_ok=True)
        with open(feed_path, "wb") as f:
            f.write(orjson.dumps(mock_root_io_feed))

        # Mock download
        with patch.object(p.parser, "_download"):
            urls, count = p.update(last_updated=None)

        # Should return URL and count
        assert isinstance(urls, list)
        assert len(urls) == 1
        assert urls[0] == "https://api.root.io/external/cve_feed"
        assert count > 0

    def test_parser_metadata_structure(self, tmpdir, mock_root_io_feed):
        """Test that vulnerability metadata is correctly structured"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        alpine_data = mock_root_io_feed["alpine"][0]
        vuln_records = p._normalize("alpine", alpine_data)

        for cve_id, record in vuln_records.items():
            vuln = record["Vulnerability"]

            # Check required fields
            assert "Name" in vuln
            assert "NamespaceName" in vuln
            assert "FixedIn" in vuln
            assert "Metadata" in vuln

            # Check metadata structure
            assert "CVE" in vuln["Metadata"]
            assert len(vuln["Metadata"]["CVE"]) > 0
            assert vuln["Metadata"]["CVE"][0]["Name"] == cve_id

    def test_parser_handles_multiple_packages_same_cve(self, tmpdir, mock_root_io_feed):
        """Test that parser correctly handles multiple packages affected by same CVE"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        alpine_data = mock_root_io_feed["alpine"][0]
        vuln_records = p._normalize("alpine", alpine_data)

        # CVE-2023-0464 affects both libssl3 and openssl
        cve_record = vuln_records["CVE-2023-0464"]
        fixed_in = cve_record["Vulnerability"]["FixedIn"]

        # Should have 2 FixedIn entries
        assert len(fixed_in) == 2

        # Check both packages are present
        package_names = [fi["Name"] for fi in fixed_in]
        assert "libssl3" in package_names
        assert "openssl" in package_names


class TestRootIoParser:
    """Additional parser-specific tests"""

    def test_version_format_default(self, tmpdir):
        """Test that unknown distros default to dpkg format"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        # Unknown distro should default to dpkg
        assert p._get_version_format("unknown-distro") == "dpkg"

    def test_parser_init_creates_logger(self, tmpdir):
        """Test that parser creates logger if none provided"""
        ws = workspace.Workspace(tmpdir, "rootio", create=True)
        p = parser.Parser(
            workspace=ws,
            url="https://api.root.io/external/cve_feed",
        )

        assert p.logger is not None
        assert p.logger.name == "Parser"
