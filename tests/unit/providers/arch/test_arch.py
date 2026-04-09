from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import orjson
import pytest

from vunnel import result
from vunnel.providers.arch import Config, Provider
from vunnel.providers.arch.parser import Parser

# ASA mock data for tests
ASA_MOCK_DATES = {
    "ASA-202401-01": "2024-01-15",
    "ASA-202401-02": "2024-01-20",
    "ASA-202310-01": "2023-10-05",
}


def _load_test_fixture():
    """Load the test fixture data for mocking _load."""
    fixture_path = os.path.join(
        os.path.dirname(__file__),
        "test-fixtures/input/arch-advisories/all.json",
    )
    with open(fixture_path, "rb") as f:
        return orjson.loads(f.read())


@pytest.fixture
def mock_workspace(tmp_path):
    """Create a mock workspace for testing."""
    ws = MagicMock()
    ws.input_path = str(tmp_path / "input")
    os.makedirs(ws.input_path, exist_ok=True)
    return ws


@pytest.mark.usefixtures("auto_fake_fixdate_finder")
class TestArchParser:
    @pytest.fixture
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

    def test_parser_initialization(self, mock_workspace):
        """Test that Parser initializes correctly."""
        url = "https://security.archlinux.org/all.json"
        timeout = 30
        parser = Parser(ws=mock_workspace, url=url, timeout=timeout)

        assert parser.url == url
        assert parser.timeout == timeout
        assert parser.logger is not None
        assert parser.workspace == mock_workspace

    def test_parse_with_valid_data(self, mock_workspace, mock_raw_data):
        """Test parsing valid Arch Linux security data."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=mock_raw_data), patch.object(parser, "_prefetch_asa_dates"):
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

    def test_parse_with_metadata(self, mock_workspace, mock_raw_data):
        """Test that metadata is properly populated."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=mock_raw_data), patch.object(parser, "_prefetch_asa_dates"):
            records = list(parser.parse())
            group_id, payload = records[0]

            assert "Metadata" in payload["Vulnerability"]
            assert payload["Vulnerability"]["Metadata"]["CVE"] == [
                {"Name": "CVE-2024-1234", "Link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
            ]
            assert payload["Vulnerability"]["Metadata"]["Advisories"] == ["ASA-202401-01"]

    def test_parse_with_invalid_data_format(self, mock_workspace):
        """Test parsing with invalid data format (not a list)."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with (
            patch.object(parser, "_download"),
            patch.object(parser, "_load", return_value={"invalid": "data"}),
            pytest.raises(ValueError, match="Invalid data format from all.json: expected list"),
        ):
            list(parser.parse())

    def test_parse_with_missing_name_field(self, mock_workspace):
        """Test that records without name field are skipped."""
        bad_data = [
            {
                "packages": ["curl"],
                "fixed": "8.5.0-1",
                # missing "name" field (AVG ID)
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=bad_data):
            records = list(parser.parse())
            assert len(records) == 0

    def test_parse_with_empty_packages(self, mock_workspace):
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
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]
            assert len(payload["Vulnerability"]["FixedIn"]) == 0

    def test_parse_multi_package_vulnerability(self, mock_workspace):
        """Test that AVGs affecting multiple packages create FixedIn entries for each."""
        data = [
            {
                "name": "AVG-1324",
                "packages": ["glibc", "lib32-glibc"],
                "affected": "2.38-1",
                "fixed": "2.38-2",
                "severity": "High",
                "status": "Fixed",
                "type": "arbitrary code execution",
                "issues": ["CVE-2023-4911"],
                "advisories": ["ASA-202310-01"],
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data), patch.object(parser, "_prefetch_asa_dates"):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]
            assert group_id == "avg-1324"

            # Should have FixedIn entries for both packages
            fixed_in = payload["Vulnerability"]["FixedIn"]
            assert len(fixed_in) == 2

            # Verify both packages are present with correct attributes
            package_names = [f["Name"] for f in fixed_in]
            assert "glibc" in package_names
            assert "lib32-glibc" in package_names

            # All should have same version and format
            for entry in fixed_in:
                assert entry["Version"] == "2.38-2"
                assert entry["VersionFormat"] == "pacman"
                assert entry["NamespaceName"] == "arch:rolling"

    def test_parse_unfixed_vulnerability(self, mock_workspace):
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
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]
            assert group_id == "avg-2901"
            assert len(payload["Vulnerability"]["FixedIn"]) == 1
            assert payload["Vulnerability"]["FixedIn"][0]["Name"] == "pam"
            assert payload["Vulnerability"]["FixedIn"][0]["Version"] == "None"
            assert payload["Vulnerability"]["FixedIn"][0]["VersionFormat"] == "pacman"

    def test_parse_skips_not_affected(self, mock_workspace):
        """Test that 'Not affected' status entries are filtered out."""
        data = [
            {
                "name": "AVG-1324",
                "packages": ["glibc", "lib32-glibc"],
                "affected": "2.32-5",
                "fixed": None,
                "severity": "Medium",
                "status": "Not affected",
                "type": "arbitrary code execution",
                "issues": ["CVE-2020-29573"],
                "advisories": [],
            },
            {
                "name": "AVG-1234",
                "packages": ["curl"],
                "affected": "8.4.0-1",
                "fixed": "8.5.0-1",
                "severity": "High",
                "status": "Fixed",
                "type": "arbitrary code execution",
                "issues": ["CVE-2024-1234"],
                "advisories": [],
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            # Only AVG-1234 should be included, AVG-1324 should be filtered out
            assert len(records) == 1
            group_id, payload = records[0]
            assert group_id == "avg-1234"
            assert payload["Vulnerability"]["Name"] == "AVG-1234"

    def test_severity_mapping(self, mock_workspace):
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

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            assert records[0][1]["Vulnerability"]["Severity"] == "Critical"
            assert records[1][1]["Vulnerability"]["Severity"] == "Low"
            assert records[2][1]["Vulnerability"]["Severity"] == "Unknown"

    def test_parse_with_whitespace(self, mock_workspace):
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
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            group_id, payload = records[0]
            assert group_id == "avg-1234"
            assert payload["Vulnerability"]["Name"] == "AVG-1234"
            assert payload["Vulnerability"]["FixedIn"][0]["Name"] == "curl"
            assert payload["Vulnerability"]["FixedIn"][0]["Version"] == "8.5.0-1"

    def test_parse_continues_on_record_error(self, mock_workspace):
        """Test that parsing continues when a single record causes an error."""
        data = [
            {
                "name": "AVG-1111",
                "packages": ["good-pkg"],
                "fixed": "1.0.0",
                "severity": "Low",
                "type": "test",
                "issues": [],
                "advisories": [],
            },
            {
                "name": "AVG-BAD",
                "packages": None,  # This will cause an error when iterating
                "fixed": "1.0.0",
                "severity": "Low",
                "type": "test",
                "issues": [],
                "advisories": [],
            },
            {
                "name": "AVG-2222",
                "packages": ["another-pkg"],
                "fixed": "2.0.0",
                "severity": "High",
                "type": "test",
                "issues": [],
                "advisories": [],
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            # Should have 2 records (bad one skipped)
            assert len(records) == 2
            assert records[0][0] == "avg-1111"
            assert records[1][0] == "avg-2222"

    def test_parse_uses_asa_date_when_available(self, mock_workspace):
        """Test that ASA advisory dates are used when available."""
        data = [
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
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        def mock_fetch_and_cache(asa_id):
            parser._asa_date_cache[asa_id] = ASA_MOCK_DATES.get(asa_id)  # noqa: SLF001

        with (
            patch.object(parser, "_download"),
            patch.object(parser, "_load", return_value=data),
            patch.object(parser, "_fetch_and_cache_asa_date", side_effect=mock_fetch_and_cache),
        ):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]
            assert group_id == "avg-1234"

            # Verify the fixed in entry uses advisory date
            fixed_in = payload["Vulnerability"]["FixedIn"][0]
            assert fixed_in["Available"]["Date"] == "2024-01-15"
            assert fixed_in["Available"]["Kind"] == "advisory"

    def test_parse_fallback_when_asa_unavailable(self, mock_workspace):
        """Test that first-observed date is used when ASA fetch fails."""
        data = [
            {
                "name": "AVG-1234",
                "packages": ["curl"],
                "affected": "8.4.0-1",
                "fixed": "8.5.0-1",
                "severity": "High",
                "status": "Fixed",
                "type": "arbitrary code execution",
                "issues": ["CVE-2024-1234"],
                "advisories": ["ASA-202401-MISSING"],  # ASA that doesn't exist
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        def mock_fetch_and_cache(asa_id):
            # Simulate fetch failure by caching None
            parser._asa_date_cache[asa_id] = None  # noqa: SLF001

        with (
            patch.object(parser, "_download"),
            patch.object(parser, "_load", return_value=data),
            patch.object(parser, "_fetch_and_cache_asa_date", side_effect=mock_fetch_and_cache),
        ):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]

            # Verify the fixed in entry uses first-observed fallback
            fixed_in = payload["Vulnerability"]["FixedIn"][0]
            assert fixed_in["Available"]["Date"] == "2024-01-01"
            assert fixed_in["Available"]["Kind"] == "first-observed"

    def test_parse_with_empty_advisories_list(self, mock_workspace):
        """Test that empty advisories list falls back to first-observed."""
        data = [
            {
                "name": "AVG-9999",
                "packages": ["test-pkg"],
                "affected": "0.9.0-1",
                "fixed": "1.0.0-1",
                "severity": "Medium",
                "status": "Fixed",
                "type": "information disclosure",
                "issues": [],
                "advisories": [],  # No advisories
            },
        ]

        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch.object(parser, "_download"), patch.object(parser, "_load", return_value=data):
            records = list(parser.parse())
            assert len(records) == 1
            group_id, payload = records[0]

            # Verify the fixed in entry uses first-observed
            fixed_in = payload["Vulnerability"]["FixedIn"][0]
            assert fixed_in["Available"]["Date"] == "2024-01-01"
            assert fixed_in["Available"]["Kind"] == "first-observed"

    def test_prefetch_populates_cache(self, mock_workspace):
        """Test that prefetch populates the cache for later lookup."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        mock_response = MagicMock()
        mock_response.text = "Arch Linux Security Advisory ASA-202401-01\nDate    : 2024-01-15\nSeverity: High"

        with patch("vunnel.utils.http_wrapper.get", return_value=mock_response) as mock_get:
            # Prefetch should make HTTP request and populate cache
            parser._fetch_and_cache_asa_date("ASA-202401-01")  # noqa: SLF001
            assert mock_get.call_count == 1

            # Cache lookup should return the prefetched value
            result = parser._get_cached_asa_date("ASA-202401-01")  # noqa: SLF001
            assert result == "2024-01-15"
            assert mock_get.call_count == 1  # No additional HTTP call

    def test_fetch_asa_date_validates_id_format(self, mock_workspace):
        """Test that invalid ASA ID formats are rejected without making HTTP requests."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        with patch("vunnel.utils.http_wrapper.get") as mock_get:
            # Invalid formats should not trigger HTTP requests
            parser._fetch_and_cache_asa_date("invalid-id")  # noqa: SLF001
            parser._fetch_and_cache_asa_date("ASA-1234567890-1")  # noqa: SLF001 (first part too long - 10 digits)
            parser._fetch_and_cache_asa_date("ASA-202401-12345678901")  # noqa: SLF001 (second part too long - 11 digits)
            parser._fetch_and_cache_asa_date("asa-202401-01")  # noqa: SLF001 (lowercase)
            parser._fetch_and_cache_asa_date("ASA-202401-01; rm -rf /")  # noqa: SLF001 (injection attempt)

            # No HTTP requests should have been made
            assert mock_get.call_count == 0

            # All invalid IDs should be cached as None
            assert parser._asa_date_cache.get("invalid-id") is None  # noqa: SLF001
            assert parser._asa_date_cache.get("ASA-1234567890-1") is None  # noqa: SLF001
            assert parser._asa_date_cache.get("ASA-202401-12345678901") is None  # noqa: SLF001
            assert parser._asa_date_cache.get("asa-202401-01") is None  # noqa: SLF001

    def test_fetch_asa_date_accepts_valid_id_format(self, mock_workspace):
        """Test that valid ASA ID formats are accepted (1-9 digits allowed)."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        mock_response = MagicMock()
        mock_response.text = "Date    : 2024-01-15"

        with patch("vunnel.utils.http_wrapper.get", return_value=mock_response) as mock_get:
            # Valid formats: ASA-{1-9 digits}-NN
            parser._fetch_and_cache_asa_date("ASA-1-01")  # noqa: SLF001 (1 digit)
            parser._fetch_and_cache_asa_date("ASA-202401-01")  # noqa: SLF001 (6 digits - typical)
            parser._fetch_and_cache_asa_date("ASA-123456789-01")  # noqa: SLF001 (9 digits)

            # HTTP requests should have been made for valid IDs
            assert mock_get.call_count == 3

    def test_get_best_asa_date_returns_earliest(self, mock_workspace):
        """Test that _get_best_asa_date returns the earliest date from multiple advisories."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        # Pre-populate cache (simulating completed prefetch)
        parser._asa_date_cache["ASA-202401-02"] = "2024-01-20"  # noqa: SLF001
        parser._asa_date_cache["ASA-202401-01"] = "2024-01-15"  # noqa: SLF001

        result = parser._get_best_asa_date(["ASA-202401-02", "ASA-202401-01"])  # noqa: SLF001
        assert result == "2024-01-15"  # Should return earliest

    def test_prefetch_asa_dates_populates_cache_for_batch(self, mock_workspace):
        """Test that _prefetch_asa_dates populates cache for all ASAs in data."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        # Test data with multiple fixed vulnerabilities having advisories
        test_data = [
            {"fixed": "1.0", "status": "Fixed", "advisories": ["ASA-202401-01", "ASA-202401-02"]},
            {"fixed": "2.0", "status": "Fixed", "advisories": ["ASA-202401-03"]},
            {"fixed": None, "status": "Not affected", "advisories": ["ASA-202401-04"]},  # Should be skipped
        ]

        def mock_get(url, **kwargs):
            response = MagicMock()
            if "ASA-202401-01" in url:
                response.text = "Date    : 2024-01-15"
            elif "ASA-202401-02" in url:
                response.text = "Date    : 2024-01-20"
            elif "ASA-202401-03" in url:
                response.text = "Date    : 2024-01-25"
            else:
                response.text = "No date"
            return response

        with patch("vunnel.utils.http_wrapper.get", side_effect=mock_get):
            with patch("time.sleep"):  # Don't actually sleep in tests
                parser._prefetch_asa_dates(test_data, max_workers=2, batch_size=10)  # noqa: SLF001

        # Verify cache was populated for fixed vulnerabilities only
        assert parser._asa_date_cache.get("ASA-202401-01") == "2024-01-15"  # noqa: SLF001
        assert parser._asa_date_cache.get("ASA-202401-02") == "2024-01-20"  # noqa: SLF001
        assert parser._asa_date_cache.get("ASA-202401-03") == "2024-01-25"  # noqa: SLF001
        assert "ASA-202401-04" not in parser._asa_date_cache  # noqa: SLF001

    def test_prefetch_asa_dates_handles_partial_failures(self, mock_workspace):
        """Test that prefetch continues when some fetches fail."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        test_data = [
            {"fixed": "1.0", "status": "Fixed", "advisories": ["ASA-202401-01", "ASA-202401-02", "ASA-202401-03"]},
        ]

        call_count = 0

        def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "ASA-202401-02" in url:
                # Simulate network failure for one ASA
                import requests
                raise requests.RequestException("Connection failed")
            response = MagicMock()
            if "ASA-202401-01" in url:
                response.text = "Date    : 2024-01-15"
            elif "ASA-202401-03" in url:
                response.text = "Date    : 2024-01-25"
            return response

        with patch("vunnel.utils.http_wrapper.get", side_effect=mock_get):
            with patch("time.sleep"):
                # Should not raise despite one failure
                parser._prefetch_asa_dates(test_data, max_workers=2, batch_size=10)  # noqa: SLF001

        # Successful fetches should be cached
        assert parser._asa_date_cache.get("ASA-202401-01") == "2024-01-15"  # noqa: SLF001
        assert parser._asa_date_cache.get("ASA-202401-03") == "2024-01-25"  # noqa: SLF001
        # Failed fetch should have None in cache
        assert parser._asa_date_cache.get("ASA-202401-02") is None  # noqa: SLF001
        # All three should have been attempted
        assert call_count == 3

    def test_prefetch_asa_dates_rate_limits_between_batches(self, mock_workspace):
        """Test that prefetch pauses between batches to respect rate limits."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        # Create enough ASAs to span multiple batches (batch_size=2 for testing)
        test_data = [
            {"fixed": "1.0", "status": "Fixed", "advisories": ["ASA-202401-01", "ASA-202401-02", "ASA-202401-03", "ASA-202401-04", "ASA-202401-05"]},
        ]

        def mock_get(url, **kwargs):
            response = MagicMock()
            response.text = "Date    : 2024-01-15"
            return response

        with patch("vunnel.utils.http_wrapper.get", side_effect=mock_get):
            with patch("time.sleep") as mock_sleep:
                parser._prefetch_asa_dates(test_data, max_workers=2, batch_size=2)  # noqa: SLF001

                # With 5 ASAs and batch_size=2, we have 3 batches: [2, 2, 1]
                # Sleep should be called between batches (not after the last one)
                assert mock_sleep.call_count == 2
                # Each sleep should be 1.0 second
                for call in mock_sleep.call_args_list:
                    assert call[0][0] == 1.0

    def test_prefetch_asa_dates_executes_all_fetches_in_batch(self, mock_workspace):
        """Test that prefetch executes all fetches within a batch using thread pool."""
        parser = Parser(ws=mock_workspace, url="https://security.archlinux.org/all.json", timeout=30)

        test_data = [
            {"fixed": "1.0", "status": "Fixed", "advisories": ["ASA-202401-01", "ASA-202401-02", "ASA-202401-03"]},
        ]

        fetched_urls = []

        def mock_get(url, **kwargs):
            fetched_urls.append(url)
            response = MagicMock()
            response.text = "Date    : 2024-01-15"
            return response

        with patch("vunnel.utils.http_wrapper.get", side_effect=mock_get):
            with patch("time.sleep"):
                parser._prefetch_asa_dates(test_data, max_workers=3, batch_size=10)  # noqa: SLF001

        # Verify all ASAs were fetched
        assert len(fetched_urls) == 3
        assert any("ASA-202401-01" in url for url in fetched_urls)
        assert any("ASA-202401-02" in url for url in fetched_urls)
        assert any("ASA-202401-03" in url for url in fetched_urls)


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
                    },
                },
            ),
        ]
        mock_parse.return_value = iter(mock_records)

        config = Config()
        config.runtime.result_store = result.StoreStrategy.FLAT_FILE

        with patch("tempfile.mkdtemp") as mock_tmpdir:
            mock_tmpdir.return_value = "/tmp/test"
            provider = Provider(root="/tmp/test", config=config)
            assert provider.parser is not None


def test_provider_schema(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    """Test that provider output conforms to the expected schema."""
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
    )

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    # Mock _download and _load to return test fixture data
    test_data = _load_test_fixture()
    monkeypatch.setattr(p.parser, "_download", lambda: None)
    monkeypatch.setattr(p.parser, "_load", lambda: test_data)

    # Mock ASA date fetching - populate cache like real prefetch does
    def mock_fetch_and_cache(asa_id):
        p.parser._asa_date_cache[asa_id] = ASA_MOCK_DATES.get(asa_id)

    monkeypatch.setattr(p.parser, "_fetch_and_cache_asa_date", mock_fetch_and_cache)

    p.update(None)

    assert workspace.num_result_entries() == 5
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    """Test provider output against expected snapshots."""
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
    )

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    # Mock _download and _load to return test fixture data
    test_data = _load_test_fixture()
    monkeypatch.setattr(p.parser, "_download", lambda: None)
    monkeypatch.setattr(p.parser, "_load", lambda: test_data)

    # Mock ASA date fetching - populate cache like real prefetch does
    def mock_fetch_and_cache(asa_id):
        p.parser._asa_date_cache[asa_id] = ASA_MOCK_DATES.get(asa_id)

    monkeypatch.setattr(p.parser, "_fetch_and_cache_asa_date", mock_fetch_and_cache)

    p.update(None)

    workspace.assert_result_snapshots()
