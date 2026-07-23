from __future__ import annotations

import pytest
from vunnel import workspace
from vunnel.providers.bellsoft.parser import Parser


class TestNormalizeSeverities:
    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        return Parser(ws=workspace.Workspace(tmpdir, "test", create=True))

    def test_normalizes_cvss_v2_without_prefix(self, parser):
        """CVSS v2 vectors without prefix should get CVSS:2.0/ added."""
        vuln_entry = {
            "id": "BELL-CVE-2000-0344",
            "severity": [
                {
                    "score": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    "type": "CVSS_V2",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"][0]["score"] == "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P"
        assert result["severity"][0]["type"] == "CVSS_V2"

    def test_preserves_cvss_v2_with_prefix(self, parser):
        """CVSS v2 vectors already with prefix should be unchanged."""
        vuln_entry = {
            "id": "BELL-CVE-2000-0344",
            "severity": [
                {
                    "score": "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    "type": "CVSS_V2",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"][0]["score"] == "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P"

    def test_normalizes_cvss_v3_without_prefix(self, parser):
        """CVSS v3 vectors without prefix should get CVSS:3.0/ added."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "severity": [
                {
                    "score": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "type": "CVSS_V3",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"][0]["score"] == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_preserves_cvss_v3_with_version(self, parser):
        """CVSS v3 vectors with specific version should be unchanged."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "severity": [
                {
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "type": "CVSS_V3",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"][0]["score"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_normalizes_cvss_v4_without_prefix(self, parser):
        """CVSS v4 vectors without prefix should get CVSS:4.0/ added."""
        vuln_entry = {
            "id": "BELL-CVE-2024-1234",
            "severity": [
                {
                    "score": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
                    "type": "CVSS_V4",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"][0]["score"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"

    def test_handles_empty_severity_list(self, parser):
        """Entries with no severities should be unchanged."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "severity": [],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"] == []

    def test_handles_missing_severity_key(self, parser):
        """Entries without severity key should be unchanged."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
        }

        result = parser._normalize_severities(vuln_entry)

        assert "severity" not in result or result.get("severity") == []

    def test_handles_multiple_severities(self, parser):
        """Multiple severity entries should all be normalized."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "severity": [
                {
                    "score": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    "type": "CVSS_V2",
                },
                {
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "type": "CVSS_V3",
                },
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert len(result["severity"]) == 2
        assert result["severity"][0]["score"] == "CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P"
        assert result["severity"][1]["score"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_handles_empty_score(self, parser):
        """Empty score strings should not cause errors."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "severity": [
                {
                    "score": "",
                    "type": "CVSS_V2",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["severity"][0]["score"] == ""

    def test_preserves_other_fields(self, parser):
        """Other fields in vuln_entry should be preserved."""
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "summary": "Test vulnerability",
            "references": [{"url": "https://example.com"}],
            "severity": [
                {
                    "score": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    "type": "CVSS_V2",
                }
            ],
        }

        result = parser._normalize_severities(vuln_entry)

        assert result["id"] == "BELL-CVE-2020-1234"
        assert result["summary"] == "Test vulnerability"
        assert result["references"] == [{"url": "https://example.com"}]

    def test_does_not_mutate_original(self, parser):
        """The original vuln_entry should not be mutated."""
        original_score = "AV:N/AC:L/Au:N/C:N/I:N/A:P"
        vuln_entry = {
            "id": "BELL-CVE-2020-1234",
            "severity": [
                {
                    "score": original_score,
                    "type": "CVSS_V2",
                }
            ],
        }

        parser._normalize_severities(vuln_entry)

        assert vuln_entry["severity"][0]["score"] == original_score
