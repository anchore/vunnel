from __future__ import annotations

import pytest

from vunnel.providers.nvd.dedupe import deduplicate_references


class TestDeduplicateReferences:
    def test_empty_list(self):
        result = deduplicate_references([])
        assert result == []

    def test_no_duplicates(self):
        refs = [
            {"url": "https://example.com", "source": "cve@mitre.org"},
            {"url": "https://other.com", "source": "nvd@nist.gov"},
        ]
        result = deduplicate_references(refs)
        assert result == refs

    def test_exact_duplicates(self):
        refs = [
            {"url": "https://example.com", "source": "cve@mitre.org"},
            {"url": "https://example.com", "source": "cve@mitre.org"},
            {"url": "https://other.com", "source": "nvd@nist.gov"},
        ]
        result = deduplicate_references(refs)
        assert len(result) == 2
        assert result[0] == {"url": "https://example.com", "source": "cve@mitre.org"}
        assert result[1] == {"url": "https://other.com", "source": "nvd@nist.gov"}

    def test_same_url_different_metadata(self):
        """When URLs match but other fields differ, keep only the first occurrence."""
        refs = [
            {"url": "https://example.com", "source": "cve@mitre.org", "tags": ["Vendor Advisory"]},
            {"url": "https://example.com", "source": "different@example.com", "tags": ["Third Party"]},
        ]
        result = deduplicate_references(refs)
        assert len(result) == 1
        assert result[0] == {"url": "https://example.com", "source": "cve@mitre.org", "tags": ["Vendor Advisory"]}

    def test_preserves_order(self):
        refs = [
            {"url": "https://aaa.com", "source": "a"},
            {"url": "https://bbb.com", "source": "b"},
            {"url": "https://aaa.com", "source": "a"},
            {"url": "https://ccc.com", "source": "c"},
            {"url": "https://bbb.com", "source": "b"},
        ]
        result = deduplicate_references(refs)
        assert len(result) == 3
        assert result[0]["url"] == "https://aaa.com"
        assert result[1]["url"] == "https://bbb.com"
        assert result[2]["url"] == "https://ccc.com"

    def test_many_duplicates(self):
        """Test case similar to CVE-2021-44228 with extreme duplication."""
        cisco_url = "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
        refs = [{"url": cisco_url, "source": "security@cisco.com"}] * 486
        refs.append({"url": "https://other.com", "source": "other"})

        result = deduplicate_references(refs)
        assert len(result) == 2
        assert result[0]["url"] == cisco_url
        assert result[1]["url"] == "https://other.com"

    def test_with_tags_field(self):
        refs = [
            {"url": "https://example.com", "source": "cve@mitre.org", "tags": ["Vendor Advisory", "Patch"]},
            {"url": "https://example.com", "source": "cve@mitre.org", "tags": ["Vendor Advisory", "Patch"]},
        ]
        result = deduplicate_references(refs)
        assert len(result) == 1
        assert result[0]["tags"] == ["Vendor Advisory", "Patch"]

    def test_missing_url_field(self):
        """Handle gracefully if a reference is missing the URL field."""
        refs = [
            {"url": "https://example.com", "source": "cve@mitre.org"},
            {"source": "no-url@example.com"},
            {"url": "https://other.com", "source": "nvd@nist.gov"},
        ]
        # Should not crash, behavior to be determined (skip or keep malformed entries)
        result = deduplicate_references(refs)
        assert len(result) <= len(refs)
