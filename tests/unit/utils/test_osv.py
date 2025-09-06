from unittest.mock import Mock
from datetime import date

from vunnel.utils import osv
from vunnel.tool.fixdate.finder import Result as FixResult


class TestPatchFixDate:
    def test_no_fixdater_returns_early(self):
        """Test that function returns early when no fixdater is provided."""
        advisory = {"id": "test-vuln", "affected": []}
        original_advisory = advisory.copy()

        osv.patch_fix_date(advisory, None)

        # Advisory should remain unchanged
        assert advisory == original_advisory

    def test_empty_advisory_no_changes(self):
        """Test that empty advisory dict is handled gracefully."""
        advisory = {}
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        # Should not crash and advisory should remain empty
        assert advisory == {}
        fixdater.best.assert_not_called()

    def test_advisory_without_affected_no_changes(self):
        """Test advisory without affected field is handled gracefully."""
        advisory = {"id": "test-vuln"}
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        assert advisory == {"id": "test-vuln"}
        fixdater.best.assert_not_called()

    def test_affected_without_package_name_skipped(self):
        """Test that affected entries without package name are skipped."""
        advisory = {
            "id": "test-vuln",
            "affected": [
                {"package": {}},  # No name
                {"package": {"name": ""}},  # Empty name
            ]
        }
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        fixdater.best.assert_not_called()

    def test_affected_without_ecosystem_skipped(self):
        """Test that affected entries without ecosystem are skipped."""
        advisory = {
            "id": "test-vuln",
            "affected": [
                {"package": {"name": "test-pkg"}},  # No ecosystem
                {"package": {"name": "test-pkg", "ecosystem": ""}},  # Empty ecosystem
            ]
        }
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        fixdater.best.assert_not_called()

    def test_no_ranges_no_changes(self):
        """Test that affected entries without ranges are handled gracefully."""
        advisory = {
            "id": "test-vuln",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "test-eco"},
                    # No ranges field
                }
            ]
        }
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        fixdater.best.assert_not_called()

    def test_no_events_no_changes(self):
        """Test that ranges without events are handled gracefully."""
        advisory = {
            "id": "test-vuln",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "test-eco"},
                    "ranges": [
                        {"type": "ECOSYSTEM"},  # No events
                        {"type": "ECOSYSTEM", "events": []},  # Empty events
                    ]
                }
            ]
        }
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        fixdater.best.assert_not_called()

    def test_events_without_fixed_version_skipped(self):
        """Test that events without 'fixed' field are skipped."""
        advisory = {
            "id": "test-vuln",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "test-eco"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0.0"},  # No fixed field
                                {"fixed": ""},  # Empty fixed field
                            ]
                        }
                    ]
                }
            ]
        }
        fixdater = Mock()

        osv.patch_fix_date(advisory, fixdater)

        fixdater.best.assert_not_called()

    def test_fixdater_no_results_no_changes(self):
        """Test that when fixdater returns no results, no changes are made."""
        advisory = {
            "id": "test-vuln",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "test-eco"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"fixed": "1.0.1"}]
                        }
                    ]
                }
            ]
        }
        fixdater = Mock()
        fixdater.best.return_value = None  # No results

        osv.patch_fix_date(advisory, fixdater)

        # Should have called find but made no changes to database_specific
        fixdater.best.assert_called_once_with(
            vuln_id="test-vuln",
            cpe_or_package="test-pkg",
            fix_version="1.0.1",
            ecosystem="test-eco",
            candidates=[],
        )

        # No database_specific should be added
        assert "database_specific" not in advisory["affected"][0]["ranges"][0]

    def test_successful_fix_date_patching(self):
        """Test successful patching of fix date data."""
        advisory = {
            "id": "CVE-2023-1234",
            "affected": [
                {
                    "package": {"name": "example-pkg", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"fixed": "2.1.0"}]
                        }
                    ]
                }
            ]
        }

        # Mock fixdater result
        fix_result = Mock(spec=FixResult)
        fix_result.date = date(2023, 6, 15)
        fix_result.kind = "release"

        fixdater = Mock()
        fixdater.best.return_value = fix_result

        osv.patch_fix_date(advisory, fixdater)

        # Verify the call
        fixdater.best.assert_called_once_with(
            vuln_id="CVE-2023-1234",
            cpe_or_package="example-pkg",
            fix_version="2.1.0",
            ecosystem="npm",
            candidates=[],
        )

        # Verify the fix data was added
        expected_fix = {
            "version": "2.1.0",
            "date": "2023-06-15",
            "kind": "release"
        }

        range_obj = advisory["affected"][0]["ranges"][0]
        assert "database_specific" in range_obj
        assert "anchore" in range_obj["database_specific"]
        assert "fixes" in range_obj["database_specific"]["anchore"]
        assert range_obj["database_specific"]["anchore"]["fixes"] == [expected_fix]

    def test_ecosystem_processor_called(self):
        """Test that ecosystem_processor is called when provided."""
        advisory = {
            "id": "CVE-2023-0001",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "original-eco"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"fixed": "1.0.0"}]
                        }
                    ]
                }
            ]
        }

        fix_result = Mock(spec=FixResult)
        fix_result.date = date(2023, 1, 1)
        fix_result.kind = "release"

        fixdater = Mock()
        fixdater.best.return_value = fix_result

        ecosystem_processor = Mock(return_value="processed-eco")

        osv.patch_fix_date(advisory, fixdater, ecosystem_processor)

        # Verify ecosystem processor was called
        ecosystem_processor.assert_called_once_with("original-eco")

        # Verify fixdater was called with processed ecosystem
        fixdater.best.assert_called_once_with(
            vuln_id="CVE-2023-0001",
            cpe_or_package="test-pkg",
            fix_version="1.0.0",
            ecosystem="processed-eco",
            candidates=[],
        )

    def test_preserve_existing_database_specific(self):
        """Test that existing database_specific data is preserved."""
        advisory = {
            "id": "CVE-2023-0002",
            "affected": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"fixed": "1.0.0"}],
                            "database_specific": {
                                "existing_field": "existing_value",
                                "other_data": {"nested": True}
                            }
                        }
                    ]
                }
            ]
        }

        fix_result = Mock(spec=FixResult)
        fix_result.date = date(2023, 1, 1)
        fix_result.kind = "release"

        fixdater = Mock()
        fixdater.best.return_value = fix_result

        osv.patch_fix_date(advisory, fixdater)

        # Verify existing data is preserved and anchore data is added
        db_spec = advisory["affected"][0]["ranges"][0]["database_specific"]

        assert db_spec["existing_field"] == "existing_value"
        assert db_spec["other_data"] == {"nested": True}
        assert "anchore" in db_spec
        assert "fixes" in db_spec["anchore"]
        assert len(db_spec["anchore"]["fixes"]) == 1
