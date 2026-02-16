from __future__ import annotations

import datetime
import os

import orjson
import pytest

from vunnel import result, workspace
from vunnel.providers.fedora import Config, Provider
from vunnel.providers.fedora.parser import Parser, _INCREMENTAL_FILE


class TestParseUpdate:
    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        config = Config()
        return Parser(workspace=ws, config=config)

    def test_null_epoch(self, parser):
        """When Bodhi returns null for epoch, it should default to 0."""
        update = {
            "alias": "FEDORA-2025-test1",
            "release": {"version": "40"},
            "severity": "medium",
            "bugs": [{"bug_id": 1, "security": True, "title": "CVE-2025-0001 test vuln"}],
            "builds": [{"nvr": "foo-1.0-1.fc40", "type": "rpm", "epoch": None}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["packages"][0]["version"] == "0:1.0-1.fc40"

    def test_nonzero_epoch(self, parser):
        """Non-zero epoch should be preserved in the version string."""
        update = {
            "alias": "FEDORA-2025-test2",
            "release": {"version": "40"},
            "severity": "high",
            "bugs": [{"bug_id": 2, "security": True, "title": "CVE-2025-0002 test vuln"}],
            "builds": [{"nvr": "java-17-openjdk-17.0.14.0.7-1.fc40", "type": "rpm", "epoch": 1}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["packages"][0]["version"] == "1:17.0.14.0.7-1.fc40"

    def test_zero_epoch(self, parser):
        """Explicit zero epoch should produce 0: prefix."""
        update = {
            "alias": "FEDORA-2025-test3",
            "release": {"version": "40"},
            "severity": "low",
            "bugs": [{"bug_id": 3, "security": True, "title": "CVE-2025-0003 test vuln"}],
            "builds": [{"nvr": "foo-2.0-1.fc40", "type": "rpm", "epoch": 0}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["packages"][0]["version"] == "0:2.0-1.fc40"

    def test_cve_from_display_name(self, parser):
        """CVE should be extracted from display_name when bugs have no CVE."""
        update = {
            "alias": "FEDORA-2025-test4",
            "display_name": "Fix CVE-2024-8176",
            "title": "expat-2.7.0-1.fc40",
            "release": {"version": "40"},
            "severity": "medium",
            "bugs": [{"bug_id": 4, "security": False, "title": "expat-2.7.0 is available"}],
            "builds": [{"nvr": "expat-2.7.0-1.fc40", "type": "rpm", "epoch": 0}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["cves"] == ["CVE-2024-8176"]

    def test_cve_from_title_fallback(self, parser):
        """CVE should be extracted from title when display_name and bugs have no CVE."""
        update = {
            "alias": "FEDORA-2025-test5",
            "display_name": "",
            "title": "CVE-2024-9999-fix-1.0-1.fc40",
            "release": {"version": "40"},
            "severity": "medium",
            "bugs": [{"bug_id": 5, "security": False, "title": "update available"}],
            "builds": [{"nvr": "foo-1.0-1.fc40", "type": "rpm", "epoch": 0}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["cves"] == ["CVE-2024-9999"]

    def test_multiple_cves_from_bugs(self, parser):
        """Multiple CVEs from different bugs should all be extracted."""
        update = {
            "alias": "FEDORA-2025-test6",
            "release": {"version": "40"},
            "severity": "medium",
            "bugs": [
                {"bug_id": 6, "security": True, "title": "CVE-2024-56171 libxml2: UAF [fedora-40]"},
                {"bug_id": 7, "security": True, "title": "CVE-2025-24928 libxml2: stack overflow [fedora-40]"},
            ],
            "builds": [{"nvr": "libxml2-2.12.10-1.fc40", "type": "rpm", "epoch": 0}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["cves"] == ["CVE-2024-56171", "CVE-2025-24928"]

    def test_bugs_cves_preferred_over_title(self, parser):
        """When bugs have CVEs, display_name/title CVEs should not be added."""
        update = {
            "alias": "FEDORA-2025-test7",
            "display_name": "Fix CVE-2024-9999",
            "release": {"version": "40"},
            "severity": "medium",
            "bugs": [{"bug_id": 8, "security": True, "title": "CVE-2024-1111 some vuln"}],
            "builds": [{"nvr": "foo-1.0-1.fc40", "type": "rpm", "epoch": 0}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }
        advisory = parser._parse_update(update)
        assert advisory is not None
        assert advisory["cves"] == ["CVE-2024-1111"]


class TestNormalize:
    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        config = Config()
        return Parser(workspace=ws, config=config)

    def test_multiple_cves_yield_multiple_records(self, parser):
        """Each CVE in an advisory should yield a separate vulnerability record."""
        advisory = {
            "advisory_id": "FEDORA-2025-test",
            "release": "40",
            "severity": "Medium",
            "title": "libxml2 security update",
            "description": "",
            "issued_date": "2025-03-20 10:00:00",
            "updated_date": "2025-03-29 12:00:00",
            "date_stable": "2025-03-29 12:00:00",
            "cves": ["CVE-2024-56171", "CVE-2025-24928"],
            "packages": [{"name": "libxml2", "version": "0:2.12.10-1.fc40"}],
            "link": "https://bodhi.fedoraproject.org/updates/FEDORA-2025-test",
        }
        results = list(parser._normalize(advisory))
        assert len(results) == 2

        ids = [r[0] for r in results]
        assert "fedora:40/CVE-2024-56171" in ids
        assert "fedora:40/CVE-2025-24928" in ids

        for _, record in results:
            assert record["Vulnerability"]["NamespaceName"] == "fedora:40"
            assert len(record["Vulnerability"]["FixedIn"]) == 1
            assert record["Vulnerability"]["FixedIn"][0]["Name"] == "libxml2"

    def test_no_cves_uses_advisory_id(self, parser):
        """When no CVEs are found, advisory ID should be used as the vulnerability name."""
        advisory = {
            "advisory_id": "FEDORA-2025-nocve",
            "release": "40",
            "severity": "Low",
            "title": "some update",
            "description": "",
            "issued_date": "2025-01-01 10:00:00",
            "updated_date": "2025-01-05 12:00:00",
            "date_stable": "2025-01-05 12:00:00",
            "cves": [],
            "packages": [{"name": "foo", "version": "0:1.0-1.fc40"}],
            "link": "https://bodhi.fedoraproject.org/updates/FEDORA-2025-nocve",
        }
        results = list(parser._normalize(advisory))
        assert len(results) == 1
        assert results[0][0] == "fedora:40/FEDORA-2025-nocve"
        assert results[0][1]["Vulnerability"]["Name"] == "FEDORA-2025-nocve"


def test_provider_schema(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    monkeypatch.setattr(p.parser, "_download", p.parser._existing_input_files)

    p.update(None)

    # 4 updates: 1 CVE + 1 CVE-from-display_name + 2 CVEs + 1 CVE = 5 records
    assert workspace.num_result_entries() == 5
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    monkeypatch.setattr(p.parser, "_download", p.parser._existing_input_files)

    p.update(None)

    workspace.assert_result_snapshots()


class TestIncremental:
    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        config = Config()
        return Parser(workspace=ws, config=config)

    def _write_page(self, parser, updates, filename="bodhi-updates-page-1.json"):
        """Helper to write a page file into the parser's input directory."""
        filepath = os.path.join(parser.workspace.input_path, filename)
        with open(filepath, "wb") as f:
            f.write(orjson.dumps(updates))
        return filepath

    def _make_update(self, alias="FEDORA-2025-aaa", cve="CVE-2025-0001", severity="medium", version="40", pkg_name="foo", pkg_version="1.0-1.fc40"):
        return {
            "alias": alias,
            "release": {"version": version},
            "severity": severity,
            "bugs": [{"bug_id": 1, "security": True, "title": f"{cve} test vuln"}],
            "builds": [{"nvr": f"{pkg_name}-{pkg_version}", "type": "rpm", "epoch": 0}],
            "date_submitted": "2025-01-01 10:00:00",
            "date_stable": "2025-01-05 12:00:00",
        }

    def test_can_update_incrementally_no_last_updated(self, parser):
        """Cannot update incrementally without a last_updated timestamp."""
        assert parser._can_update_incrementally(None) is False

    def test_can_update_incrementally_no_existing_files(self, parser):
        """Cannot update incrementally without existing input files."""
        ts = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        assert parser._can_update_incrementally(ts) is False

    def test_can_update_incrementally_with_data(self, parser):
        """Can update incrementally when both timestamp and input files exist."""
        self._write_page(parser, [self._make_update()])
        ts = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        assert parser._can_update_incrementally(ts) is True

    def test_load_all_updates_deduplicates_by_alias(self, parser):
        """Incremental file should override full-sync data for the same alias."""
        original = self._make_update(alias="FEDORA-2025-aaa", severity="medium")
        self._write_page(parser, [original])

        # Write incremental file with updated severity for the same alias
        modified = self._make_update(alias="FEDORA-2025-aaa", severity="critical")
        incremental_path = os.path.join(parser.workspace.input_path, _INCREMENTAL_FILE)
        with open(incremental_path, "wb") as f:
            f.write(orjson.dumps([modified]))

        updates = parser._load_all_updates()
        assert len(updates) == 1
        assert updates[0]["severity"] == "critical"

    def test_load_all_updates_merges_new_and_old(self, parser):
        """Incremental file adds new updates alongside full-sync data."""
        original = self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001")
        self._write_page(parser, [original])

        new_update = self._make_update(alias="FEDORA-2025-bbb", cve="CVE-2025-0002")
        incremental_path = os.path.join(parser.workspace.input_path, _INCREMENTAL_FILE)
        with open(incremental_path, "wb") as f:
            f.write(orjson.dumps([new_update]))

        updates = parser._load_all_updates()
        aliases = {u["alias"] for u in updates}
        assert aliases == {"FEDORA-2025-aaa", "FEDORA-2025-bbb"}

    def test_full_download_cleans_incremental_file(self, parser, monkeypatch):
        """Full sync should remove the incremental overlay file."""
        # Create an incremental file
        incremental_path = os.path.join(parser.workspace.input_path, _INCREMENTAL_FILE)
        with open(incremental_path, "wb") as f:
            f.write(orjson.dumps([self._make_update()]))

        assert os.path.exists(incremental_path)

        # Mock _fetch_page to return empty results (simulating end of pagination)
        monkeypatch.setattr(parser, "_fetch_page", lambda *a, **kw: {"updates": [], "pages": 1})

        parser._download()

        assert not os.path.exists(incremental_path)

    def test_get_uses_incremental_path(self, parser, monkeypatch):
        """When skip_if_exists=True and last_updated is set, get() should use incremental download."""
        original = self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001")
        self._write_page(parser, [original])

        download_updates_called = []

        def mock_download_updates(last_updated):
            download_updates_called.append(last_updated)

        monkeypatch.setattr(parser, "_download_updates", mock_download_updates)

        ts = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
        # consume the generator
        list(parser.get(last_updated=ts, skip_if_exists=True))

        assert len(download_updates_called) == 1
        assert download_updates_called[0] == ts

    def test_get_uses_full_sync_without_last_updated(self, parser, monkeypatch):
        """When last_updated is None, get() should do a full sync."""
        download_called = []

        def mock_download():
            download_called.append(True)
            return []

        monkeypatch.setattr(parser, "_download", mock_download)

        list(parser.get(last_updated=None, skip_if_exists=True))

        assert len(download_called) == 1

    def test_incremental_produces_correct_results(self, parser):
        """End-to-end: incremental overlay should affect the final vulnerability output."""
        # Original data: severity medium
        original = self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001", severity="medium")
        self._write_page(parser, [original])

        # Incremental: same advisory updated to critical severity
        modified = self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001", severity="critical")
        incremental_path = os.path.join(parser.workspace.input_path, _INCREMENTAL_FILE)
        with open(incremental_path, "wb") as f:
            f.write(orjson.dumps([modified]))

        # Use skip_download to process existing data
        parser.config.runtime.skip_download = True
        results = list(parser.get())

        assert len(results) == 1
        vuln_id, record = results[0]
        assert vuln_id == "fedora:40/CVE-2025-0001"
        assert record["Vulnerability"]["Severity"] == "Critical"
