from __future__ import annotations

import pytest

from vunnel import result, workspace
from vunnel.providers.fedora import Config, Provider
from vunnel.providers.fedora.parser import Parser


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
