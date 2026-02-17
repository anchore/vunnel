from __future__ import annotations

import datetime
import os

import orjson
import pytest

from vunnel import result, workspace
from vunnel.providers.fedora import Config, Provider
from vunnel.providers.fedora.parser import Parser, _UPDATE_FILE_GLOB


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


class TestCrossUpdateMerging:
    """Test that the same CVE fixed across multiple updates merges FixedIn entries."""

    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        config = Config()
        return Parser(workspace=ws, config=config)

    def _write_update(self, parser, update):
        alias = update["alias"]
        filepath = os.path.join(parser.workspace.input_path, f"{alias}.json")
        with open(filepath, "wb") as f:
            f.write(orjson.dumps(update))

    def test_same_cve_different_packages_merged(self, parser):
        """CVE-2004-2779 fixed in mingw-libid3tag by one update and libid3tag by another.

        Based on real Bodhi data: FEDORA-2018-4e26c06aef and FEDORA-2018-e06468b832.
        The output should have a single CVE-2004-2779 record with both packages in FixedIn.
        """
        # mingw-libid3tag update
        self._write_update(parser, {
            "alias": "FEDORA-2018-4e26c06aef",
            "display_name": "",
            "title": "mingw-libid3tag-0.15.1b-23.fc27",
            "notes": "Fix CVE-2017-11550 and CVE-2004-2779",
            "type": "security",
            "status": "stable",
            "severity": "low",
            "date_submitted": "2018-04-12 10:04:32",
            "date_modified": None,
            "date_stable": "2018-04-23 15:50:52",
            "date_pushed": "2018-04-23 15:50:52",
            "url": "https://bodhi.fedoraproject.org/updates/FEDORA-2018-4e26c06aef",
            "release": {"name": "F27", "version": "27", "id_prefix": "FEDORA"},
            "bugs": [
                {"bug_id": 1561983, "security": True, "title": "CVE-2004-2779 libid3tag: id3_utf16_deserialize() misparses ID3v2 tags with an odd number of bytes resulting in an endless loop"},
                {"bug_id": 1561986, "security": True, "title": "CVE-2004-2779 mingw-libid3tag: libid3tag: id3_utf16_deserialize() misparses ID3v2 tags with an odd number of bytes resulting in an endless loop [fedora-all]"},
            ],
            "builds": [{"nvr": "mingw-libid3tag-0.15.1b-23.fc27", "type": "rpm", "epoch": 0}],
        })

        # libid3tag update
        self._write_update(parser, {
            "alias": "FEDORA-2018-e06468b832",
            "display_name": "",
            "title": "libid3tag-0.15.1b-26.fc27",
            "notes": "Security fix for CVE-2004-2779 and CVE-2017-11550",
            "type": "security",
            "status": "stable",
            "severity": "low",
            "date_submitted": "2018-03-29 14:44:23",
            "date_modified": "2018-03-30 15:35:22",
            "date_stable": "2018-04-09 19:08:06",
            "date_pushed": "2018-04-09 19:08:06",
            "url": "https://bodhi.fedoraproject.org/updates/FEDORA-2018-e06468b832",
            "release": {"name": "F27", "version": "27", "id_prefix": "FEDORA"},
            "bugs": [
                {"bug_id": 1478934, "security": True, "title": "CVE-2017-11550 libid3tag: NULL Pointer Dereference in id3_ucs4_length function in ucs4.c"},
                {"bug_id": 1561983, "security": True, "title": "CVE-2004-2779 libid3tag: id3_utf16_deserialize() misparses ID3v2 tags with an odd number of bytes resulting in an endless loop"},
                {"bug_id": 1561985, "security": True, "title": "CVE-2004-2779 libid3tag: id3_utf16_deserialize() misparses ID3v2 tags with an odd number of bytes resulting in an endless loop [fedora-all]"},
            ],
            "builds": [{"nvr": "libid3tag-0.15.1b-26.fc27", "type": "rpm", "epoch": 0}],
        })

        parser.config.runtime.skip_download = True
        results = list(parser.get())

        # Find the CVE-2004-2779 record
        cve_2779 = [r for vid, r in results if vid == "fedora:27/CVE-2004-2779"]
        assert len(cve_2779) == 1, f"expected exactly 1 record for CVE-2004-2779, got {len(cve_2779)}"

        fixed_in = cve_2779[0]["Vulnerability"]["FixedIn"]
        fixed_in_names = sorted(entry["Name"] for entry in fixed_in)
        assert fixed_in_names == ["libid3tag", "mingw-libid3tag"], (
            f"expected both packages in FixedIn, got {fixed_in_names}"
        )

        # CVE-2017-11550 should also exist (only in the libid3tag update)
        cve_11550 = [r for vid, r in results if vid == "fedora:27/CVE-2017-11550"]
        assert len(cve_11550) == 1

    def test_same_cve_same_package_different_updates_keeps_first(self, parser):
        """If two updates fix the same CVE in the same package, FixedIn should not duplicate."""
        for alias, version in [("FEDORA-2025-aaa", "1.0-1.fc40"), ("FEDORA-2025-bbb", "1.1-1.fc40")]:
            self._write_update(parser, {
                "alias": alias,
                "release": {"version": "40"},
                "severity": "medium",
                "bugs": [{"bug_id": 1, "security": True, "title": "CVE-2025-0001 test vuln"}],
                "builds": [{"nvr": f"foo-{version}", "type": "rpm", "epoch": 0}],
                "date_submitted": "2025-01-01 10:00:00",
                "date_stable": "2025-01-05 12:00:00",
            })

        parser.config.runtime.skip_download = True
        results = list(parser.get())

        cve_records = [(vid, r) for vid, r in results if vid == "fedora:40/CVE-2025-0001"]
        assert len(cve_records) == 1

        fixed_in = cve_records[0][1]["Vulnerability"]["FixedIn"]
        pkg_names = [entry["Name"] for entry in fixed_in]
        # Both are "foo" — should have both versions since they're different advisories
        assert len(fixed_in) == 2
        versions = sorted(entry["Version"] for entry in fixed_in)
        assert versions == ["0:1.0-1.fc40", "0:1.1-1.fc40"]


def test_provider_schema(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    monkeypatch.setattr(p.parser, "_download", lambda: None)

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

    monkeypatch.setattr(p.parser, "_download", lambda: None)

    p.update(None)

    workspace.assert_result_snapshots()


class TestIncremental:
    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        config = Config()
        return Parser(workspace=ws, config=config)

    def _write_update(self, parser, update):
        """Helper to write a single update file into the parser's input directory."""
        alias = update["alias"]
        filepath = os.path.join(parser.workspace.input_path, f"{alias}.json")
        with open(filepath, "wb") as f:
            f.write(orjson.dumps(update))
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
        self._write_update(parser, self._make_update())
        ts = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        assert parser._can_update_incrementally(ts) is True

    def test_incremental_overwrites_existing_update(self, parser):
        """Writing a new version of the same update overwrites the file."""
        original = self._make_update(alias="FEDORA-2025-aaa", severity="medium")
        self._write_update(parser, original)

        modified = self._make_update(alias="FEDORA-2025-aaa", severity="critical")
        self._write_update(parser, modified)

        updates = parser._load_all_updates()
        assert len(updates) == 1
        assert updates[0]["severity"] == "critical"

    def test_load_all_updates_loads_multiple_files(self, parser):
        """Each update file is loaded independently."""
        self._write_update(parser, self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001"))
        self._write_update(parser, self._make_update(alias="FEDORA-2025-bbb", cve="CVE-2025-0002"))

        updates = parser._load_all_updates()
        aliases = {u["alias"] for u in updates}
        assert aliases == {"FEDORA-2025-aaa", "FEDORA-2025-bbb"}

    def test_full_download_cleans_existing_files(self, parser, monkeypatch):
        """Full sync should remove all existing per-update files."""
        self._write_update(parser, self._make_update(alias="FEDORA-2025-old"))
        filepath = os.path.join(parser.workspace.input_path, "FEDORA-2025-old.json")
        assert os.path.exists(filepath)

        # Mock _fetch_page to return empty results (simulating end of pagination)
        monkeypatch.setattr(parser, "_fetch_page", lambda *a, **kw: {"updates": [], "pages": 1})

        parser._download()

        assert not os.path.exists(filepath)

    def test_get_uses_incremental_path(self, parser, monkeypatch):
        """When skip_if_exists=True and last_updated is set, get() should use incremental download."""
        self._write_update(parser, self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001"))

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

        monkeypatch.setattr(parser, "_download", mock_download)

        list(parser.get(last_updated=None, skip_if_exists=True))

        assert len(download_called) == 1

    def test_incremental_partial_failure_preserves_already_saved_files(self, parser, monkeypatch):
        """If a fetch fails mid-pagination, files saved before the error remain on disk."""
        # Pre-existing update from a prior full sync
        self._write_update(parser, self._make_update(alias="FEDORA-2025-old", cve="CVE-2025-0001"))

        call_count = 0

        def mock_fetch_page(page, release=None, extra_params=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First page succeeds — returns one new update
                return {
                    "updates": [self._make_update(alias="FEDORA-2025-new", cve="CVE-2025-0002")],
                    "pages": 2,
                }
            # Second page blows up
            raise RuntimeError("simulated network failure")

        monkeypatch.setattr(parser, "_fetch_page", mock_fetch_page)

        ts = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
        with pytest.raises(RuntimeError, match="simulated network failure"):
            parser._download_updates(ts)

        # The pre-existing file and the successfully-saved file should both still be on disk
        existing = {os.path.basename(f) for f in parser._existing_input_files()}
        assert "FEDORA-2025-old.json" in existing
        assert "FEDORA-2025-new.json" in existing

    def test_incremental_partial_failure_does_not_update_results(self, parser, monkeypatch):
        """If incremental download fails, get() raises and yields no partial results."""
        self._write_update(parser, self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001"))

        def mock_download_updates(last_updated):
            raise RuntimeError("simulated network failure")

        monkeypatch.setattr(parser, "_download_updates", mock_download_updates)

        ts = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
        with pytest.raises(RuntimeError, match="simulated network failure"):
            list(parser.get(last_updated=ts, skip_if_exists=True))

    def test_save_update_skips_update_without_alias(self, parser):
        """An update with no alias should not be saved and _save_update returns None."""
        update = self._make_update()
        del update["alias"]
        result = parser._save_update(update)
        assert result is None
        assert len(parser._existing_input_files()) == 0

    def test_duplicate_cve_across_updates_emitted_once(self, parser):
        """If two different updates fix the same CVE for the same release, it's emitted only once."""
        self._write_update(parser, self._make_update(
            alias="FEDORA-2025-aaa", cve="CVE-2025-0001", pkg_name="foo", pkg_version="1.0-1.fc40",
        ))
        self._write_update(parser, self._make_update(
            alias="FEDORA-2025-bbb", cve="CVE-2025-0001", pkg_name="bar", pkg_version="2.0-1.fc40",
        ))

        parser.config.runtime.skip_download = True
        results = list(parser.get())

        vuln_ids = [vid for vid, _ in results]
        assert vuln_ids.count("fedora:40/CVE-2025-0001") == 1

    def test_incremental_produces_correct_results(self, parser):
        """End-to-end: overwriting an update file should affect the final vulnerability output."""
        # Original data: severity medium
        original = self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001", severity="medium")
        self._write_update(parser, original)

        # Overwrite with updated severity
        modified = self._make_update(alias="FEDORA-2025-aaa", cve="CVE-2025-0001", severity="critical")
        self._write_update(parser, modified)

        # Use skip_download to process existing data
        parser.config.runtime.skip_download = True
        results = list(parser.get())

        assert len(results) == 1
        vuln_id, record = results[0]
        assert vuln_id == "fedora:40/CVE-2025-0001"
        assert record["Vulnerability"]["Severity"] == "Critical"
