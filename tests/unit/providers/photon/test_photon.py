from __future__ import annotations

import os

import pytest
from vunnel import result, workspace
from vunnel.providers.photon import Config, Provider
from vunnel.providers.photon.parser import (
    AdvisoryInfo,
    Parser,
    _parse_advisory_file,
    cvss_to_severity,
    parse_advisories,
    parse_fixed_version,
)


class TestCvssToSeverity:
    def test_none_score(self):
        assert cvss_to_severity(None) == "Unknown"

    def test_critical(self):
        assert cvss_to_severity(9.0) == "Critical"
        assert cvss_to_severity(10.0) == "Critical"

    def test_high(self):
        assert cvss_to_severity(7.0) == "High"
        assert cvss_to_severity(8.9) == "High"

    def test_medium(self):
        assert cvss_to_severity(4.0) == "Medium"
        assert cvss_to_severity(6.9) == "Medium"

    def test_low(self):
        assert cvss_to_severity(0.1) == "Low"
        assert cvss_to_severity(3.9) == "Low"

    def test_negligible(self):
        assert cvss_to_severity(0.0) == "Negligible"


class TestParseFixedVersion:
    def test_na(self):
        assert parse_fixed_version("NA") == "None"

    def test_empty(self):
        assert parse_fixed_version("") == "None"

    def test_valid_version(self):
        assert parse_fixed_version("7.88.1-4.ph4") == "7.88.1-4.ph4"


class TestParseAdvisoryFile:
    def test_parse_security_update_file(self, helpers):
        fixture_path = helpers.local_dir("test-fixtures/input/photon.wiki/Security-Update-4.0-500.md")
        result = _parse_advisory_file(fixture_path)
        assert result is not None
        advisory_id, date, version, cve_ids = result
        assert advisory_id == "PHSA-2023-4.0-0500"
        assert date == "2023-10-11"
        assert version == "4.0"
        assert cve_ids == {"CVE-2023-38545", "CVE-2023-38546"}

    def test_parse_non_advisory_file(self, tmp_path):
        f = tmp_path / "Home.md"
        f.write_text("# Home\nSome content\n")
        assert _parse_advisory_file(str(f)) is None

    def test_parse_file_missing_advisory_id(self, tmp_path):
        f = tmp_path / "Security-Update-4.0-999.md"
        f.write_text("# No advisory id here\nIssue date      : 2023-01-01\nCVE-2023-12345\n")
        assert _parse_advisory_file(str(f)) is None

    def test_parse_file_missing_date(self, tmp_path):
        f = tmp_path / "Security-Update-4.0-999.md"
        f.write_text("Advisory Id     : PHSA-2023-4.0-0999\nNo date\nCVE-2023-12345\n")
        assert _parse_advisory_file(str(f)) is None

    def test_parse_file_no_cves(self, tmp_path):
        f = tmp_path / "Security-Update-4.0-999.md"
        f.write_text("Advisory Id     : PHSA-2023-4.0-0999\nIssue date      : 2023-01-01\nNo CVEs here\n")
        assert _parse_advisory_file(str(f)) is None


class TestParseAdvisories:
    def test_parse_advisories_from_wiki(self, helpers):
        wiki_path = helpers.local_dir("test-fixtures/input/photon.wiki")
        advisory_map = parse_advisories(wiki_path)

        # CVE-2023-38545 and CVE-2023-38546 should map to PHSA-2023-4.0-0500
        assert ("4.0", "CVE-2023-38545") in advisory_map
        info = advisory_map[("4.0", "CVE-2023-38545")]
        assert info.advisory_id == "PHSA-2023-4.0-0500"
        assert info.date == "2023-10-11"
        assert info.url == "https://github.com/vmware/photon/wiki/Security-Update-4.0-500"

        assert ("4.0", "CVE-2023-38546") in advisory_map
        assert advisory_map[("4.0", "CVE-2023-38546")].advisory_id == "PHSA-2023-4.0-0500"

        # CVE-2023-44487 should map to PHSA-2023-4.0-0501
        assert ("4.0", "CVE-2023-44487") in advisory_map
        info = advisory_map[("4.0", "CVE-2023-44487")]
        assert info.advisory_id == "PHSA-2023-4.0-0501"
        assert info.date == "2023-10-15"

        # CVE-2023-50447 should NOT be in the map (no advisory for it)
        assert ("4.0", "CVE-2023-50447") not in advisory_map

    def test_parse_advisories_nonexistent_dir(self):
        assert parse_advisories("/nonexistent/path") == {}

    def test_earlier_advisory_wins(self, tmp_path):
        """When a CVE appears in multiple advisories, the earliest date wins."""
        f1 = tmp_path / "Security-Update-4.0-100.md"
        f1.write_text(
            "Advisory Id     : PHSA-2023-4.0-0100\n"
            "Issue date      : 2023-06-01\n"
            "CVE-2023-99999\n"
        )
        f2 = tmp_path / "Security-Update-4.0-200.md"
        f2.write_text(
            "Advisory Id     : PHSA-2023-4.0-0200\n"
            "Issue date      : 2023-03-01\n"
            "CVE-2023-99999\n"
        )
        advisory_map = parse_advisories(str(tmp_path))
        assert advisory_map[("4.0", "CVE-2023-99999")].advisory_id == "PHSA-2023-4.0-0200"
        assert advisory_map[("4.0", "CVE-2023-99999")].date == "2023-03-01"


class TestParser:
    def test_extract_version_from_filename(self, tmpdir):
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )
        assert p._extract_version_from_filename("/some/path/cve_data_photon4.0.json") == "4.0"
        assert p._extract_version_from_filename("/some/path/cve_data_photon3.0.json") == "3.0"
        assert p._extract_version_from_filename("/some/path/badname.json") == ""

    def test_parse_file(self, helpers, tmpdir):
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        fixture_path = helpers.local_dir("test-fixtures/input/cve_data_photon4.0.json")
        results = list(p._parse_file(fixture_path))

        # We expect 4 unique CVEs (CVE-2023-44487's "Not Affected" httpd entry is skipped)
        cve_ids = [r[1] for r in results]
        assert sorted(cve_ids) == sorted([
            "CVE-2023-38545",
            "CVE-2023-38546",
            "CVE-2023-44487",
            "CVE-2023-50447",
        ])

        # All results should be in the photon:4.0 namespace
        namespaces = {r[0] for r in results}
        assert namespaces == {"photon:4.0"}

        # Each result should have the Vulnerability wrapper
        for _ns, _cve_id, payload in results:
            assert "Vulnerability" in payload
            vuln = payload["Vulnerability"]
            assert "FixedIn" in vuln
            assert len(vuln["FixedIn"]) > 0

    def test_parse_file_with_advisories(self, helpers, tmpdir):
        """When advisory map is populated, FixedIn entries should have VendorAdvisory."""
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        wiki_path = helpers.local_dir("test-fixtures/input/photon.wiki")
        p._advisory_map = parse_advisories(wiki_path)

        fixture_path = helpers.local_dir("test-fixtures/input/cve_data_photon4.0.json")
        results = {r[1]: r[2] for r in p._parse_file(fixture_path)}

        # CVE-2023-38545 has an advisory
        vuln = results["CVE-2023-38545"]["Vulnerability"]
        fixed_in = vuln["FixedIn"][0]
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False
        assert len(fixed_in["VendorAdvisory"]["AdvisorySummary"]) == 1
        assert fixed_in["VendorAdvisory"]["AdvisorySummary"][0]["ID"] == "PHSA-2023-4.0-0500"
        assert fixed_in["VendorAdvisory"]["AdvisorySummary"][0]["Link"] == "https://github.com/vmware/photon/wiki/Security-Update-4.0-500"

        # CVE-2023-50447 has no advisory - VendorAdvisory should be default (NoAdvisory=False, empty summary)
        vuln = results["CVE-2023-50447"]["Vulnerability"]
        fixed_in = vuln["FixedIn"][0]
        assert fixed_in["VendorAdvisory"]["NoAdvisory"] is False
        assert fixed_in["VendorAdvisory"]["AdvisorySummary"] == []

    def test_parse_file_multi_package_cve(self, helpers, tmpdir):
        """CVE-2023-38546 affects both curl and curl-libs -- they should be grouped."""
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        fixture_path = helpers.local_dir("test-fixtures/input/cve_data_photon4.0.json")
        results = {r[1]: r[2] for r in p._parse_file(fixture_path)}

        vuln = results["CVE-2023-38546"]["Vulnerability"]
        fixed_in_names = [f["Name"] for f in vuln["FixedIn"]]
        assert sorted(fixed_in_names) == ["curl", "curl-libs"]

    def test_parse_file_not_affected_skipped(self, helpers, tmpdir):
        """CVE-2023-44487 marks httpd as 'Not Affected' -- only nghttp2 should appear."""
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        fixture_path = helpers.local_dir("test-fixtures/input/cve_data_photon4.0.json")
        results = {r[1]: r[2] for r in p._parse_file(fixture_path)}

        vuln = results["CVE-2023-44487"]["Vulnerability"]
        fixed_in_names = [f["Name"] for f in vuln["FixedIn"]]
        assert fixed_in_names == ["nghttp2"]

    def test_parse_file_na_version(self, helpers, tmpdir):
        """CVE-2023-50447 has res_ver=NA -- Version should be 'None', no VulnerableRange."""
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        fixture_path = helpers.local_dir("test-fixtures/input/cve_data_photon4.0.json")
        results = {r[1]: r[2] for r in p._parse_file(fixture_path)}

        vuln = results["CVE-2023-50447"]["Vulnerability"]
        fixed_in = vuln["FixedIn"][0]
        assert fixed_in["Version"] == "None"
        assert fixed_in["VulnerableRange"] is None

    def test_parse_file_severity_mapping(self, helpers, tmpdir):
        """CVE-2023-38545 has score 9.8 -> Critical, CVE-2023-50447 has null -> Unknown."""
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        fixture_path = helpers.local_dir("test-fixtures/input/cve_data_photon4.0.json")
        results = {r[1]: r[2] for r in p._parse_file(fixture_path)}

        assert results["CVE-2023-38545"]["Vulnerability"]["Severity"] == "Critical"
        assert results["CVE-2023-38546"]["Vulnerability"]["Severity"] == "Low"
        assert results["CVE-2023-44487"]["Vulnerability"]["Severity"] == "High"
        assert results["CVE-2023-50447"]["Vulnerability"]["Severity"] == "Unknown"

    def test_patch_fix_date_uses_advisory(self, helpers, tmpdir):
        """Advisory dates should be preferred over first-observed dates."""
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            download_timeout=125,
            allow_versions=["4.0"],
            logger=__import__("logging").getLogger("test"),
        )

        wiki_path = helpers.local_dir("test-fixtures/input/photon.wiki")
        p._advisory_map = parse_advisories(wiki_path)

        record = {
            "Vulnerability": {
                "Name": "CVE-2023-38545",
                "FixedIn": [
                    {
                        "Name": "curl",
                        "NamespaceName": "photon:4.0",
                        "Version": "7.88.1-4.ph4",
                        "VendorAdvisory": {"NoAdvisory": False, "AdvisorySummary": []},
                    },
                ],
            },
        }

        patched = p._patch_fix_date(record)
        fixed_in = patched["Vulnerability"]["FixedIn"][0]
        assert fixed_in["Available"]["Date"] == "2023-10-11"
        assert fixed_in["Available"]["Kind"] == "advisory"


def test_provider_schema(helpers, disable_get_requests, auto_fake_fixdate_finder, monkeypatch):
    ws = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.allow_versions = ["4.0"]
    p = Provider(root=ws.root, config=c)

    # Monkeypatch _download to return paths to already-copied fixture files
    def mock_download(self_inner):
        # Parse advisories from the fixture wiki directory
        wiki_path = os.path.join(p.workspace.input_path, "photon.wiki")
        self_inner._advisory_map = parse_advisories(wiki_path)
        return [os.path.join(p.workspace.input_path, "cve_data_photon4.0.json")]

    monkeypatch.setattr(Parser, "_download", mock_download)

    p.update(None)

    assert ws.num_result_entries() == 4
    assert ws.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, auto_fake_fixdate_finder, monkeypatch):
    ws = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.allow_versions = ["4.0"]
    p = Provider(root=ws.root, config=c)

    def mock_download(self_inner):
        # Parse advisories from the fixture wiki directory
        wiki_path = os.path.join(p.workspace.input_path, "photon.wiki")
        self_inner._advisory_map = parse_advisories(wiki_path)
        return [os.path.join(p.workspace.input_path, "cve_data_photon4.0.json")]

    monkeypatch.setattr(Parser, "_download", mock_download)

    p.update(None)

    ws.assert_result_snapshots()
