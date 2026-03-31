"""Tests for RapidFort parser: schema compliance and multi-range CVE handling."""

from __future__ import annotations

import pytest
from vunnel import result, workspace
from vunnel.providers.rapidfort.parser import Parser, _events_to_range_pairs


class TestEventsToRangePairs:
    """Tests for _events_to_range_pairs helper."""

    def test_single_event(self):
        events = [{"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.1"}]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 1
        assert pairs[0] == (">= 7.68.0, < 7.68.0-1ubuntu2.1", "7.68.0-1ubuntu2.1", None)

    def test_multi_range_cve_2022_22576(self):
        """CVE-2022-22576 has two events (two branches: 7.68.0 and 7.81.0)."""
        events = [
            {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10"},
            {"introduced": "7.81.0", "fixed": "7.81.0-1ubuntu1.1"},
        ]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 2
        assert pairs[0] == (">= 7.68.0, < 7.68.0-1ubuntu2.10", "7.68.0-1ubuntu2.10", None)
        assert pairs[1] == (">= 7.81.0, < 7.81.0-1ubuntu1.1", "7.81.0-1ubuntu1.1", None)

    def test_deduplication(self):
        """Duplicate events should be deduplicated."""
        events = [
            {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10"},
            {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10"},
        ]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 1

    def test_introduced_only(self):
        events = [{"introduced": "7.68.0"}]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 1
        assert pairs[0] == (">= 7.68.0", "None", None)

    def test_fixed_only(self):
        events = [{"fixed": "7.68.0-1ubuntu2.1"}]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 1
        assert pairs[0] == ("< 7.68.0-1ubuntu2.1", "7.68.0-1ubuntu2.1", None)

    def test_identifier_is_preserved_and_part_of_dedup_key(self):
        events = [
            {"introduced": "0", "fixed": "7.78.0-4.fc36", "identifier": "fc36"},
            {"introduced": "0", "fixed": "7.81.0-3.fc37", "identifier": "fc37"},
            {"introduced": "0", "fixed": "7.78.0-4.fc36", "identifier": "fc36"},
        ]
        pairs = _events_to_range_pairs(events)
        assert pairs == [
            (">= 0, < 7.78.0-4.fc36", "7.78.0-4.fc36", "fc36"),
            (">= 0, < 7.81.0-3.fc37", "7.81.0-3.fc37", "fc37"),
        ]


class TestNormalize:
    """Tests for _normalize with multi-range CVEs."""

    def test_multi_range_cve_produces_two_fixed_in_entries(
        self, tmpdir, auto_fake_fixdate_finder
    ):
        """CVE-2022-22576 must produce exactly 2 FixedIn entries with correct ranges."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2022-22576": {
                "cve_id": "CVE-2022-22576",
                "description": "Test description",
                "severity": "HIGH",
                "events": [
                    {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10"},
                    {"introduced": "7.81.0", "fixed": "7.81.0-1ubuntu1.1"},
                ],
            },
        }

        with parser:
            vuln_dict = parser._normalize("ubuntu", "20.04", "curl", cve_map)

        assert "CVE-2022-22576" in vuln_dict
        record = vuln_dict["CVE-2022-22576"]
        fixed_in = record["Vulnerability"]["FixedIn"]

        assert len(fixed_in) == 2, "Multi-range CVE must produce 2 FixedIn entries"

        fixed_in_sorted = sorted(fixed_in, key=lambda x: x["Version"])
        assert fixed_in_sorted[0]["Version"] == "7.68.0-1ubuntu2.10"
        assert fixed_in_sorted[0]["VulnerableRange"] == ">= 7.68.0, < 7.68.0-1ubuntu2.10", (
            fixed_in_sorted[0]["VulnerableRange"]
        )
        assert fixed_in_sorted[0]["VendorAdvisory"]["AdvisorySummary"] == [
            {
                "ID": "curl",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/ubuntu/curl.json",
            },
        ]
        assert fixed_in_sorted[1]["Version"] == "7.81.0-1ubuntu1.1"
        assert fixed_in_sorted[1]["VulnerableRange"] == ">= 7.81.0, < 7.81.0-1ubuntu1.1", (
            fixed_in_sorted[1]["VulnerableRange"]
        )

    def test_fix_availability_field_present(
        self, tmpdir, auto_fake_fixdate_finder
    ):
        """Output must include 'Available' field (matching grype OSFixedIn struct and all other providers)."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2020-8169": {
                "cve_id": "CVE-2020-8169",
                "description": "Test description",
                "severity": "HIGH",
                "events": [{"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.1"}],
            },
        }

        with parser:
            vuln_dict = parser._normalize("ubuntu", "20.04", "curl", cve_map)

        record = vuln_dict["CVE-2020-8169"]
        fixed_in = record["Vulnerability"]["FixedIn"]
        assert len(fixed_in) == 1
        assert "Available" in fixed_in[0], "Must use 'Available' to match grype OSFixedIn struct"
        assert fixed_in[0]["Available"]["Date"] == "2024-01-01"
        assert fixed_in[0]["Available"]["Kind"] == "first-observed"

    def test_redhat_events_keep_outer_os_version_and_per_range_identifier(
        self, tmpdir, auto_fake_fixdate_finder
    ):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2014-0139": {
                "cve_id": "CVE-2014-0139",
                "description": "Test description",
                "severity": "LOW",
                "events": [
                    {"introduced": "0", "identifier": "el9"},
                    {"introduced": "0", "fixed": "7.78.0-4.fc36", "identifier": "fc36"},
                    {"introduced": "0", "fixed": "7.81.0-3.fc37", "identifier": "fc37"},
                ],
            },
        }

        with parser:
            vuln_dict = parser._normalize("redhat", "9", "curl", cve_map)

        record = vuln_dict["CVE-2014-0139"]
        assert record["Vulnerability"]["NamespaceName"] == "rapidfort-redhat:9"

        fixed_in = sorted(
            record["Vulnerability"]["FixedIn"],
            key=lambda x: (x["Identifier"], x["Version"]),
        )

        assert len(fixed_in) == 3
        assert fixed_in[0]["Identifier"] == "el9"
        assert fixed_in[0]["NamespaceName"] == "rapidfort-redhat:9"
        assert fixed_in[0]["VersionFormat"] == "rpm"
        assert fixed_in[0]["Version"] == "None"
        assert fixed_in[0]["VulnerableRange"] == ">= 0"
        assert fixed_in[0]["VendorAdvisory"]["AdvisorySummary"] == [
            {
                "ID": "curl",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
            {
                "ID": "release-identifier:el9",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
        ]
        assert fixed_in[1]["Identifier"] == "fc36"
        assert fixed_in[1]["Version"] == "7.78.0-4.fc36"
        assert fixed_in[1]["VulnerableRange"] == ">= 0, < 7.78.0-4.fc36"
        assert fixed_in[1]["VendorAdvisory"]["AdvisorySummary"] == [
            {
                "ID": "curl",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
            {
                "ID": "release-identifier:fc36",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
        ]
        assert fixed_in[2]["Identifier"] == "fc37"
        assert fixed_in[2]["Version"] == "7.81.0-3.fc37"
        assert fixed_in[2]["VulnerableRange"] == ">= 0, < 7.81.0-3.fc37"
        assert fixed_in[2]["VendorAdvisory"]["AdvisorySummary"] == [
            {
                "ID": "curl",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
            {
                "ID": "release-identifier:fc37",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
        ]


def test_provider_schema(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    """Provider output must validate against schema-1.1.0.json."""
    ws = helpers.provider_workspace_helper(
        name="rapidfort",
        input_fixture="test-fixtures/input",
    )

    from vunnel.providers.rapidfort import Config, Provider

    # Patch git operations so we use pre-populated fixtures instead of cloning
    def noop(*args, **kwargs):
        pass

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=str(ws.root), config=c)
    monkeypatch.setattr(p.parser.git_wrapper, "delete_repo", noop)
    monkeypatch.setattr(p.parser.git_wrapper, "clone_repo", noop)

    p.update(None)

    assert ws.num_result_entries() >= 2
    assert ws.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    """Snapshot test for multi-range CVE regression."""
    ws = helpers.provider_workspace_helper(
        name="rapidfort",
        input_fixture="test-fixtures/input",
    )

    from vunnel.providers.rapidfort import Config, Provider

    def noop(*args, **kwargs):
        pass

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=str(ws.root), config=c)
    monkeypatch.setattr(p.parser.git_wrapper, "delete_repo", noop)
    monkeypatch.setattr(p.parser.git_wrapper, "clone_repo", noop)

    p.update(None)

    ws.assert_result_snapshots()


class TestMergeIntoNamespace:
    """Tests for _merge_into_namespace: same CVE in multiple packages."""

    def test_same_cve_in_two_packages_merges_fixed_in(self, tmpdir, auto_fake_fixdate_finder):
        """Same CVE appearing in curl and libcurl4 must produce one record with two FixedIn entries."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2022-22576": {
                "cve_id": "CVE-2022-22576",
                "description": "Test",
                "severity": "HIGH",
                "events": [{"introduced": "1.0.0", "fixed": "1.0.1"}],
            },
        }

        ns = "rapidfort-ubuntu:20.04"
        namespace_vulns: dict = {}

        with parser:
            curl_vulns = parser._normalize("ubuntu", "20.04", "curl", cve_map)
            libcurl_vulns = parser._normalize("ubuntu", "20.04", "libcurl4", cve_map)

        parser._merge_into_namespace(namespace_vulns, ns, curl_vulns)
        parser._merge_into_namespace(namespace_vulns, ns, libcurl_vulns)

        assert len(namespace_vulns[ns]) == 1, "same CVE must produce one vuln record"
        fixed_in = namespace_vulns[ns]["CVE-2022-22576"]["Vulnerability"]["FixedIn"]
        assert len(fixed_in) == 2, "FixedIn must have one entry per package"
        package_names = {f["Name"] for f in fixed_in}
        assert package_names == {"curl", "libcurl4"}

    def test_distinct_cves_are_not_merged(self, tmpdir, auto_fake_fixdate_finder):
        """Different CVEs in the same package must remain as separate records."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map_a = {
            "CVE-2022-00001": {
                "cve_id": "CVE-2022-00001",
                "severity": "HIGH",
                "events": [{"introduced": "1.0.0", "fixed": "1.0.1"}],
            },
        }
        cve_map_b = {
            "CVE-2022-00002": {
                "cve_id": "CVE-2022-00002",
                "severity": "LOW",
                "events": [{"introduced": "2.0.0", "fixed": "2.0.1"}],
            },
        }

        ns = "rapidfort-ubuntu:20.04"
        namespace_vulns: dict = {}

        with parser:
            vulns_a = parser._normalize("ubuntu", "20.04", "curl", cve_map_a)
            vulns_b = parser._normalize("ubuntu", "20.04", "curl", cve_map_b)

        parser._merge_into_namespace(namespace_vulns, ns, vulns_a)
        parser._merge_into_namespace(namespace_vulns, ns, vulns_b)

        assert len(namespace_vulns[ns]) == 2, "distinct CVEs must remain as separate records"


class TestMapSeverity:
    """Tests for _map_severity helper."""

    def test_known_severities_case_insensitive(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        assert parser._map_severity("critical") == "Critical"
        assert parser._map_severity("HIGH") == "High"
        assert parser._map_severity("medium") == "Medium"
        assert parser._map_severity("Low") == "Low"
        assert parser._map_severity("NEGLIGIBLE") == "Negligible"

    def test_unknown_on_none(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        assert parser._map_severity(None) == "Unknown"

    def test_unknown_on_empty_string(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        assert parser._map_severity("") == "Unknown"

    def test_unknown_on_unrecognized_value(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        assert parser._map_severity("invalid") == "Unknown"
        assert parser._map_severity("NONE") == "Unknown"
