"""Tests for RapidFort parser: schema compliance, release-stream channels, and multi-range CVE handling."""

from __future__ import annotations

import pytest
from vunnel import result, workspace
from vunnel.providers.rapidfort.parser import Parser, _channel_for, _events_to_range_pairs


class TestEventsToRangePairs:
    """Tests for _events_to_range_pairs helper."""

    def test_single_event(self):
        events = [{"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.1"}]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 1
        assert pairs[0] == (">= 7.68.0, < 7.68.0-1ubuntu2.1", "7.68.0-1ubuntu2.1")

    def test_multi_range_cve_2022_22576(self):
        """CVE-2022-22576 has two events (two branches: 7.68.0 and 7.81.0)."""
        events = [
            {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10"},
            {"introduced": "7.81.0", "fixed": "7.81.0-1ubuntu1.1"},
        ]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 2
        assert pairs[0] == (">= 7.68.0, < 7.68.0-1ubuntu2.10", "7.68.0-1ubuntu2.10")
        assert pairs[1] == (">= 7.81.0, < 7.81.0-1ubuntu1.1", "7.81.0-1ubuntu1.1")

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
        assert pairs[0] == (">= 7.68.0", "None")

    def test_fixed_only(self):
        events = [{"fixed": "7.68.0-1ubuntu2.1"}]
        pairs = _events_to_range_pairs(events)
        assert len(pairs) == 1
        assert pairs[0] == ("< 7.68.0-1ubuntu2.1", "7.68.0-1ubuntu2.1")


class TestChannelFor:
    """Tests for _channel_for: mapping release-stream identifiers to namespace channels."""

    def test_no_identifier_is_native(self):
        assert _channel_for("alpine", "3.20", None) is None
        assert _channel_for("debian", "12", None) is None
        assert _channel_for("ubuntu", "20.04", None) is None

    def test_redhat_native_el_stream_folds_to_channel_less(self):
        assert _channel_for("redhat", "9", "el9") is None

    def test_redhat_foreign_streams_become_channels(self):
        assert _channel_for("redhat", "9", "fc43") == "fc43"
        assert _channel_for("redhat", "9", "rf") == "rf"

    def test_ubuntu_native_stream_folds_to_channel_less(self):
        assert _channel_for("ubuntu", "20.04", "ubuntu") is None

    def test_ubuntu_rf_stream_becomes_channel(self):
        assert _channel_for("ubuntu", "20.04", "rf") == "rf"

    def test_debian_native_stream_folds_to_channel_less(self):
        # a debian-identified event in the debian tree is a stock debian build, i.e. the native
        # stream -- exactly as "ubuntu" is for ubuntu. Passing it through instead would mint a
        # channel named after the base distro, which no client routes to, leaving every record
        # in it unreachable.
        assert _channel_for("debian", "12", "debian") is None

    def test_debian_rf_stream_becomes_channel(self):
        assert _channel_for("debian", "12", "rf") == "rf"

    def test_native_fold_is_scoped_to_the_matching_distro(self):
        # the fold keys off the distro's own name, so a foreign distro's name stays a channel
        assert _channel_for("debian", "12", "ubuntu") == "ubuntu"
        assert _channel_for("ubuntu", "20.04", "debian") == "debian"

    def test_channels_are_lowercased(self):
        assert _channel_for("redhat", "9", "FC43") == "fc43"


class TestNormalize:
    """Tests for _normalize: namespace-keyed output with per-stream channels."""

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
            by_namespace = parser._normalize("ubuntu", "20.04", "curl", cve_map)

        assert list(by_namespace) == ["rapidfort-ubuntu:20.04"]
        vuln_dict = by_namespace["rapidfort-ubuntu:20.04"]

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
            by_namespace = parser._normalize("ubuntu", "20.04", "curl", cve_map)

        record = by_namespace["rapidfort-ubuntu:20.04"]["CVE-2020-8169"]
        fixed_in = record["Vulnerability"]["FixedIn"]
        assert len(fixed_in) == 1
        assert "Available" in fixed_in[0], "Must use 'Available' to match grype OSFixedIn struct"
        assert fixed_in[0]["Available"]["Date"] == "2024-01-01"
        assert fixed_in[0]["Available"]["Kind"] == "first-observed"

    def test_redhat_streams_split_into_channel_namespaces(
        self, tmpdir, auto_fake_fixdate_finder
    ):
        """The native el stream folds channel-less; each foreign stream gets its own +channel namespace."""
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
                    {"introduced": "0", "fixed": "0:7.88.0-1.rf", "identifier": "rf"},
                ],
            },
        }

        with parser:
            by_namespace = parser._normalize("redhat", "9", "curl", cve_map)

        assert sorted(by_namespace) == [
            "rapidfort-redhat:9",
            "rapidfort-redhat:9+fc36",
            "rapidfort-redhat:9+fc37",
            "rapidfort-redhat:9+rf",
        ]

        # the native el9 event (no fix) lands in the channel-less namespace
        native = by_namespace["rapidfort-redhat:9"]["CVE-2014-0139"]
        assert native["Vulnerability"]["NamespaceName"] == "rapidfort-redhat:9"
        native_fixed_in = native["Vulnerability"]["FixedIn"]
        assert len(native_fixed_in) == 1
        assert native_fixed_in[0]["NamespaceName"] == "rapidfort-redhat:9"
        assert native_fixed_in[0]["VersionFormat"] == "rpm"
        assert native_fixed_in[0]["Version"] == "None"
        assert native_fixed_in[0]["VulnerableRange"] == ">= 0"
        assert "Identifier" not in native_fixed_in[0]
        assert native_fixed_in[0]["VendorAdvisory"]["AdvisorySummary"] == [
            {
                "ID": "curl",
                "Link": "https://github.com/rapidfort/security-advisories/tree/main/OS/redhat/curl.json",
            },
        ]

        # each fedora stream lands in its own channel namespace
        fc36 = by_namespace["rapidfort-redhat:9+fc36"]["CVE-2014-0139"]
        assert fc36["Vulnerability"]["NamespaceName"] == "rapidfort-redhat:9+fc36"
        fc36_fixed_in = fc36["Vulnerability"]["FixedIn"]
        assert len(fc36_fixed_in) == 1
        assert fc36_fixed_in[0]["NamespaceName"] == "rapidfort-redhat:9+fc36"
        assert fc36_fixed_in[0]["Version"] == "7.78.0-4.fc36"
        assert fc36_fixed_in[0]["VulnerableRange"] == ">= 0, < 7.78.0-4.fc36"
        assert "Identifier" not in fc36_fixed_in[0]

        # the rapidfort rebuild stream lands in +rf
        rf = by_namespace["rapidfort-redhat:9+rf"]["CVE-2014-0139"]
        rf_fixed_in = rf["Vulnerability"]["FixedIn"]
        assert len(rf_fixed_in) == 1
        assert rf_fixed_in[0]["Version"] == "0:7.88.0-1.rf"

    def test_redhat_cross_release_events_are_dropped(
        self, tmpdir, auto_fake_fixdate_finder, caplog
    ):
        """An el8-identified event under the redhat 9 key belongs to no reachable stream and is dropped."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2014-0139": {
                "cve_id": "CVE-2014-0139",
                "severity": "LOW",
                "events": [
                    {"introduced": "0", "fixed": "7.61.1-34.el8", "identifier": "el8"},
                    {"introduced": "0", "fixed": "7.76.1-19.el9_2", "identifier": "el9"},
                ],
            },
        }

        with parser:
            by_namespace = parser._normalize("redhat", "9", "curl", cve_map)

        assert sorted(by_namespace) == ["rapidfort-redhat:9"]
        fixed_in = by_namespace["rapidfort-redhat:9"]["CVE-2014-0139"]["Vulnerability"]["FixedIn"]
        assert len(fixed_in) == 1
        assert fixed_in[0]["Version"] == "7.76.1-19.el9_2"

    def test_ubuntu_native_streams_fold_together(
        self, tmpdir, auto_fake_fixdate_finder
    ):
        """ubuntu-identified and rf-identified events split; unidentified events are native."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2022-22576": {
                "cve_id": "CVE-2022-22576",
                "severity": "HIGH",
                "events": [
                    {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10", "identifier": "ubuntu"},
                    {"introduced": "7.68.0", "fixed": "7.68.0-1rfubu.1", "identifier": "rf"},
                ],
            },
        }

        with parser:
            by_namespace = parser._normalize("ubuntu", "20.04", "curl", cve_map)

        assert sorted(by_namespace) == ["rapidfort-ubuntu:20.04", "rapidfort-ubuntu:20.04+rf"]
        native = by_namespace["rapidfort-ubuntu:20.04"]["CVE-2022-22576"]["Vulnerability"]["FixedIn"]
        assert [f["Version"] for f in native] == ["7.68.0-1ubuntu2.10"]
        rf = by_namespace["rapidfort-ubuntu:20.04+rf"]["CVE-2022-22576"]["Vulnerability"]["FixedIn"]
        assert [f["Version"] for f in rf] == ["7.68.0-1rfubu.1"]

    def test_ubuntu_fold_safety_guard(
        self, tmpdir, auto_fake_fixdate_finder, caplog
    ):
        """Both ubuntu-identified AND unidentified events for one CVE+package: keep only the
        ubuntu-identified events (never OR-merge two streams into one namespace) and warn."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        parser = Parser(workspace=ws)

        cve_map = {
            "CVE-2022-22576": {
                "cve_id": "CVE-2022-22576",
                "severity": "HIGH",
                "events": [
                    {"introduced": "7.68.0", "fixed": "7.68.0-1ubuntu2.10", "identifier": "ubuntu"},
                    {"introduced": "7.68.0", "fixed": "7.68.1-1"},
                ],
            },
        }

        with parser:
            by_namespace = parser._normalize("ubuntu", "20.04", "curl", cve_map)

        fixed_in = by_namespace["rapidfort-ubuntu:20.04"]["CVE-2022-22576"]["Vulnerability"]["FixedIn"]
        assert [f["Version"] for f in fixed_in] == ["7.68.0-1ubuntu2.10"]


class TestNormalizeOSVersion:
    """Tests for _normalize_os_version: version-key normalization."""

    @pytest.fixture()
    def parser(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        return Parser(workspace=ws)

    def test_numeric_versions_pass_through(self, parser):
        assert parser._normalize_os_version("redhat", "9") == "9"
        assert parser._normalize_os_version("ubuntu", "20.04") == "20.04"

    def test_el_prefixed_redhat_key_is_normalized(self, parser):
        assert parser._normalize_os_version("redhat", "el4") == "4"

    def test_unusable_keys_are_skipped(self, parser):
        assert parser._normalize_os_version("redhat", "elX") is None
        assert parser._normalize_os_version("ubuntu", "") is None
        assert parser._normalize_os_version("ubuntu", "unknown") is None


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
    """Snapshot test for multi-range CVE and release-stream channel regression."""
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
            curl_vulns = parser._normalize("ubuntu", "20.04", "curl", cve_map)[ns]
            libcurl_vulns = parser._normalize("ubuntu", "20.04", "libcurl4", cve_map)[ns]

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
            vulns_a = parser._normalize("ubuntu", "20.04", "curl", cve_map_a)[ns]
            vulns_b = parser._normalize("ubuntu", "20.04", "curl", cve_map_b)[ns]

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
