from __future__ import annotations

import json
import os
import shutil
from unittest.mock import MagicMock

import pytest

from vunnel import result
from vunnel.providers.chainguard import Config, Provider


# ---------------------------------------------------------------------------
# Helpers for mocking HTTP calls to the Chainguard OSV endpoint
# ---------------------------------------------------------------------------

def _osv_fixture_path(filename: str) -> str:
    here = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(here, "test-fixtures", "osv", filename)


def _make_osv_mock_http_get(
    fail_records: set[str] | None = None,
    malformed_records: set[str] | None = None,
    index_fail: bool = False,
    index_malformed: bool = False,
    index_not_list: bool = False,
    index_missing_id: bool = False,
    index_entry_not_dict: bool = False,
):
    """
    Returns a mock for vunnel.utils.http_wrapper.get that serves the OSV
    test fixtures from disk, keyed by URL substring.

    Args:
        fail_records: Set of record IDs that should raise RequestException
        malformed_records: Set of record IDs that should return invalid JSON
        index_fail: If True, raise RequestException when fetching the index
        index_malformed: If True, return invalid JSON for the index
        index_not_list: If True, return a dict instead of a list for the index
        index_missing_id: If True, return an index entry without "id" field
        index_entry_not_dict: If True, return an index with a non-dict entry
    """
    import requests

    fail_records = fail_records or set()
    malformed_records = malformed_records or set()

    fixture_map = {
        "all.json": "all.json",
        "CGA-224q-ccj5-2p53": "CGA-224q-ccj5-2p53.json",
        "CGA-22hv-wp9q-4779": "CGA-22hv-wp9q-4779.json",
        "CGA-xcpc-gm23-prj9": "CGA-xcpc-gm23-prj9.json",
    }

    def mock_get(url, *args, **kwargs):
        # Handle index-level failures
        if "all.json" in url:
            if index_fail:
                raise requests.RequestException("simulated network failure for index")
            if index_malformed:
                resp = MagicMock()
                resp.content = b"not valid json {"
                return resp
            if index_not_list:
                resp = MagicMock()
                resp.content = b'{"error": "this is not a list"}'
                return resp
            if index_missing_id:
                resp = MagicMock()
                resp.content = b'[{"modified": "2026-01-07T00:00:00Z"}]'
                return resp
            if index_entry_not_dict:
                resp = MagicMock()
                resp.content = b'["not-a-dict", 123, null]'
                return resp

        # Check if this is a record that should fail with network error
        for record_id in fail_records:
            if record_id in url:
                raise requests.RequestException(f"simulated network failure for {record_id}")

        # Check if this is a record that should return malformed JSON
        for record_id in malformed_records:
            if record_id in url:
                resp = MagicMock()
                resp.content = b"not valid json {"
                return resp

        for key, fixture_file in fixture_map.items():
            if key in url:
                resp = MagicMock()
                with open(_osv_fixture_path(fixture_file), "rb") as f:
                    resp.content = f.read()
                return resp
        raise RuntimeError(f"unexpected URL in test: {url}")

    return mock_get


@pytest.fixture
def osv_workspace(helpers):
    """Provides a workspace for OSV mode tests."""
    return helpers.provider_workspace_helper(name=Provider.name())


@pytest.fixture
def osv_provider(osv_workspace, monkeypatch):
    """
    Provides a fully configured OSV-mode provider with mocked HTTP.
    Returns (provider, workspace) tuple.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)
    return p, osv_workspace


def _find_record_by_id(workspace, record_id: str) -> dict | None:
    """Helper to find a specific record by ID from workspace results."""
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        if envelope["item"]["id"] == record_id:
            return envelope["item"]
    return None


# ---------------------------------------------------------------------------
# OSV mode tests (use_osv=True)
# ---------------------------------------------------------------------------

def test_provider_schema_osv(osv_provider):
    """
    Full provider integration test for OSV mode: mocks the HTTP calls to the
    Chainguard OSV endpoint and validates that all emitted records are valid
    against the OSV schema.
    """
    p, workspace = osv_provider
    p.update(None)

    # 3 CGA records in the index -> 3 result files
    assert workspace.num_result_entries() == 3
    assert workspace.result_schemas_valid(require_entries=True)


def test_osv_record_identifiers(osv_provider):
    """
    Verify that result files are keyed by CGA ID (lowercased) and that the
    emitted records carry the CGA ID as their primary identifier.
    """
    p, workspace = osv_provider
    p.update(None)

    ids_found = set()
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        ids_found.add(envelope["item"]["id"])

    assert "CGA-224q-ccj5-2p53" in ids_found
    assert "CGA-22hv-wp9q-4779" in ids_found
    assert "CGA-xcpc-gm23-prj9" in ids_found


def test_osv_upstream_ids_preserved(osv_provider):
    """
    OSV 1.7.0 introduces 'upstream' field for distro advisories to reference
    the original CVE/GHSA IDs.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    assert "upstream" in haproxy_record
    assert "CVE-2025-32464" in haproxy_record["upstream"]
    assert "GHSA-frg5-h47x-75j9" in haproxy_record["upstream"]


def test_osv_both_ecosystems_in_single_record(osv_provider):
    """
    A single CGA record covers both Chainguard and Wolfi packages.
    Verify that both ecosystems appear in the affected list of the
    emitted record so grype-db can route them to both distros.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    ecosystems = {a["package"]["ecosystem"] for a in haproxy_record["affected"]}
    assert "Chainguard" in ecosystems
    assert "Wolfi" in ecosystems

    # Specific packages
    names = {a["package"]["name"] for a in haproxy_record["affected"]}
    assert "haproxy-2.2" in names   # Chainguard-only package
    assert "haproxy-3.0" in names   # Wolfi package


def test_osv_per_package_fix_versions(osv_provider):
    """
    Each package in a CGA record can have a different fix version.
    Verify fix versions are preserved per package.
    """
    p, workspace = osv_provider
    p.update(None)

    langfuse_record = _find_record_by_id(workspace, "CGA-22hv-wp9q-4779")

    assert langfuse_record is not None
    by_name = {a["package"]["name"]: a for a in langfuse_record["affected"]}

    # langfuse-3-worker and langfuse-fips-3-worker have different fix versions
    assert "langfuse-3-worker" in by_name
    assert "langfuse-fips-3-worker" in by_name

    worker_events = by_name["langfuse-3-worker"]["ranges"][0]["events"]
    fips_events = by_name["langfuse-fips-3-worker"]["ranges"][0]["events"]

    worker_fixed = next(e["fixed"] for e in worker_events if "fixed" in e)
    fips_fixed = next(e["fixed"] for e in fips_events if "fixed" in e)

    assert worker_fixed == "3.153.0-r0"
    assert fips_fixed == "3.152.0-r0"


def test_osv_nak_entry(osv_provider):
    """
    A NAK entry (package explicitly not affected) is represented with
    fixed='0' in the OSV range events. Verify the record is emitted as-is
    so grype-db can detect the NAK constraint (< 0).
    """
    p, workspace = osv_provider
    p.update(None)

    syncthing_record = _find_record_by_id(workspace, "CGA-xcpc-gm23-prj9")

    assert syncthing_record is not None
    by_name = {a["package"]["name"]: a for a in syncthing_record["affected"]}

    # syncthing-compat is a NAK: fixed="0" means no version is vulnerable
    assert "syncthing-compat" in by_name
    nak_events = by_name["syncthing-compat"]["ranges"][0]["events"]
    fixed_events = [e for e in nak_events if "fixed" in e]
    assert len(fixed_events) == 1
    assert fixed_events[0]["fixed"] == "0"

    # syncthing itself has a real fix version
    assert "syncthing" in by_name
    syncthing_events = by_name["syncthing"]["ranges"][0]["events"]
    real_fixed = next(e["fixed"] for e in syncthing_events if "fixed" in e)
    assert real_fixed == "2.0.14-r1"


def test_osv_purl_with_arch_preserved(osv_provider):
    """
    PURL fields with architecture qualifiers must be preserved in the
    affected list. The enriched feed includes ?arch= qualifiers.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    by_name = {a["package"]["name"]: a for a in haproxy_record["affected"]}

    # Chainguard package with arch qualifier
    assert "?arch=x86_64" in by_name["haproxy-2.2"]["package"]["purl"]
    # Wolfi package with arch qualifier
    assert "?arch=aarch64" in by_name["haproxy-3.0"]["package"]["purl"]


def test_osv_purl_without_arch_preserved(osv_provider):
    """
    PURL fields without architecture qualifiers must also be preserved.
    Not all packages have arch-specific builds.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    by_name = {a["package"]["name"]: a for a in haproxy_record["affected"]}

    # haproxy-3.1 has no arch qualifier in the fixture
    assert "haproxy-3.1" in by_name
    purl = by_name["haproxy-3.1"]["package"]["purl"]
    assert purl == "pkg:apk/wolfi/haproxy-3.1"
    assert "?arch=" not in purl


def test_osv_summary_preserved(osv_provider):
    """
    The enriched OSV feed includes a one-line summary of the vulnerability.
    Verify this field is preserved.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    assert "summary" in haproxy_record
    assert "HAProxy" in haproxy_record["summary"]


def test_osv_severity_preserved(osv_provider):
    """
    The enriched OSV feed includes CVSS severity scores.
    Verify the severity array is preserved with proper structure.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    assert "severity" in haproxy_record
    assert len(haproxy_record["severity"]) >= 1

    severity = haproxy_record["severity"][0]
    assert severity["type"] == "CVSS_V3"
    assert severity["score"].startswith("CVSS:3.1/")


def test_osv_references_preserved(osv_provider):
    """
    The enriched OSV feed includes references to upstream advisories.
    Verify the references array is preserved.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None
    assert "references" in haproxy_record
    assert len(haproxy_record["references"]) >= 1

    # Check for NVD reference
    nvd_refs = [r for r in haproxy_record["references"] if "nvd.nist.gov" in r["url"]]
    assert len(nvd_refs) >= 1
    assert nvd_refs[0]["type"] == "ADVISORY"


def test_osv_ecosystem_specific_components_preserved(osv_provider):
    """
    The enriched OSV feed includes ecosystem_specific.components for
    per-component tracking. Verify the structure is preserved.
    """
    p, workspace = osv_provider
    p.update(None)

    haproxy_record = _find_record_by_id(workspace, "CGA-224q-ccj5-2p53")

    assert haproxy_record is not None

    # Find the affected entry with ecosystem_specific
    affected_with_components = [
        a for a in haproxy_record["affected"]
        if "ecosystem_specific" in a
    ]
    assert len(affected_with_components) >= 1

    eco_specific = affected_with_components[0]["ecosystem_specific"]
    assert "components" in eco_specific
    assert len(eco_specific["components"]) >= 1

    component = eco_specific["components"][0]
    # Verify all required component fields are present
    assert "advisory_id" in component
    assert component["advisory_id"].startswith("CGA-")
    assert "component_name" in component
    assert "component_version" in component
    assert "component_type" in component
    assert "component_location" in component
    assert "component_purl" in component
    assert "status" in component


def test_osv_component_types_preserved(osv_provider):
    """
    The enriched OSV feed supports multiple component types (apk, npm,
    go-module, java-archive, etc.). Verify different types are preserved.
    """
    p, workspace = osv_provider
    p.update(None)

    # Check npm component in langfuse record
    langfuse_record = _find_record_by_id(workspace, "CGA-22hv-wp9q-4779")
    assert langfuse_record is not None

    affected_with_components = [
        a for a in langfuse_record["affected"]
        if "ecosystem_specific" in a
    ]
    assert len(affected_with_components) >= 1

    component = affected_with_components[0]["ecosystem_specific"]["components"][0]
    assert component["component_type"] == "npm"
    assert component["component_purl"].startswith("pkg:npm/")

    # Check go-module component in syncthing record
    syncthing_record = _find_record_by_id(workspace, "CGA-xcpc-gm23-prj9")
    assert syncthing_record is not None

    affected_with_components = [
        a for a in syncthing_record["affected"]
        if "ecosystem_specific" in a and a["package"]["name"] == "syncthing"
    ]
    assert len(affected_with_components) >= 1

    component = affected_with_components[0]["ecosystem_specific"]["components"][0]
    assert component["component_type"] == "go-module"
    assert component["component_purl"].startswith("pkg:golang/")


def test_osv_component_status_not_affected_with_justification(osv_provider):
    """
    Components with status='not_affected' must include a justification.
    This corresponds to false-positive determinations in the v2 advisory model.
    """
    p, workspace = osv_provider
    p.update(None)

    syncthing_record = _find_record_by_id(workspace, "CGA-xcpc-gm23-prj9")
    assert syncthing_record is not None

    # Find the syncthing-compat entry which has a not_affected component
    compat_affected = [
        a for a in syncthing_record["affected"]
        if a["package"]["name"] == "syncthing-compat" and "ecosystem_specific" in a
    ]
    assert len(compat_affected) == 1

    component = compat_affected[0]["ecosystem_specific"]["components"][0]
    assert component["status"] == "not_affected"
    assert "justification" in component
    assert component["justification"] == "VULNERABLE_CODE_NOT_PRESENT"
    # Optional note field
    assert "note" in component


def test_osv_schema_url_in_envelope(osv_provider):
    """
    Verify the envelope schema URL points to the OSV schema, not the
    OS/secdb schema. This is what grype-db uses to route records to the
    correct processor.
    """
    p, workspace = osv_provider
    p.update(None)

    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        assert "/osv/" in envelope["schema"], (
            f"expected OSV schema URL, got: {envelope['schema']}"
        )
        assert "/os/" not in envelope["schema"], (
            f"got secdb schema URL instead of OSV: {envelope['schema']}"
        )


def test_osv_custom_base_url(osv_workspace, monkeypatch):
    """
    Verify the osv_base_url config option is respected.
    """
    from vunnel.utils import http_wrapper

    captured_urls = []
    original_mock = _make_osv_mock_http_get()

    def tracking_mock(url, *args, **kwargs):
        captured_urls.append(url)
        # Rewrite custom URL back to fixture URL for mock to work
        url = url.replace("https://custom.example.com/osv", "https://packages.cgr.dev/chainguard/osv")
        return original_mock(url, *args, **kwargs)

    monkeypatch.setattr(http_wrapper, "get", tracking_mock)

    c = Config()
    c.use_osv = True
    c.osv_base_url = "https://custom.example.com/osv"
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)
    p.update(None)

    # Verify custom base URL was used
    assert any("custom.example.com" in url for url in captured_urls)
    assert captured_urls[0] == "https://custom.example.com/osv/all.json"


def test_osv_network_failure_crashes(osv_workspace, monkeypatch):
    """
    When fetching an individual record fails due to a network error,
    the provider should fail with a clear error. We cannot produce a
    partial feed with missing entries - downstream consumers would have
    no way to know data is missing.
    """
    from vunnel.utils import http_wrapper

    # Make one record fail with network error
    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(fail_records={"CGA-22hv-wp9q-4779"})
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"failed to fetch.*CGA-22hv-wp9q-4779"):
        p.update(None)


def test_osv_malformed_json_crashes(osv_workspace, monkeypatch):
    """
    When a record returns malformed JSON, the provider should crash with
    a clear error rather than silently skipping. Malformed data indicates
    a feed problem that needs to be fixed upstream.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(malformed_records={"CGA-22hv-wp9q-4779"})
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"CGA-22hv-wp9q-4779.*invalid JSON"):
        p.update(None)


def test_osv_index_network_failure_crashes(osv_workspace, monkeypatch):
    """
    When fetching the index fails, the provider should crash with a clear
    error. Without the index, we cannot know what records exist.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(index_fail=True)
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"failed to fetch Chainguard OSV index"):
        p.update(None)


def test_osv_index_malformed_json_crashes(osv_workspace, monkeypatch):
    """
    When the index returns malformed JSON, the provider should crash with
    a clear error indicating the index is broken.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(index_malformed=True)
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"index.*contains invalid JSON"):
        p.update(None)


def test_osv_index_not_list_crashes(osv_workspace, monkeypatch):
    """
    When the index returns a non-list (e.g., dict), the provider should crash
    with a clear error. Without this check, a dict index would silently produce
    zero results or iterate over keys instead of entries.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(index_not_list=True)
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"expected a list, got dict"):
        p.update(None)


def test_osv_index_entry_missing_id_crashes(osv_workspace, monkeypatch):
    """
    When an index entry is missing the required "id" field, the provider
    should crash with a clear error showing the malformed entry.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(index_missing_id=True)
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"entry 0 is missing required 'id' field"):
        p.update(None)


def test_osv_index_entry_not_dict_crashes(osv_workspace, monkeypatch):
    """
    When an index entry is not a dict (e.g., string, number, null), the
    provider should crash with a clear error. Without this check, non-dict
    entries would cause confusing TypeError exceptions.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(
        http_wrapper, "get",
        _make_osv_mock_http_get(index_entry_not_dict=True)
    )

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with pytest.raises(RuntimeError, match=r"entry 0 has invalid type.*expected dict, got str"):
        p.update(None)


def test_osv_schema_version_in_record(osv_provider):
    """
    Verify that records include schema_version field.
    """
    p, workspace = osv_provider
    p.update(None)

    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        record = envelope["item"]
        assert "schema_version" in record, "expected schema_version field in record"


def test_osv_incompatible_schema_version_skipped(osv_workspace, monkeypatch, caplog):
    """
    Records with an incompatible major version (e.g., 2.0.0) should be skipped
    with a warning, not crash.
    """
    from vunnel.utils import http_wrapper
    import logging

    # Create a mock that returns one compatible and one incompatible record
    def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        if "all.json" in url:
            resp.content = b'[{"id": "CGA-compat"}, {"id": "CGA-incompat"}]'
        elif "CGA-compat" in url:
            resp.content = json.dumps({
                "schema_version": "1.7.0",
                "id": "CGA-compat",
                "modified": "2026-01-01T00:00:00Z",
                "affected": []
            }).encode()
        elif "CGA-incompat" in url:
            resp.content = json.dumps({
                "schema_version": "2.0.0",
                "id": "CGA-incompat",
                "modified": "2026-01-01T00:00:00Z",
                "affected": []
            }).encode()
        else:
            raise RuntimeError(f"unexpected URL: {url}")
        return resp

    monkeypatch.setattr(http_wrapper, "get", mock_get)

    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=osv_workspace.root, config=c)

    with caplog.at_level(logging.WARNING):
        p.update(None)

    # Only the compatible record should be written
    result_files = list(osv_workspace.result_files())
    assert len(result_files) == 1

    with open(result_files[0]) as f:
        envelope = json.load(f)
    assert envelope["item"]["id"] == "CGA-compat"

    # Should have logged a warning about the incompatible record
    assert any("CGA-incompat" in msg and "2.0.0" in msg for msg in caplog.messages)


# ---------------------------------------------------------------------------
# secdb mode (use_osv=False, backward compatibility)
# ---------------------------------------------------------------------------

def test_provider_schema_secdb(helpers, disable_get_requests, auto_fake_fixdate_finder):
    """
    Backward-compatibility test: with use_osv=False the provider should behave
    exactly like the old secdb-based provider (OS schema, 189 entries).
    """
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.use_osv = False
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    p.update(None)

    assert workspace.num_result_entries() == 189
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_secdb_schema_url(helpers, disable_get_requests, auto_fake_fixdate_finder):
    """
    With use_osv=False the emitted envelopes must use the OS/secdb schema URL.
    """
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.use_osv = False
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    p.update(None)

    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        assert "/os/" in envelope["schema"], (
            f"expected secdb OS schema URL, got: {envelope['schema']}"
        )


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    """
    Snapshot test for secdb mode (use_osv=False): ensures the exact output
    stays stable for backward compatibility.
    """
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )

    c = Config()
    c.use_osv = False
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()


def test_use_osv_defaults_to_false():
    """
    Verify use_osv defaults to False for backward compatibility with
    existing deployments using the secdb format.
    """
    c = Config()
    assert c.use_osv is False
