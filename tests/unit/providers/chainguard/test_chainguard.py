from __future__ import annotations

import json
import os
import shutil
from unittest.mock import MagicMock

from vunnel import result
from vunnel.providers.chainguard import Config, Provider


# ---------------------------------------------------------------------------
# Helpers for mocking HTTP calls to the Chainguard OSV endpoint
# ---------------------------------------------------------------------------

def _osv_fixture_path(filename: str) -> str:
    here = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(here, "test-fixtures", "osv", filename)


def _make_osv_mock_http_get():
    """
    Returns a mock for vunnel.utils.http_wrapper.get that serves the OSV
    test fixtures from disk, keyed by URL substring.
    """
    fixture_map = {
        "all.json": "all.json",
        "CGA-224q-ccj5-2p53": "CGA-224q-ccj5-2p53.json",
        "CGA-22hv-wp9q-4779": "CGA-22hv-wp9q-4779.json",
        "CGA-xcpc-gm23-prj9": "CGA-xcpc-gm23-prj9.json",
    }

    def mock_get(url, *args, **kwargs):
        for key, fixture_file in fixture_map.items():
            if key in url:
                resp = MagicMock()
                with open(_osv_fixture_path(fixture_file), "rb") as f:
                    resp.content = f.read()
                return resp
        raise RuntimeError(f"unexpected URL in test: {url}")

    return mock_get


# ---------------------------------------------------------------------------
# OSV mode (use_osv=True, the new default)
# ---------------------------------------------------------------------------

def test_provider_schema_osv(helpers, monkeypatch):
    """
    Full provider integration test for OSV mode: mocks the HTTP calls to the
    Chainguard OSV endpoint and validates that all emitted records are valid
    against the OSV schema.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    assert c.use_osv is False, "use_osv should default to False (secdb)"
    c.use_osv = True  # opt into OSV mode for this test

    p.update(None)

    # 3 CGA records in the index → 3 result files
    assert workspace.num_result_entries() == 3
    assert workspace.result_schemas_valid(require_entries=True)


def test_osv_record_identifiers(helpers, monkeypatch):
    """
    Verify that result files are keyed by CGA ID (lowercased) and that the
    emitted records carry the CGA ID as their primary identifier.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    ids_found = set()
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        ids_found.add(envelope["item"]["id"])

    assert "CGA-224q-ccj5-2p53" in ids_found
    assert "CGA-22hv-wp9q-4779" in ids_found
    assert "CGA-xcpc-gm23-prj9" in ids_found


def test_osv_related_ids_preserved(helpers, monkeypatch):
    """
    Chainguard CGA records carry CVE/GHSA IDs in 'related', not 'aliases'.
    Verify the field is preserved in the emitted record so that downstream
    processors (grype-db) can map them to aliases.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    haproxy_record = None
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        if envelope["item"]["id"] == "CGA-224q-ccj5-2p53":
            haproxy_record = envelope["item"]
            break

    assert haproxy_record is not None
    assert "related" in haproxy_record
    assert "CVE-2025-32464" in haproxy_record["related"]
    assert "GHSA-frg5-h47x-75j9" in haproxy_record["related"]


def test_osv_both_ecosystems_in_single_record(helpers, monkeypatch):
    """
    A single CGA record covers both Chainguard and Wolfi packages.
    Verify that both ecosystems appear in the affected list of the
    emitted record so grype-db can route them to both distros.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    haproxy_record = None
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        if envelope["item"]["id"] == "CGA-224q-ccj5-2p53":
            haproxy_record = envelope["item"]
            break

    assert haproxy_record is not None
    ecosystems = {a["package"]["ecosystem"] for a in haproxy_record["affected"]}
    assert "Chainguard" in ecosystems
    assert "Wolfi" in ecosystems

    # Specific packages
    names = {a["package"]["name"] for a in haproxy_record["affected"]}
    assert "haproxy-2.2" in names   # Chainguard-only package
    assert "haproxy-3.0" in names   # Wolfi package


def test_osv_per_package_fix_versions(helpers, monkeypatch):
    """
    Each package in a CGA record can have a different fix version.
    Verify fix versions are preserved per package.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    langfuse_record = None
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        if envelope["item"]["id"] == "CGA-22hv-wp9q-4779":
            langfuse_record = envelope["item"]
            break

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


def test_osv_nak_entry(helpers, monkeypatch):
    """
    A NAK entry (package explicitly not affected) is represented with
    fixed='0' in the OSV range events. Verify the record is emitted as-is
    so grype-db can detect the NAK constraint (< 0).
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    syncthing_record = None
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        if envelope["item"]["id"] == "CGA-xcpc-gm23-prj9":
            syncthing_record = envelope["item"]
            break

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


def test_osv_purl_preserved(helpers, monkeypatch):
    """
    PURL fields must be preserved in the affected list so grype-db can use
    them for package type detection.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    haproxy_record = None
    for rf in workspace.result_files():
        with open(rf) as f:
            envelope = json.load(f)
        if envelope["item"]["id"] == "CGA-224q-ccj5-2p53":
            haproxy_record = envelope["item"]
            break

    assert haproxy_record is not None
    by_name = {a["package"]["name"]: a for a in haproxy_record["affected"]}
    assert by_name["haproxy-2.2"]["package"]["purl"] == "pkg:apk/chainguard/haproxy-2.2"
    assert by_name["haproxy-3.0"]["package"]["purl"] == "pkg:apk/wolfi/haproxy-3.0"


def test_osv_schema_url_in_envelope(helpers, monkeypatch):
    """
    Verify the envelope schema URL points to the OSV schema, not the
    OS/secdb schema. This is what grype-db uses to route records to the
    correct processor.
    """
    from vunnel.utils import http_wrapper

    monkeypatch.setattr(http_wrapper, "get", _make_osv_mock_http_get())

    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.use_osv = True
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
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
