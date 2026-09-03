from __future__ import annotations

import io
import os
import zipfile

import pytest
from vunnel import result, schema, workspace
from vunnel.providers.echo_osv import Config, Provider
from vunnel.providers.echo_osv.parser import Parser


@pytest.fixture()
def osv_zip_bytes(helpers):
    """Build an in-memory zip from the JSON fixtures (the real feed ships all.zip).

    Built on the fly rather than committed: the repo .gitignore excludes
    *.zip, so a checked-in archive would silently vanish from the repo.
    """
    fixture_dir = os.path.join(helpers.local_dir("test-fixtures"), "input", "osv-json")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for fname in sorted(os.listdir(fixture_dir)):
            if fname.endswith(".json"):
                zf.write(os.path.join(fixture_dir, fname), fname)
    return buf.getvalue()


class TestParser:
    def test_load_and_filter(self, osv_zip_bytes, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        p = Parser(
            ws=ws,
            url="https://advisory.echohq.com/osv/all.zip",
        )

        entries = list(p._load(osv_zip_bytes))
        assert len(entries) == 4

        results = []
        for entry in entries:
            result = p._normalize(entry)
            if result is not None:
                results.append(result)

        # 3 entries have language (Echo:*) affected packages
        assert len(results) == 3

        ids = [r[0] for r in results]
        assert "ECHO-7db2-03aa-5591" in ids
        assert "ECHO-aa11-bb22-cc33" in ids
        assert "ECHO-dd44-ee55-ff66" in ids
        # OS-only entry should be excluded
        assert "ECHO-003f-2632-599c" not in ids

        # Every normalized record must carry the advisory marker so grype routes
        # the ranges into the unaffected-package store rather than the affected one.
        for _, _, record in results:
            assert record["database_specific"]["anchore"]["record_type"] == "advisory"

        # OSV 1.7 `upstream` must be merged into `aliases` so grype's OSV transformer
        # (which only reads aliases/related) can cross-reference Echo's NAK to GHSA
        # or NVD matches for the same CVE.
        by_id = {r[0]: r[2] for r in results}
        # ECHO-7db2-03aa-5591 has only `upstream` in the input — must surface as aliases
        assert "CVE-2026-1703" in by_id["ECHO-7db2-03aa-5591"]["aliases"]
        # ECHO-aa11-bb22-cc33 has only `aliases` in the input — must be preserved as-is
        assert "CVE-2025-99999" in by_id["ECHO-aa11-bb22-cc33"]["aliases"]

        # npm and maven language ecosystems pass through untouched
        assert {a["package"]["ecosystem"] for a in by_id["ECHO-dd44-ee55-ff66"]["affected"]} == {
            "Echo:npm",
            "Echo:Maven",
        }

    def test_echo_os_entries_stripped_from_mixed(self, tmpdir, auto_fake_fixdate_finder):
        """For entries with both Echo:PyPi and Echo ecosystems, only Echo:PyPi affected entries are kept."""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        p = Parser(
            ws=ws,
            url="https://advisory.echohq.com/osv/all.zip",
        )

        mixed_entry = {
            "schema_version": "1.6.1",
            "id": "ECHO-mixed",
            "affected": [
                {
                    "package": {"ecosystem": "Echo:PyPi", "name": "pip"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "25.2+echo.1"}]}],
                },
                {
                    "package": {"ecosystem": "Echo", "name": "python-pip"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "25.3+dfsg-1+e2"}]}],
                },
            ],
        }

        result = p._normalize(mixed_entry)
        assert result is not None
        vuln_id, _, record = result
        assert vuln_id == "ECHO-mixed"
        assert len(record["affected"]) == 1
        assert record["affected"][0]["package"]["ecosystem"] == "Echo:PyPi"


@pytest.mark.parametrize(
    "schema_version,expected",
    [
        ("1.6.1", schema.OSVSchema(version="1.6.1")),
        ("1.5.0", schema.OSVSchema(version="1.5.0")),
        ("0.6.0", None),
        ("2.4.0", None),
    ],
)
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


def test_provider_schema(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder, osv_zip_bytes):
    ws = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=ws.root, config=c)

    monkeypatch.setattr(p.parser, "_download", lambda: osv_zip_bytes)

    p.update(None)

    assert ws.num_result_entries() == 3
    assert ws.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder, osv_zip_bytes):
    ws = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=ws.root, config=c)

    monkeypatch.setattr(p.parser, "_download", lambda: osv_zip_bytes)

    p.update(None)

    ws.assert_result_snapshots()
