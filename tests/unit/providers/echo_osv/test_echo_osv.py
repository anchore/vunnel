from __future__ import annotations

import io
import zipfile

import pytest
from vunnel import result, schema, workspace
from vunnel.providers.echo_osv import Config, Provider
from vunnel.providers.echo_osv.parser import Parser


class TestParser:
    @pytest.fixture()
    def osv_zip_bytes(self, helpers):
        """Build an in-memory zip from the JSON fixtures."""
        import os

        fixture_dir = os.path.join(helpers.local_dir("test-fixtures"), "input", "osv-json")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for fname in sorted(os.listdir(fixture_dir)):
                if fname.endswith(".json"):
                    zf.write(os.path.join(fixture_dir, fname), fname)
        return buf.getvalue()

    def test_load_and_filter(self, osv_zip_bytes, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        p = Parser(
            ws=ws,
            url="https://advisory.echohq.com/osv/all.zip",
        )

        entries = list(p._load(osv_zip_bytes))
        assert len(entries) == 3

        results = []
        for entry in entries:
            result = p._normalize(entry)
            if result is not None:
                results.append(result)

        # Only 2 entries have Echo:PyPi affected packages
        assert len(results) == 2

        ids = [r[0] for r in results]
        assert "ECHO-7db2-03aa-5591" in ids
        assert "ECHO-aa11-bb22-cc33" in ids
        # OS-only entry should be excluded
        assert "ECHO-003f-2632-599c" not in ids

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


def test_provider_schema(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    ws = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=ws.root, config=c)

    zip_path = helpers.local_dir("test-fixtures/input/osv-all.zip")
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    monkeypatch.setattr(p.parser, "_download", lambda: zip_bytes)

    p.update(None)

    assert ws.num_result_entries() == 2
    assert ws.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    ws = helpers.provider_workspace_helper(name=Provider.name())
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=ws.root, config=c)

    zip_path = helpers.local_dir("test-fixtures/input/osv-all.zip")
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    monkeypatch.setattr(p.parser, "_download", lambda: zip_bytes)

    p.update(None)

    ws.assert_result_snapshots()
