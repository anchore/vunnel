"""Provider-level tests. Parser internals live in test_parser.py."""

from __future__ import annotations

import io
import json
import os
import tarfile
from unittest.mock import patch

import pytest

from vunnel import result, schema as schema_def
from vunnel.providers.bellsoft import Config, Provider
from vunnel.providers.bellsoft.parser import PINNED_OSV_SCHEMA_VERSION, Parser


def _write_archive(input_path: str, members: dict[str, bytes]) -> None:
    os.makedirs(input_path, exist_ok=True)
    with tarfile.open(os.path.join(input_path, Parser._archive_name_), mode="w:gz") as tar:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


def _advisories(input_path: str, records: list[dict], sub_dir: str = "BELL-CVE") -> None:
    _write_archive(
        input_path,
        {f"osv-database-master/{sub_dir}/{r['id']}.json": json.dumps(r).encode() for r in records},
    )


def _build_input_archive_from_fixtures(helpers, workspace) -> None:
    """Fixtures stay plain JSON rather than a checked-in .tar.gz so they stay reviewable."""
    fixture_dir = helpers.local_dir("test-fixtures/input/BELL-CVE")
    members = {}
    for name in sorted(os.listdir(fixture_dir)):
        with open(os.path.join(fixture_dir, name), "rb") as fh:
            members[f"osv-database-master/BELL-CVE/{name}"] = fh.read()
    _write_archive(str(workspace.input_dir), members)


def _provider(root) -> Provider:
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    return Provider(root=root, config=c)


# ---------------------------------------------------------------------------
# schema and snapshot gates
# ---------------------------------------------------------------------------


@patch.object(Parser, "_download")
def test_provider_schema(mock_download, helpers, disable_get_requests, auto_fake_fixdate_finder):
    mock_download.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    p = _provider(workspace.root)

    _build_input_archive_from_fixtures(helpers, workspace)

    p.update(None)

    # One of the 5 fixtures is withdrawn.
    assert workspace.num_result_entries() == 4
    assert workspace.result_schemas_valid(require_entries=True)


@patch.object(Parser, "_download")
def test_provider_via_snapshot(mock_download, helpers, disable_get_requests, auto_fake_fixdate_finder):
    mock_download.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    p = _provider(workspace.root)

    _build_input_archive_from_fixtures(helpers, workspace)

    p.update(None)

    workspace.assert_result_snapshots()


# ---------------------------------------------------------------------------
# update() plumbing
# ---------------------------------------------------------------------------


def test_update_returns_count_and_lowercased_identifiers(helpers, disable_get_requests, auto_fake_fixdate_finder):
    ws_helper = helpers.provider_workspace_helper(name=Provider.name())
    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
    )
    p = _provider(ws_helper.root)
    with patch.object(Parser, "_download"):
        urls, count = p.update(None)

    assert count == 1
    assert urls == [Parser._download_url_]
    names = [os.path.basename(f) for f in ws_helper.result_files()]
    assert names == ["bell-cve-2020-0001.json"]
    with open(ws_helper.result_files()[0]) as fh:
        envelope = json.load(fh)
    assert envelope["identifier"] == "bell-cve-2020-0001"
    assert envelope["item"]["id"] == "BELL-CVE-2020-0001"
    # The record declares 1.7.4. The envelope names the pinned schema.
    assert envelope["schema"] == schema_def.OSVSchema(PINNED_OSV_SCHEMA_VERSION).url


# ---------------------------------------------------------------------------
# zero-result runs
# ---------------------------------------------------------------------------


def test_update_with_zero_advisories_is_a_no_op(helpers, disable_get_requests, auto_fake_fixdate_finder):
    ws_helper = helpers.provider_workspace_helper(name=Provider.name())
    # Upstream renamed the advisory directory, so the filter matches nothing.
    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
        sub_dir="advisories",
    )
    p = _provider(ws_helper.root)
    with patch.object(Parser, "_download"):
        _, count = p.update(None)

    assert count == 0
    assert ws_helper.num_result_entries() == 0


def test_zero_advisories_leaves_previous_results_in_place(helpers, disable_get_requests, auto_fake_fixdate_finder):
    """Writer.write calls store.prepare() only on the first write, so
    DELETE_BEFORE_WRITE never fires in a run that yields nothing."""
    ws_helper = helpers.provider_workspace_helper(name=Provider.name())

    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
    )
    with patch.object(Parser, "_download"):
        _provider(ws_helper.root).update(None)
    assert ws_helper.num_result_entries() == 1

    # Second run: upstream renamed the advisory directory.
    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
        sub_dir="advisories",
    )
    with patch.object(Parser, "_download"):
        _, count = _provider(ws_helper.root).update(None)

    assert count == 0
    assert ws_helper.num_result_entries() == 1


# ---------------------------------------------------------------------------
# compatible_schema()
# ---------------------------------------------------------------------------


class TestCompatibleSchema:
    def test_same_major_version_uses_pinned_schema(self):
        # Upstream records declare 1.7.4 or 1.6.7.
        pinned = Provider.__schema__.version
        assert Provider.compatible_schema("1.7.4").version == pinned
        assert Provider.compatible_schema("1.6.7").version == pinned

    def test_incompatible_major_version_is_rejected(self):
        assert Provider.compatible_schema("2.0.0") is None

    @pytest.mark.parametrize(
        "schema_version",
        [
            pytest.param("abc", id="garbage-string"),
            pytest.param(None, id="null"),
            pytest.param(1, id="number"),
            pytest.param("", id="empty"),
        ],
    )
    def test_bad_schema_version_is_rejected_not_fatal(self, schema_version):
        assert Provider.compatible_schema(schema_version) is None


def test_record_with_unparseable_schema_version_is_skipped_not_fatal(
    helpers, disable_get_requests, auto_fake_fixdate_finder,
):
    """The bogus value stays in the payload, so emitting the record would fail the
    OSV schema."""
    ws_helper = helpers.provider_workspace_helper(name=Provider.name())
    _advisories(
        str(ws_helper.input_path),
        [
            {"id": "BELL-CVE-2020-0002", "modified": "2024-01-01T00:00:00Z", "schema_version": None},
            {"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"},
        ],
    )
    p = _provider(ws_helper.root)
    with patch.object(Parser, "_download"):
        _, count = p.update(None)

    assert count == 1
    assert ws_helper.result_schemas_valid(require_entries=True)
