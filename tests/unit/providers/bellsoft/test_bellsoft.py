"""Provider-level tests for the bellsoft provider.

Covers Provider.update() end to end: schema conformance of what gets written,
the result envelope, and compatible_schema(). Parser internals live in
test_parser.py.
"""

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
    """Write the tarball the parser expects into a workspace input dir."""
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
    """Pack the JSON advisories under test-fixtures/input into the input tarball.

    The fixtures are kept as plain JSON (rather than a checked-in .tar.gz) so
    they stay reviewable and diffable; the repo has no binary archive fixtures.
    The layout mirrors a real github archive download, which nests everything
    under a "<repo>-<branch>/" top-level directory.
    """
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
# the standard provider gates: real upstream fixtures in, valid records out
# ---------------------------------------------------------------------------


@patch.object(Parser, "_download")
def test_provider_schema(mock_download, helpers, disable_get_requests, auto_fake_fixdate_finder):
    mock_download.return_value = None
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    p = _provider(workspace.root)

    _build_input_archive_from_fixtures(helpers, workspace)

    p.update(None)

    # 5 fixtures in, 1 of which is withdrawn and dropped by the parser
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
# update() plumbing: the returned count, and the shape of the written envelope
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
    # the envelope always advertises the pinned schema, never the record's own
    assert envelope["schema"] == schema_def.OSVSchema(PINNED_OSV_SCHEMA_VERSION).url


# ---------------------------------------------------------------------------
# a run that finds nothing must not clobber the previous run
# ---------------------------------------------------------------------------


def test_update_with_zero_advisories_is_a_no_op(helpers, disable_get_requests, auto_fake_fixdate_finder):
    """If upstream renames the BELL-CVE directory the filter matches nothing.

    A zero-result run is deliberately a no-op, framework-wide: Provider._update
    only calls record_state() when `count > 0` (src/vunnel/provider.py:203), so
    the last good run's state is preserved. See the sibling test for why that
    matters. This pins the safety property, not a bellsoft quirk.
    """
    ws_helper = helpers.provider_workspace_helper(name=Provider.name())
    # same records, but upstream renamed the advisory directory
    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
        sub_dir="advisories",
    )
    p = _provider(ws_helper.root)
    with patch.object(Parser, "_download"):
        _, count = p.update(None)

    # no exception and no results: the run is a no-op
    assert count == 0
    assert ws_helper.num_result_entries() == 0


def test_zero_advisories_leaves_previous_results_in_place(helpers, disable_get_requests, auto_fake_fixdate_finder):
    """A vacuous run must not clobber a good one.

    DELETE_BEFORE_WRITE is applied by store.prepare(), which Writer.write only
    calls on the *first* write (src/vunnel/result.py:347). So a run that yields
    nothing never clears the previous results -- serving day-old data is
    strictly better than serving none. This is framework behavior every
    provider inherits; only rocky and rhel add a zero-result guard, and only
    for the skip_download case where an empty result means user error.
    """
    ws_helper = helpers.provider_workspace_helper(name=Provider.name())

    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
    )
    with patch.object(Parser, "_download"):
        _provider(ws_helper.root).update(None)
    assert ws_helper.num_result_entries() == 1

    # second run: upstream layout changed, nothing matches
    _advisories(
        str(ws_helper.input_path),
        [{"id": "BELL-CVE-2020-0001", "modified": "2024-01-01T00:00:00Z", "schema_version": "1.7.4"}],
        sub_dir="advisories",
    )
    with patch.object(Parser, "_download"):
        _, count = _provider(ws_helper.root).update(None)

    assert count == 0
    # the previous run's results survive rather than being clobbered
    assert ws_helper.num_result_entries() == 1


# ---------------------------------------------------------------------------
# compatible_schema(): which declared versions are writable, and under what
# ---------------------------------------------------------------------------


class TestCompatibleSchema:
    def test_same_major_version_uses_pinned_schema(self):
        # a record's declared schema_version (e.g. the real 1.6.7 upstream
        # record) is metadata, not the validation target: the envelope must
        # always point at the provider's pinned, vendored schema
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
        """compatible_schema() is fed whatever upstream declared; a bogus value
        must be reported as incompatible, never crash the provider."""
        assert Provider.compatible_schema(schema_version) is None


def test_record_with_unparseable_schema_version_is_skipped_not_fatal(
    helpers, disable_get_requests, auto_fake_fixdate_finder,
):
    """A bogus schema_version must not crash the run, and must not be emitted.

    Falling back to a default and keeping the record was the tempting fix, but
    the bogus value stays in the payload -- `"schema_version": null` fails the
    OSV schema with "None is not of type 'string'". So the record is skipped
    with a warning, and the sibling advisory is still emitted and conformant.
    """
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
