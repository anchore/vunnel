from __future__ import annotations

import datetime
import os
import shutil
from unittest.mock import patch

import orjson
import pytest

from vunnel import provider, result, schema, workspace
from vunnel.providers.ubuntu import Config, Provider
from vunnel.providers.ubuntu.parser import (
    Parser,
    ecosystem_to_slug,
    slice_by_ecosystem,
)
from vunnel.tool.fixdate.finder import Result


@pytest.fixture
def fixture_dir(helpers):
    return helpers.local_dir("test-fixtures")


@pytest.fixture
def fresh_workspace(tmpdir):
    return workspace.Workspace(tmpdir, "ubuntu", create=True)


# ---------------------------------------------------------------------------
# Helpers under test (pure functions)
# ---------------------------------------------------------------------------


class TestEcosystemToSlug:
    def test_lowercase_and_colons_become_hyphens(self):
        assert ecosystem_to_slug("Ubuntu:22.04:LTS") == "ubuntu-22.04-lts"

    def test_pro_fips_long_form(self):
        assert ecosystem_to_slug("Ubuntu:Pro:FIPS-updates:20.04:LTS") == "ubuntu-pro-fips-updates-20.04-lts"

    def test_non_lts(self):
        assert ecosystem_to_slug("Ubuntu:25.10") == "ubuntu-25.10"


class TestSliceByEcosystem:
    def test_single_ecosystem_yields_one_slice(self):
        rec = {
            "id": "UBUNTU-CVE-X",
            "details": "anything",
            "affected": [
                {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "foo"}, "ranges": []},
            ],
        }
        sliced = slice_by_ecosystem(rec)
        assert list(sliced.keys()) == ["Ubuntu:22.04:LTS"]
        assert len(sliced["Ubuntu:22.04:LTS"]["affected"]) == 1

    def test_multi_ecosystem_yields_one_slice_per_eco(self):
        rec = {
            "id": "UBUNTU-CVE-X",
            "affected": [
                {"package": {"ecosystem": "Ubuntu:18.04:LTS", "name": "foo"}},
                {"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "foo"}},
                {"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "foo-aws"}},
            ],
        }
        sliced = slice_by_ecosystem(rec)
        assert set(sliced.keys()) == {"Ubuntu:18.04:LTS", "Ubuntu:20.04:LTS"}
        assert len(sliced["Ubuntu:18.04:LTS"]["affected"]) == 1
        # multiple affected[] entries for the same ecosystem land in one slice
        assert len(sliced["Ubuntu:20.04:LTS"]["affected"]) == 2

    def test_empty_affected_yields_empty(self):
        assert slice_by_ecosystem({"id": "X", "affected": []}) == {}
        assert slice_by_ecosystem({"id": "X"}) == {}

    def test_top_level_fields_preserved_in_each_slice(self):
        rec = {
            "id": "UBUNTU-CVE-X",
            "schema_version": "1.7.0",
            "details": "description text",
            "withdrawn": "2025-01-01T00:00:00Z",
            "severity": [{"type": "Ubuntu", "score": "low"}],
            "references": [{"type": "REPORT", "url": "https://example.com"}],
            "affected": [
                {"package": {"ecosystem": "Ubuntu:18.04:LTS", "name": "foo"}},
                {"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "foo"}},
            ],
        }
        sliced = slice_by_ecosystem(rec)
        for eco, slice_rec in sliced.items():
            assert slice_rec["id"] == "UBUNTU-CVE-X"
            assert slice_rec["schema_version"] == "1.7.0"
            assert slice_rec["details"] == "description text"
            assert slice_rec["withdrawn"] == "2025-01-01T00:00:00Z"
            assert slice_rec["severity"] == [{"type": "Ubuntu", "score": "low"}]
            assert slice_rec["references"] == [{"type": "REPORT", "url": "https://example.com"}]
            # only this ecosystem's affected entries
            assert all(a["package"]["ecosystem"] == eco for a in slice_rec["affected"])

    def test_entries_without_ecosystem_skipped(self):
        rec = {
            "id": "X",
            "affected": [
                {"package": {"ecosystem": "Ubuntu:22.04:LTS"}},
                {"package": {"name": "no-eco"}},  # missing ecosystem
                {},  # missing package entirely
            ],
        }
        sliced = slice_by_ecosystem(rec)
        assert set(sliced.keys()) == {"Ubuntu:22.04:LTS"}
        assert len(sliced["Ubuntu:22.04:LTS"]["affected"]) == 1


# ---------------------------------------------------------------------------
# Provider static attrs and config validation
# ---------------------------------------------------------------------------


class TestProvider:
    def test_static_attrs(self):
        assert Provider.name() == "ubuntu"
        assert Provider.tags() == ["vulnerability", "os"]
        assert "/osv/" in Provider.__schema__.url
        # see __init__.py docstring: bumping these would workspace.clear() the load-bearing input dir
        assert Provider.__distribution_version__ == 1
        assert Provider.__version__ == 3

    def test_compatible_schema_not_overridden(self):
        assert "compatible_schema" not in Provider.__dict__

    def test_rejects_existing_input_delete(self, tmpdir):
        c = Config()
        c.runtime.existing_input = provider.InputStatePolicy.DELETE
        with pytest.raises(ValueError, match="existing_input"):
            Provider(root=str(tmpdir), config=c)

    def test_rejects_on_error_input_delete(self, tmpdir):
        c = Config()
        c.runtime.on_error.input = provider.InputStatePolicy.DELETE
        with pytest.raises(ValueError, match="on_error.input"):
            Provider(root=str(tmpdir), config=c)


# ---------------------------------------------------------------------------
# Fragment writing — streaming tarball → per-ecosystem .db files
# ---------------------------------------------------------------------------


def _seed_archive(fresh_workspace, fixture_dir):
    shutil.copy(
        os.path.join(fixture_dir, "sample-osv-all.tar.xz"),
        os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


def _fragment_paths(workspace):
    fragments_dir = os.path.join(workspace.input_path, "fragments")
    if not os.path.isdir(fragments_dir):
        return []
    return sorted(os.listdir(fragments_dir))


class TestParserFragmentWriter:
    # Real OSV fixtures in tests/unit/providers/ubuntu/test-fixtures/osv:
    #   UBUNTU-CVE-2013-2208   (1.7.0, has `fixed:` events, withdrawn)
    #                                                -> Ubuntu:14.04:LTS
    #   UBUNTU-CVE-2020-36325  (1.6.3, withdrawn)    -> Ubuntu:Pro:14.04:LTS
    #   UBUNTU-CVE-2021-3782   (1.7.0)               -> Ubuntu:18.04:LTS, Ubuntu:20.04:LTS,
    #                                                   Ubuntu:22.04:LTS, Ubuntu:Pro:16.04:LTS
    #   UBUNTU-CVE-2026-1403   (1.7.0)               -> Ubuntu:16.04:LTS

    def test_writes_one_fragment_per_ecosystem(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        assert _fragment_paths(fresh_workspace) == [
            "ubuntu-14.04-lts.db",
            "ubuntu-16.04-lts.db",
            "ubuntu-18.04-lts.db",
            "ubuntu-20.04-lts.db",
            "ubuntu-22.04-lts.db",
            "ubuntu-pro-14.04-lts.db",
            "ubuntu-pro-16.04-lts.db",
        ]

    def test_fragment_envelope_identifier_is_eco_slug_prefixed(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-16.04-lts.db")
        with result.SQLiteReader(path) as reader:
            ids = [e.identifier for e in reader.each()]
        assert ids == ["ubuntu-16.04-lts/ubuntu-cve-2026-1403"]

    def test_fragment_payload_is_per_ecosystem_slice(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        # CVE-2021-3782 spans 4 ecosystems — each fragment should hold only its slice
        for release_slug, expected_eco in [
            ("ubuntu-18.04-lts", "Ubuntu:18.04:LTS"),
            ("ubuntu-20.04-lts", "Ubuntu:20.04:LTS"),
            ("ubuntu-22.04-lts", "Ubuntu:22.04:LTS"),
            ("ubuntu-pro-16.04-lts", "Ubuntu:Pro:16.04:LTS"),
        ]:
            path = os.path.join(fresh_workspace.input_path, "fragments", f"{release_slug}.db")
            with result.SQLiteReader(path) as reader:
                envelope = next(e for e in reader.each() if "2021-3782" in e.identifier)
            ecosystems = {a["package"]["ecosystem"] for a in envelope.item["affected"]}
            assert ecosystems == {expected_eco}

    def test_fragment_envelope_carries_per_record_schema(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        # UBUNTU-CVE-2020-36325 declares schema_version 1.6.3 in Canonical's feed
        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-pro-14.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(reader.each())
        assert env.schema.endswith("/osv/schema-1.6.3.json")

    def test_fragment_preserves_withdrawn_field(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2020-36325 has withdrawn="2025-06-23T15:53:49Z" — the slice must carry it
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-pro-14.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(reader.each())
        assert env.item.get("withdrawn") == "2025-06-23T15:53:49Z"

    def test_record_with_no_affected_emits_no_fragments(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, tmp_path):
        # construct a tarball with one record that has empty affected[]
        import tarfile
        import io

        empty_rec = {
            "schema_version": "1.7.0",
            "id": "UBUNTU-CVE-EMPTY",
            "details": "no affected",
            "affected": [],
        }
        archive_path = os.path.join(fresh_workspace.input_path, "osv-all.tar.xz")
        body = orjson.dumps(empty_rec)
        with tarfile.open(archive_path, mode="w:xz") as tar:
            ti = tarfile.TarInfo("osv/cve/2099/UBUNTU-CVE-EMPTY.json")
            ti.size = len(body)
            tar.addfile(ti, io.BytesIO(body))

        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        assert _fragment_paths(fresh_workspace) == []


class TestParserFreeze:
    """The headline behavior — fragments for ecosystems absent from today's tarball survive.

    `Ubuntu:25.10` (questing) is not in the fixture tarball so it's a natural stand-in
    for a release that's about to leave the OSV feed.
    """

    def test_fragment_for_absent_ecosystem_is_preserved(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # plant a fake "frozen" fragment for an ecosystem not in today's tarball
        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        os.makedirs(fragments_dir)
        frozen_path = os.path.join(fragments_dir, "ubuntu-25.10.db")
        # write something into it so we can check it's not been zero'd
        with result.Writer(
            workspace=fresh_workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=frozen_path,
        ) as w:
            w.write(
                identifier="ubuntu-25.10/ubuntu-cve-frozen-1",
                schema=schema.OSVSchema(version="1.7.0"),
                payload={"id": "UBUNTU-CVE-FROZEN-1", "details": "frozen", "affected": []},
            )
        frozen_mtime = os.path.getmtime(frozen_path)

        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        # frozen fragment is untouched
        assert os.path.exists(frozen_path)
        assert os.path.getmtime(frozen_path) == frozen_mtime
        # but the ecosystems in today's tarball wrote their own fragments
        present = set(_fragment_paths(fresh_workspace))
        assert "ubuntu-25.10.db" in present
        assert "ubuntu-22.04-lts.db" in present

    def test_fragment_for_present_ecosystem_is_overwritten(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # plant a stale fragment for an ecosystem THAT IS in today's tarball — should be wiped
        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        os.makedirs(fragments_dir)
        stale_path = os.path.join(fragments_dir, "ubuntu-22.04-lts.db")
        with result.Writer(
            workspace=fresh_workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=stale_path,
        ) as w:
            w.write(
                identifier="ubuntu-22.04-lts/ubuntu-cve-stale-1",
                schema=schema.OSVSchema(version="1.7.0"),
                payload={"id": "UBUNTU-CVE-STALE-1", "details": "stale", "affected": []},
            )

        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        # stale row should be gone after rewrite
        with result.SQLiteReader(stale_path) as reader:
            ids = {e.identifier for e in reader.each()}
        assert "ubuntu-22.04-lts/ubuntu-cve-stale-1" not in ids
        # the 22.04 slice of the real 2021-3782 fixture should be present in its place
        assert any("2021-3782" in i for i in ids)


# ---------------------------------------------------------------------------
# Fix-date patching happens before slicing
# ---------------------------------------------------------------------------


class TestParserFixDatePatching:
    def test_patched_fix_date_appears_in_slice(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # UBUNTU-CVE-2013-2208 carries a real `fixed: 1.3.1-3` event on Ubuntu:14.04:LTS.
        # Mark the fixdate response accurate so it beats the (later) published-date candidate.
        finder = fake_fixdate_finder(
            responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
        )
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace, fixdater=finder)
        p._write_fragments()

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-14.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2013-2208" in e.identifier)
        anchore = env.item["affected"][0]["ranges"][0]["database_specific"]["anchore"]
        assert any(fix["date"] == "2013-07-15" and fix["version"] == "1.3.1-3" for fix in anchore["fixes"])

    def test_no_fixed_events_no_anchore_field(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        # Fixtures with only {"introduced": "0"} ranges (no fixed: events) —
        # patch_fix_date is a no-op for them. The other fragments (2013-2208 + all
        # of 2021-3782's slices) DO have fixed: events and would get anchore populated.
        for slug in ("ubuntu-16.04-lts", "ubuntu-pro-14.04-lts"):
            path = os.path.join(fresh_workspace.input_path, "fragments", f"{slug}.db")
            with result.SQLiteReader(path) as reader:
                env = next(reader.each())
            for r in env.item["affected"][0]["ranges"]:
                assert "anchore" not in r.get("database_specific", {})


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


class TestParserDownload:
    def test_download_streams_to_archive_path(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        with open(os.path.join(fixture_dir, "sample-osv-all.tar.xz"), "rb") as f:
            payload = f.read()

        class FakeResp:
            def __init__(self, data: bytes):
                self._data = data

            def iter_content(self, chunk_size: int):  # noqa: ARG002
                yield self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return None

        with patch("vunnel.providers.ubuntu.parser.http.get", return_value=FakeResp(payload)):
            p = Parser(workspace=fresh_workspace)
            p._download_archive()

        archive = os.path.join(fresh_workspace.input_path, "osv-all.tar.xz")
        assert os.path.isfile(archive)
        assert os.path.getsize(archive) == len(payload)

    def test_download_creates_input_dir_if_missing(self, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "ubuntu", create=True)
        # delete the input dir to simulate a fresh setup
        shutil.rmtree(ws.input_path)
        assert not os.path.isdir(ws.input_path)

        class FakeResp:
            def iter_content(self, chunk_size: int):  # noqa: ARG002
                yield b"x"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return None

        with patch("vunnel.providers.ubuntu.parser.http.get", return_value=FakeResp()):
            p = Parser(workspace=ws)
            p._download_archive()

        assert os.path.isfile(os.path.join(ws.input_path, "osv-all.tar.xz"))


# ---------------------------------------------------------------------------
# Iteration: read fragments back from disk
# ---------------------------------------------------------------------------


class TestParserIteration:
    def test_iter_fragments_yields_envelopes_from_every_db_file(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        ids = sorted(t[0] for t in p._iter_fragments())
        # one envelope per (CVE, ecosystem) pair: 2013-2208 × 1, 2020-36325 × 1, 2021-3782 × 4, 2026-1403 × 1 = 7
        assert ids == [
            "ubuntu-14.04-lts/ubuntu-cve-2013-2208",
            "ubuntu-16.04-lts/ubuntu-cve-2026-1403",
            "ubuntu-18.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-20.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-22.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-pro-14.04-lts/ubuntu-cve-2020-36325",
            "ubuntu-pro-16.04-lts/ubuntu-cve-2021-3782",
        ]

    def test_iter_fragments_yields_correct_schema_per_record(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        by_id = {t[0]: t[1] for t in p._iter_fragments()}
        # 2020-36325 declares 1.6.3 (real Canonical record); the others declare 1.7.0
        assert by_id["ubuntu-pro-14.04-lts/ubuntu-cve-2020-36325"].url.endswith("/osv/schema-1.6.3.json")
        assert by_id["ubuntu-18.04-lts/ubuntu-cve-2021-3782"].url.endswith("/osv/schema-1.7.0.json")

    def test_iter_fragments_empty_when_dir_missing(self, fresh_workspace, auto_fake_fixdate_finder):
        p = Parser(workspace=fresh_workspace)
        assert list(p._iter_fragments()) == []

    def test_iter_includes_frozen_fragments(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # plant a frozen fragment, then run write_fragments against the fixture
        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        os.makedirs(fragments_dir)
        with result.Writer(
            workspace=fresh_workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=os.path.join(fragments_dir, "ubuntu-25.10.db"),
        ) as w:
            w.write(
                identifier="ubuntu-25.10/ubuntu-cve-frozen",
                schema=schema.OSVSchema(version="1.7.0"),
                payload={"id": "UBUNTU-CVE-FROZEN", "details": "frozen", "affected": []},
            )

        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        ids = {t[0] for t in p._iter_fragments()}
        # frozen survives alongside today's data
        assert "ubuntu-25.10/ubuntu-cve-frozen" in ids
        assert "ubuntu-22.04-lts/ubuntu-cve-2021-3782" in ids


# ---------------------------------------------------------------------------
# Full Provider.update integration
# ---------------------------------------------------------------------------


def _stage_workspace_for_update(ws_root: str, fixture_dir: str) -> None:
    input_path = os.path.join(ws_root, "ubuntu", "input")
    os.makedirs(input_path, exist_ok=True)
    shutil.copy(
        os.path.join(fixture_dir, "sample-osv-all.tar.xz"),
        os.path.join(input_path, "osv-all.tar.xz"),
    )


# ---------------------------------------------------------------------------
# Legacy passthrough — normalized-cve-data → OS schema envelopes for at-cutover EOL
# ---------------------------------------------------------------------------


def _seed_normalized(fresh_workspace, fixture_dir):
    shutil.copytree(
        os.path.join(fixture_dir, "normalized-cve-data"),
        os.path.join(fresh_workspace.input_path, "normalized-cve-data"),
    )


class TestParserLegacyPassthrough:
    # Real normalized-cve-data fixtures:
    #   CVE-2012-5124   chromium-browser, released on precise + quantal
    #   CVE-2013-6627   chromium-browser, released on precise + quantal + raring
    #   CVE-2022-31258  check-mk, not-affected on bionic (used for OSV-coverage filter)

    def test_emits_os_schema_envelopes_for_eol_namespaces(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_normalized(fresh_workspace, fixture_dir)
        # No fragments dir → no ecosystems covered → every legacy ns emits.
        p = Parser(workspace=fresh_workspace)
        records = list(p._iter_normalized_cve_data())

        identifiers = sorted(r[0] for r in records)
        assert identifiers == [
            "ubuntu:12.04/cve-2012-5124",
            "ubuntu:12.04/cve-2013-6627",
            "ubuntu:12.10/cve-2012-5124",
            "ubuntu:12.10/cve-2013-6627",
            "ubuntu:13.04/cve-2013-6627",
            "ubuntu:18.04/cve-2022-31258",
        ]
        for _id, sch, _payload in records:
            assert "/os/" in sch.url

    def test_skips_records_for_osv_covered_namespaces(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_normalized(fresh_workspace, fixture_dir)
        # plant a fragment for 18.04 — CVE-2022-31258 bionic should be filtered
        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        os.makedirs(fragments_dir)
        open(os.path.join(fragments_dir, "ubuntu-18.04-lts.db"), "wb").close()

        p = Parser(workspace=fresh_workspace)
        identifiers = sorted(r[0] for r in p._iter_normalized_cve_data())

        assert "ubuntu:18.04/cve-2022-31258" not in identifiers
        assert identifiers == [
            "ubuntu:12.04/cve-2012-5124",
            "ubuntu:12.04/cve-2013-6627",
            "ubuntu:12.10/cve-2012-5124",
            "ubuntu:12.10/cve-2013-6627",
            "ubuntu:13.04/cve-2013-6627",
        ]

    def test_missing_dir_yields_nothing(self, fresh_workspace, auto_fake_fixdate_finder):
        p = Parser(workspace=fresh_workspace)
        assert list(p._iter_normalized_cve_data()) == []

    def test_invalid_files_are_skipped(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_normalized(fresh_workspace, fixture_dir)
        norm = os.path.join(fresh_workspace.input_path, "normalized-cve-data")
        with open(os.path.join(norm, "CVE-2099-9999"), "w") as f:
            f.write("not json")
        # non-CVE filename - silently ignored
        with open(os.path.join(norm, "README"), "w") as f:
            f.write("not a CVE file")

        p = Parser(workspace=fresh_workspace)
        identifiers = sorted(r[0] for r in p._iter_normalized_cve_data())
        # the three real fixtures still emit fully; garbage doesn't crash iteration
        assert identifiers == [
            "ubuntu:12.04/cve-2012-5124",
            "ubuntu:12.04/cve-2013-6627",
            "ubuntu:12.10/cve-2012-5124",
            "ubuntu:12.10/cve-2013-6627",
            "ubuntu:13.04/cve-2013-6627",
            "ubuntu:18.04/cve-2022-31258",
        ]

    def test_legacy_payload_is_v3_vulnerability_shape(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_normalized(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        by_id = {r[0]: r[2] for r in p._iter_normalized_cve_data()}

        precise = by_id["ubuntu:12.04/cve-2012-5124"]
        assert "Vulnerability" in precise
        vuln = precise["Vulnerability"]
        assert vuln["Name"] == "CVE-2012-5124"
        assert vuln["NamespaceName"] == "ubuntu:12.04"
        # the real Canonical record has chromium-browser released at 3.0.1271.97-0ubuntu0.12.04.1
        fixed_in_versions = [f["Version"] for f in vuln["FixedIn"]]
        assert "3.0.1271.97-0ubuntu0.12.04.1" in fixed_in_versions


class TestParserEmissionOrder:
    """Policy: legacy first, OSV last. Identifier shapes don't collide so this is informational."""

    def test_legacy_yielded_before_osv(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_normalized(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        with patch.object(p, "_download_archive"):
            ids = [t[0] for t in p.get()]

        first_osv = next(i for i, x in enumerate(ids) if x.startswith("ubuntu-"))
        # any legacy id (ubuntu:X.YY/...) must appear before any fragment id (ubuntu-X.YY-lts/...)
        legacy_indices = [i for i, x in enumerate(ids) if x.startswith("ubuntu:")]
        if legacy_indices:
            assert max(legacy_indices) < first_osv


# ---------------------------------------------------------------------------
# Full Provider.update integration
# ---------------------------------------------------------------------------


class TestProviderUpdate:
    def test_writes_one_envelope_per_ecosystem_cve_pair(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"):
            p.update(None)

        # 4 OSV records sliced across 7 ecosystems = 7 envelopes
        assert ws.num_result_entries() == 7

    def test_writes_per_record_osv_schema(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"):
            p.update(None)

        import json
        schemas = []
        for f in ws.result_files():
            with open(f) as fh:
                schemas.append(json.load(fh)["schema"])
        assert any("/osv/schema-1.7.0.json" in s for s in schemas), schemas
        assert any("/osv/schema-1.6.3.json" in s for s in schemas), schemas

    def test_writes_mixed_schema_with_legacy(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)
        # also stage the normalized-cve-data fixture
        input_path = os.path.join(str(ws.root), "ubuntu", "input")
        shutil.copytree(
            os.path.join(fixture_dir, "normalized-cve-data"),
            os.path.join(input_path, "normalized-cve-data"),
        )

        with patch.object(p.parser, "_download_archive"):
            p.update(None)

        # 7 OSV envelopes + 5 legacy envelopes (CVE-2022-31258 bionic is filtered out by OSV coverage on 18.04)
        # legacy: 2012-5124×2 + 2013-6627×3 = 5
        assert ws.num_result_entries() == 12

        # check mixed-schema output
        import json
        schemas = []
        for f in ws.result_files():
            with open(f) as fh:
                schemas.append(json.load(fh)["schema"])
        assert any("/osv/schema-1.7.0.json" in s for s in schemas), schemas
        assert any("/os/schema-" in s for s in schemas), schemas

    def test_via_snapshot(self, helpers, fixture_dir, fake_fixdate_finder):
        fake_fixdate_finder(responses=[Result(date=datetime.date(2024, 1, 1), kind="first-observed")])

        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)
        # legacy fixture included — snapshot will assert on both OSV + legacy envelopes
        input_path = os.path.join(str(ws.root), "ubuntu", "input")
        shutil.copytree(
            os.path.join(fixture_dir, "normalized-cve-data"),
            os.path.join(input_path, "normalized-cve-data"),
        )

        with patch.object(p.parser, "_download_archive"):
            p.update(None)

        ws.assert_result_snapshots()
