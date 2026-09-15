from __future__ import annotations

import datetime
import logging
import os
import shutil
import tarfile
from unittest.mock import patch

import orjson
import pytest

from vunnel import provider, result, schema, workspace
from vunnel.providers.ubuntu import Config, Provider, eol_calendar
from vunnel.providers.ubuntu.parser import (
    Parser,
    _annotate_wont_fix,
    _build_synthetic_base_affected,
    canonical_ecosystem,
    canonical_slug,
    ecosystem_to_slug,
    pro_to_base_ecosystem,
    release_identity,
    slice_by_ecosystem,
)
from vunnel.providers.ubuntu import vex_cache
from vunnel.providers.ubuntu.os_downconvert import is_cve_program_rejection
from vunnel.providers.ubuntu.vex_overlay import (
    VEXOverlay,
    canonical_token,
    distro_label_from_purl,
    is_wont_fix_action,
    source_package_from_purl,
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
        assert Provider.tags() == ["vulnerability", "os", "large"]
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


def _build_sample_archive(fixture_dir: str, source_subdir: str, archive_prefix: str, dst_path: str) -> None:
    """Build a small tar.xz at dst_path from the loose JSON tree under fixture_dir/source_subdir.

    Binary tar.xz fixtures don't live in the repo — the loose JSON files are
    the source of truth (reviewable diffs, no LFS pressure). Each test builder
    that needs a tarball constructs one on demand. ~5ms for the small fixture
    trees we ship; cheap enough not to bother memoizing.

    archive_prefix is the directory each archive member sits under
    (e.g. "osv" → entries become "osv/cve/<year>/<file>.json"). This matches
    the production layout the parser expects.

    Both files and directories are explicitly sorted: os.walk's directory
    order is filesystem-dependent (ext4 vs APFS vs CI overlayfs all differ),
    and the tarball's member order propagates into SQLite insertion order
    inside fragments. Without sort, tests that read fragments via
    `next(reader.each())` get a different first row on CI vs local.
    """
    src = os.path.join(fixture_dir, source_subdir)
    with tarfile.open(dst_path, mode="w:xz") as tar:
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for fname in sorted(files):
                if not fname.endswith(".json"):
                    continue
                full = os.path.join(root, fname)
                arc = f"{archive_prefix}/" + os.path.relpath(full, src).replace(os.sep, "/")
                tar.add(full, arcname=arc)


def _seed_archive(fresh_workspace, fixture_dir):
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


def _seed_vex_archive(fresh_workspace, fixture_dir):
    _build_sample_archive(
        fixture_dir,
        source_subdir="vex",
        archive_prefix="vex",
        dst_path=os.path.join(fresh_workspace.input_path, "vex-all.tar.xz"),
    )


def _seed_esm_cases_archive(fresh_workspace, fixture_dir):
    # Real Canonical OSV records (netty/unzip/wolfssl) kept in an isolated tree so
    # they exercise the full parser without perturbing the exact-ordering/snapshot
    # tests that read the main osv/ fixtures.
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv-esm-cases",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


@pytest.fixture
def sample_vex_archive(tmp_path, fixture_dir):
    """Build a VEX tar.xz once per test and return its path.

    Used by tests that take a path directly (e.g. VEXOverlay.from_archive)
    rather than seeding it into a workspace.
    """
    out = tmp_path / "sample-vex-all.tar.xz"
    _build_sample_archive(fixture_dir, "vex", "vex", str(out))
    return str(out)


def _fragment_paths(workspace):
    fragments_dir = os.path.join(workspace.input_path, "fragments")
    if not os.path.isdir(fragments_dir):
        return []
    return sorted(os.listdir(fragments_dir))


class TestParserFragmentWriter:
    # Real OSV fixtures in tests/unit/providers/ubuntu/test-fixtures/osv:
    #   UBUNTU-CVE-2013-2208   (1.7.0, fixed events, withdrawn) -> Ubuntu:14.04:LTS
    #   UBUNTU-CVE-2016-20013  (1.7.0, no fixed events)         -> 10 ecosystems
    #                                                              (used for VEX wont-fix tests)
    #   UBUNTU-CVE-2020-36325  (1.6.3, withdrawn)               -> Ubuntu:Pro:14.04:LTS
    #   UBUNTU-CVE-2021-3782   (1.7.0)                          -> 4 ecosystems
    #   UBUNTU-CVE-2026-1403   (1.7.0)                          -> Ubuntu:16.04:LTS

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
            "ubuntu-24.04-lts.db",
            "ubuntu-pro-14.04-lts.db",
            "ubuntu-pro-16.04-lts.db",
            "ubuntu-pro-18.04-lts.db",
            "ubuntu-pro-20.04-lts.db",
        ]

    def test_fragment_envelope_identifier_is_eco_slug_prefixed(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        # ubuntu-24.04-lts has only CVE-2016-20013 in our fixture set
        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-24.04-lts.db")
        with result.SQLiteReader(path) as reader:
            ids = [e.identifier for e in reader.each()]
        assert ids == ["ubuntu-24.04-lts/ubuntu-cve-2016-20013"]

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

        # UBUNTU-CVE-2020-36325 declares schema_version 1.6.3 in Canonical's feed.
        # ubuntu-pro-14.04-lts.db contains both CVE-2016-20013 (1.7.0) and CVE-2020-36325
        # (1.6.3); look up by identifier rather than picking the first row, since
        # SQLite insertion order depends on tarball member order which is filesystem-dependent.
        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-pro-14.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2020-36325" in e.identifier)
        assert env.schema.endswith("/osv/schema-1.6.3.json")

    def test_fragment_preserves_withdrawn_field(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2020-36325 has withdrawn="2025-06-23T15:53:49Z" — the slice must carry it
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-pro-14.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2020-36325" in e.identifier)
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


class TestParserFixDateDeferredToYield:
    """patch_fix_date is applied at yield time, not write time.

    This lets frozen fragments pick up fixdater improvements on every run
    without rewriting the cache.
    """

    def test_fragment_on_disk_has_no_anchore_data(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Even with a fixdater that would happily return a date, the cached
        # fragment payload must NOT have database_specific.anchore — patching
        # happens at yield time only.
        fake_fixdate_finder(
            responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
        )
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-14.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2013-2208" in e.identifier)
        for r in env.item["affected"][0]["ranges"]:
            assert "anchore" not in r.get("database_specific", {}), "fragment payload should be raw OSV record, no fix-date patching at write time"

    def test_yielded_record_has_anchore_when_fixed_event_present(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # On yield, patch_fix_date runs and populates database_specific.anchore
        # for records that have `fixed:` events.
        fake_fixdate_finder(
            responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
        )
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        # CVE-2013-2208 has a real `fixed: 1.3.1-3` event
        payload = yielded["ubuntu-14.04-lts/ubuntu-cve-2013-2208"]
        anchore = payload["affected"][0]["ranges"][0]["database_specific"]["anchore"]
        assert any(fix["date"] == "2013-07-15" and fix["version"] == "1.3.1-3" for fix in anchore["fixes"])

    def test_fixdater_keyed_by_upstream_cve_not_ubuntu_cve(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Regression test: the OSV record's `id` is `UBUNTU-CVE-*` (Canonical's internal
        # key), but the fix-date cache keys by the upstream `CVE-*`. The parser must look
        # up using the upstream CVE id or every fixdater hit silently misses.
        #
        # Configure the fake finder with a dict keyed by the upstream CVE only. If the
        # parser uses the UBUNTU-CVE id, the lookup falls through and no anchore.fixes
        # gets written; if it uses the upstream, the lookup hits.
        fake_fixdate_finder(
            responses={
                "CVE-2013-2208": [Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
            }
        )
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        payload = yielded["ubuntu-14.04-lts/ubuntu-cve-2013-2208"]
        anchore = payload["affected"][0]["ranges"][0]["database_specific"]["anchore"]
        assert any(fix["date"] == "2013-07-15" and fix["version"] == "1.3.1-3" for fix in anchore["fixes"]), (
            "fixdater lookup must use upstream CVE id (CVE-2013-2208), not the OSV record id "
            "(UBUNTU-CVE-2013-2208); otherwise every fix-date lookup silently misses"
        )

    def test_yielded_record_no_anchore_when_no_fixed_event(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        # 2026-1403 and 2012-5855 have only {"introduced": "0"} — patch_fix_date is a no-op
        for ident in ("ubuntu-16.04-lts/ubuntu-cve-2026-1403", "ubuntu-pro-14.04-lts/ubuntu-cve-2012-5855"):
            payload = yielded[ident]
            for r in payload["affected"][0]["ranges"]:
                assert "anchore" not in r.get("database_specific", {})

    def test_frozen_fragment_picks_up_todays_fixdater(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # The headline win of this design: a fragment written before with stale
        # (or no) fixdater info should pick up today's fixdater on the next yield.
        _seed_archive(fresh_workspace, fixture_dir)

        # First pass: a fixdater that returns nothing — fragments get written but
        # no anchore data is computed at write time anyway.
        empty = fake_fixdate_finder(responses=[])
        p1 = Parser(workspace=fresh_workspace, fixdater=empty)
        p1._write_fragments()

        # Second pass: same fragments on disk, but yield with a populated fixdater.
        good = fake_fixdate_finder(
            responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
        )
        p2 = Parser(workspace=fresh_workspace, fixdater=good)
        yielded = {t[0]: t[2] for t in p2._iter_fragments()}
        payload = yielded["ubuntu-14.04-lts/ubuntu-cve-2013-2208"]
        anchore = payload["affected"][0]["ranges"][0]["database_specific"]["anchore"]
        assert any(fix["date"] == "2013-07-15" for fix in anchore["fixes"])


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


class TestParserDownload:
    def test_download_streams_to_archive_path(self, fresh_workspace, fixture_dir, tmp_path, auto_fake_fixdate_finder):
        sample = tmp_path / "sample-osv-all.tar.xz"
        _build_sample_archive(fixture_dir, "osv", "osv", str(sample))
        with open(sample, "rb") as f:
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
        # 17 real (CVE, ecosystem) envelopes + 2 inferred from Pro-only-fix sources:
        #   2012-5855 has only Ubuntu:Pro:14.04:LTS (vlc) → synthesize base 14.04/vlc
        #   2021-3782 has Ubuntu:Pro:16.04:LTS (wayland) but no base 16.04 for wayland in any
        #     fixture record → synthesize base 16.04/wayland (the existing 16.04 entry from
        #     CVE-2026-1403 is for gitlab, different package → doesn't suppress)
        # UBUNTU-CVE-2020-36325 is in the fixture set and appears nowhere here: its
        # details open `** DISPUTED **`, so the CVE program has retracted it.
        assert ids == [
            "ubuntu-14.04-lts/ubuntu-cve-2012-5855",  # ← inferred from Pro:14.04/vlc
            "ubuntu-14.04-lts/ubuntu-cve-2013-2208",
            "ubuntu-14.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-16.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-16.04-lts/ubuntu-cve-2021-3782",  # ← inferred from Pro:16.04/wayland
            "ubuntu-16.04-lts/ubuntu-cve-2026-1403",
            "ubuntu-18.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-18.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-20.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-20.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-22.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-22.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-24.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-pro-14.04-lts/ubuntu-cve-2012-5855",
            "ubuntu-pro-14.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-pro-16.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-pro-16.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-pro-18.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-pro-20.04-lts/ubuntu-cve-2016-20013",
        ]

    def test_iter_fragments_yields_correct_schema_per_record(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        by_id = {t[0]: t[1] for t in p._iter_fragments()}
        # 2012-5855 declares 1.6.3 (real Canonical record); the others declare 1.7.0
        assert by_id["ubuntu-pro-14.04-lts/ubuntu-cve-2012-5855"].url.endswith("/osv/schema-1.6.3.json")
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
    _build_sample_archive(fixture_dir, "osv", "osv", os.path.join(input_path, "osv-all.tar.xz"))


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

    def test_fixdater_not_queried_for_osv_covered_namespaces(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Count fixdater queries via a callable response. With a fragment for 18.04
        # present, the bionic legacy record (CVE-2022-31258) should never reach map_parsed
        # — so fixdater should be called zero times for it.
        calls = []

        def counting_responses(vuln_id, cpe_or_package, fix_version, ecosystem):
            calls.append((vuln_id, cpe_or_package, ecosystem))
            return []

        fake_fixdate_finder(responses=counting_responses)
        _seed_normalized(fresh_workspace, fixture_dir)
        # plant a fragment for 18.04
        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        os.makedirs(fragments_dir)
        open(os.path.join(fragments_dir, "ubuntu-18.04-lts.db"), "wb").close()

        p = Parser(workspace=fresh_workspace)
        list(p._iter_normalized_cve_data())

        # No fixdater call should reference CVE-2022-31258 (its only namespace is OSV-covered)
        bionic_filtered_calls = [c for c in calls if c[0] == "CVE-2022-31258"]
        assert bionic_filtered_calls == [], f"expected zero fixdater calls for OSV-covered CVE-2022-31258, got {bionic_filtered_calls}"
        # And calls for the EOL namespaces DO happen
        assert any(c[0] == "CVE-2012-5124" for c in calls)
        assert any(c[0] == "CVE-2013-6627" for c in calls)


class TestParserEmissionOrder:
    """Policy: legacy first, OSV last. Identifier shapes don't collide so this is informational."""

    def test_legacy_yielded_before_osv(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)
        _seed_normalized(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
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
        c.downconvert_osv_to_os = False

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"), _patch_calendar_download(p.parser, fixture_dir):
            p.update(None)

        # 17 real OSV envelopes + 2 inferred-from-Pro base envelopes
        # (Pro:14.04/vlc → base 14.04; Pro:16.04/wayland → base 16.04). See
        # test_iter_fragments_yields_envelopes_from_every_db_file for the breakdown.
        # UBUNTU-CVE-2020-36325 is in the fixture set and in neither count: its
        # details open `** DISPUTED **`, so it is a CVE-program rejection.
        assert ws.num_result_entries() == 19

    def test_writes_per_record_osv_schema(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.downconvert_osv_to_os = False

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"), _patch_calendar_download(p.parser, fixture_dir):
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
        c.downconvert_osv_to_os = False

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)
        # also stage the normalized-cve-data fixture
        input_path = os.path.join(str(ws.root), "ubuntu", "input")
        shutil.copytree(
            os.path.join(fixture_dir, "normalized-cve-data"),
            os.path.join(input_path, "normalized-cve-data"),
        )

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"), _patch_calendar_download(p.parser, fixture_dir):
            p.update(None)

        # 17 real OSV + 2 inferred-from-Pro base envelopes + 5 legacy envelopes
        # + 1 from the tracker snapshot, with the `** DISPUTED **`
        # UBUNTU-CVE-2020-36325 and its inference in none of them.
        # Legacy: 2012-5124×2 + 2013-6627×3 = 5. The passthrough still skips
        # CVE-2022-31258 on bionic because 18.04 has an OSV fragment, and the
        # snapshot now states it there instead: `not-affected` for check-mk,
        # which neither feed mentions, is the 25th.
        assert ws.num_result_entries() == 25

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
        c.downconvert_osv_to_os = False

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)
        input_path = os.path.join(str(ws.root), "ubuntu", "input")
        # legacy fixture
        shutil.copytree(
            os.path.join(fixture_dir, "normalized-cve-data"),
            os.path.join(input_path, "normalized-cve-data"),
        )
        # VEX fixture so wont-fix annotations bake into the snapshots
        _build_sample_archive(fixture_dir, "vex", "vex", os.path.join(input_path, "vex-all.tar.xz"))

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"), _patch_calendar_download(p.parser, fixture_dir):
            p.update(None)

        ws.assert_result_snapshots()


# ---------------------------------------------------------------------------
# VEX overlay — wont-fix annotation from Canonical's OpenVEX feed
# ---------------------------------------------------------------------------


class TestVEXHelpers:
    """Pure-function tests for the VEX module."""

    def test_distro_label_from_purl(self):
        assert (
            distro_label_from_purl(
                "pkg:deb/ubuntu/glibc@2.39-0ubuntu8.7?arch=source&distro=noble",
            )
            == "noble"
        )
        # ESM/Pro channels use compound distro labels
        assert (
            distro_label_from_purl(
                "pkg:deb/ubuntu/eglibc@2.19-0ubuntu6.15+esm4?arch=source&distro=esm-infra-legacy/trusty",
            )
            == "esm-infra-legacy/trusty"
        )
        # No distro qualifier → None
        assert distro_label_from_purl("pkg:deb/ubuntu/foo@1.0") is None
        assert distro_label_from_purl("") is None

    def test_source_package_from_purl(self):
        assert (
            source_package_from_purl(
                "pkg:deb/ubuntu/glibc@2.39-0ubuntu8.7?arch=source&distro=noble",
            )
            == "glibc"
        )
        assert source_package_from_purl("not-a-purl") is None
        assert source_package_from_purl("") is None

    def test_is_wont_fix_action_matches_both_canonical_openings(self):
        decided = (
            "This package (for the given release) is vulnerable to the CVE, "
            "the problem is understood, but the Ubuntu Security Team decided "
            "to not fix it. CVE Notes: ..."
        )
        assert is_wont_fix_action(decided) is True

        no_longer_supported = "This package (for the given release) is no longer supported. CVE Notes: ..."
        assert is_wont_fix_action(no_longer_supported) is True

    def test_is_wont_fix_action_rejects_needs_fixing(self):
        assert (
            is_wont_fix_action(
                "This package (for the given release) is vulnerable to the CVE and needs fixing.",
            )
            is False
        )
        assert (
            is_wont_fix_action(
                "This package (for the given release) is vulnerable to the CVE, needs fixing, and it is being actively worked on.",
            )
            is False
        )
        assert is_wont_fix_action(None) is False
        assert is_wont_fix_action("") is False
        assert is_wont_fix_action("some random text") is False


class TestVEXOverlay:
    """End-to-end index-from-fragments tests using the real-record fixture."""

    def test_indexes_wont_fix_entries(self, fresh_workspace, fixture_dir):
        overlay = _vex_index(fresh_workspace, fixture_dir)
        # CVE-2016-20013 is marked won't-fix on every release where Canonical's UCT
        # used status: "ignored". The fixture has the real record verbatim — every
        # (noble, jammy, focal, etc.) × (glibc, syslinux, dietlibc, sssd, zabbix) tuple
        # that's `ignored` upstream should be present.
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "glibc") is True
        assert overlay.is_wont_fix("CVE-2016-20013", "jammy", "glibc") is True
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "syslinux") is True
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "dietlibc") is True

    def test_does_not_index_needs_fixing_entries(self, fresh_workspace, fixture_dir):
        overlay = _vex_index(fresh_workspace, fixture_dir)
        # CVE-2023-38545 (curl) has status "affected" but action_statement "needs fixing"
        # on jammy and noble — Canonical will ship a fix. Should NOT be indexed as wont-fix.
        assert overlay.is_wont_fix("CVE-2023-38545", "jammy", "curl") is False
        assert overlay.is_wont_fix("CVE-2023-38545", "noble", "curl") is False

    def test_unknown_lookups_return_false(self, fresh_workspace, fixture_dir):
        overlay = _vex_index(fresh_workspace, fixture_dir)
        assert overlay.is_wont_fix("CVE-9999-9999", "noble", "glibc") is False
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "no-such-pkg") is False
        # right CVE/pkg, but a release Canonical doesn't cover anymore
        assert overlay.is_wont_fix("CVE-2016-20013", "natty", "glibc") is False

    def test_empty_overlay_is_safely_queryable(self):
        # An index built from a workspace with no VEX fragments should not blow up
        overlay = VEXOverlay()
        assert overlay.is_wont_fix("any", "any", "any") is False
        assert overlay.is_not_affected("any", "any", "any") is False
        assert len(overlay) == 0


class TestAnnotateWontFix:
    """The slicing-time helper that stamps wont-fix onto matching slices."""

    def _record(self):
        # Minimal OSV record fragment with two ecosystem slices.
        return {
            "id": "UBUNTU-CVE-2016-20013",
            "upstream": ["CVE-2016-20013"],
            "affected": [
                {
                    "package": {
                        "ecosystem": "Ubuntu:24.04:LTS",
                        "name": "glibc",
                        "purl": "pkg:deb/ubuntu/glibc@2.39?arch=source&distro=noble",
                    },
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                },
                {
                    "package": {
                        "ecosystem": "Ubuntu:24.04:LTS",
                        "name": "needs-fixing-pkg",
                        "purl": "pkg:deb/ubuntu/needs-fixing-pkg@1.0?arch=source&distro=noble",
                    },
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                },
            ],
        }

    def test_annotates_only_wont_fix_packages(self, fresh_workspace, fixture_dir):
        overlay = _vex_index(fresh_workspace, fixture_dir)
        rec = self._record()
        sliced = slice_by_ecosystem(rec)
        _annotate_wont_fix(sliced, rec, overlay)

        # One slice for Ubuntu:24.04:LTS containing both packages
        slice24 = sliced["Ubuntu:24.04:LTS"]
        glibc = next(a for a in slice24["affected"] if a["package"]["name"] == "glibc")
        other = next(a for a in slice24["affected"] if a["package"]["name"] == "needs-fixing-pkg")

        # glibc is in VEX as wont-fix → annotated
        assert glibc["database_specific"]["anchore"]["status"] == "wont-fix"
        # the other package isn't in VEX → no annotation
        assert "database_specific" not in other or "anchore" not in other.get("database_specific", {})

    def test_no_upstream_means_no_annotation(self, fresh_workspace, fixture_dir):
        overlay = _vex_index(fresh_workspace, fixture_dir)
        rec = self._record()
        rec["upstream"] = []  # without an upstream CVE we have no join key
        sliced = slice_by_ecosystem(rec)
        _annotate_wont_fix(sliced, rec, overlay)

        for slice_payload in sliced.values():
            for aff in slice_payload["affected"]:
                assert "database_specific" not in aff or "anchore" not in aff.get("database_specific", {})

    def test_preserves_other_database_specific_keys(self, fresh_workspace, fixture_dir):
        overlay = _vex_index(fresh_workspace, fixture_dir)
        rec = self._record()
        # pre-existing database_specific data on glibc should be preserved
        rec["affected"][0]["database_specific"] = {"anchore": {"other_key": "stays"}, "vendor": "x"}
        sliced = slice_by_ecosystem(rec)
        _annotate_wont_fix(sliced, rec, overlay)

        glibc = next(a for a in sliced["Ubuntu:24.04:LTS"]["affected"] if a["package"]["name"] == "glibc")
        assert glibc["database_specific"]["anchore"] == {"other_key": "stays", "status": "wont-fix"}
        assert glibc["database_specific"]["vendor"] == "x"


class TestParserVEXIntegration:
    """Judge-at-emit-time semantics: the fragment on disk carries no disposition."""

    def test_wont_fix_is_labelled_at_emit_and_not_on_disk(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        p.vex_store.write(os.path.join(fresh_workspace.input_path, "vex-all.tar.xz"), calendar=None, now=_utc("2026-09-10T00:00:00+00:00"))
        p._vex_overlay = p._load_vex_overlay()

        # the fragment on disk is the raw OSV record, as it is for fix dates
        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-24.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2016-20013" in e.identifier)
        for aff in env.item["affected"]:
            assert "anchore" not in (aff.get("database_specific") or {})

        # CVE-2016-20013 / noble / glibc — Canonical's "ignored" case
        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        glibc = next(a for a in yielded["ubuntu-24.04-lts/ubuntu-cve-2016-20013"]["affected"] if a["package"]["name"] == "glibc")
        assert glibc["database_specific"]["anchore"]["status"] == "wont-fix"

    def test_no_vex_cache_means_no_annotations(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Without any VEX fragments the run proceeds and emits raw records
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        p._vex_overlay = p._load_vex_overlay()
        assert len(p._vex_overlay) == 0

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        for aff in yielded["ubuntu-24.04-lts/ubuntu-cve-2016-20013"]["affected"]:
            assert "anchore" not in (aff.get("database_specific") or {})

    def test_label_baked_in_by_an_earlier_build_survives(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Every fragment frozen on the first run under the calendar rule was
        # written by the old code, which stamped the label into the payload. The
        # yield path adds labels and never removes one, so those keep theirs even
        # with no VEX fragment for the release.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-2026-7246",
            {
                "id": "UBUNTU-CVE-2026-7246",
                "upstream": ["CVE-2026-7246"],
                "affected": [
                    {
                        "package": {"ecosystem": "Ubuntu:25.10", "name": "python-click", "purl": "pkg:deb/ubuntu/python-click@8.2?arch=source&distro=questing"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                        "database_specific": {"anchore": {"status": "wont-fix"}},
                    },
                ],
            },
        )

        p = Parser(workspace=fresh_workspace)
        p._vex_overlay = p._load_vex_overlay()
        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        payload = yielded["ubuntu-25.10/ubuntu-cve-2026-7246"]
        assert payload["affected"][0]["database_specific"]["anchore"]["status"] == "wont-fix"


# ---------------------------------------------------------------------------
# Pro-only-fix → base wont-fix inference
# ---------------------------------------------------------------------------


class TestProToBaseEcosystem:
    """Pure-function tests for pro_to_base_ecosystem.

    The function deliberately restricts to plain ESM-tier Pro
    (Ubuntu:Pro:<version>[:LTS]). FIPS / FIPS-updates / FIPS-preview /
    Realtime / Nvidia-BlueField are all rejected because they ship
    *different builds* whose vulnerable code paths may diverge from base.
    See the function docstring for the full rationale.
    """

    def test_plain_pro_with_lts_suffix(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:20.04:LTS") == "Ubuntu:20.04:LTS"

    def test_plain_pro_oldest_esm_release(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:14.04:LTS") == "Ubuntu:14.04:LTS"

    def test_plain_pro_without_lts_suffix(self):
        # Pro variants of non-LTS releases are uncommon but the parsing should
        # still produce the matching base form.
        assert pro_to_base_ecosystem("Ubuntu:Pro:25.10") == "Ubuntu:25.10"

    def test_fips_rejected(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:FIPS:20.04:LTS") is None
        assert pro_to_base_ecosystem("Ubuntu:Pro:FIPS-updates:22.04:LTS") is None
        assert pro_to_base_ecosystem("Ubuntu:Pro:FIPS-preview:22.04:LTS") is None

    def test_realtime_rejected(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:Realtime:24.04:LTS") is None
        # Six-segment Realtime kernel variant observed in real data
        assert pro_to_base_ecosystem("Ubuntu:Pro:22.04:LTS:Realtime:Kernel") is None

    def test_nvidia_bluefield_rejected(self):
        # Different product line, not an ESM continuation of base
        assert pro_to_base_ecosystem("Ubuntu:Nvidia-BlueField:22.04:LTS") is None

    def test_already_base_returns_none(self):
        assert pro_to_base_ecosystem("Ubuntu:20.04:LTS") is None
        assert pro_to_base_ecosystem("Ubuntu:25.10") is None
        assert pro_to_base_ecosystem("Ubuntu:26.04:LTS") is None

    def test_malformed_inputs_return_none(self):
        assert pro_to_base_ecosystem("") is None
        assert pro_to_base_ecosystem("Ubuntu") is None
        assert pro_to_base_ecosystem("Ubuntu:Pro") is None
        assert pro_to_base_ecosystem("Ubuntu:Pro:notaversion:LTS") is None
        assert pro_to_base_ecosystem("Debian:Pro:20.04:LTS") is None  # wrong distro
        # An LTS suffix variant we don't expect — be strict, not lenient
        assert pro_to_base_ecosystem("Ubuntu:Pro:20.04:WEIRD") is None


class TestSyntheticBaseAffectedBuilder:
    """Tests for _build_synthetic_base_affected — the per-affected-entry synthesizer."""

    def _template(self, name="glibc", purl=True, binaries=True):
        eco_spec = {"binaries": [{"binary_name": "libc6", "binary_version": "x"}]} if binaries else {}
        pkg = {"ecosystem": "Ubuntu:Pro:20.04:LTS", "name": name}
        if purl:
            pkg["purl"] = "pkg:deb/ubuntu/glibc@2.31?arch=source&distro=esm-infra/focal"
        return {
            "package": pkg,
            "ecosystem_specific": eco_spec,
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31+esm1"}]},
            ],
        }

    def test_rebases_ecosystem(self):
        out = _build_synthetic_base_affected(self._template(), "Ubuntu:20.04:LTS")
        assert out["package"]["ecosystem"] == "Ubuntu:20.04:LTS"
        assert out["package"]["name"] == "glibc"

    def test_drops_pro_purl(self):
        # The Pro purl's distro qualifier (e.g. distro=esm-infra/focal) doesn't
        # apply to base 20.04 — we don't want to fabricate a misleading qualifier.
        out = _build_synthetic_base_affected(self._template(), "Ubuntu:20.04:LTS")
        assert "purl" not in out["package"]

    def test_preserves_binaries(self):
        # Pro ESM binaries are byte-identical to base while base is supported;
        # carrying them lets binary→source resolution still work for scans.
        out = _build_synthetic_base_affected(self._template(), "Ubuntu:20.04:LTS")
        assert out["ecosystem_specific"]["binaries"] == [
            {"binary_name": "libc6", "binary_version": "x"},
        ]

    def test_replaces_ranges_with_no_fix_sentinel(self):
        # Synthesized base entries are always "vulnerable, no fix shipped on base"
        # — even if Pro had a fixed event. The Pro fix doesn't apply to base.
        out = _build_synthetic_base_affected(self._template(), "Ubuntu:20.04:LTS")
        assert out["ranges"] == [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]},
        ]

    def test_emits_wont_fix_status_without_inference_provenance_key(self):
        # The wont-fix status lives directly on database_specific.anchore; the
        # inference.source_ecosystems provenance is added by the caller because
        # it depends on cross-fragment context the builder doesn't know.
        out = _build_synthetic_base_affected(self._template(), "Ubuntu:20.04:LTS")
        anchore = out["database_specific"]["anchore"]
        assert anchore["status"] == "wont-fix"
        assert "inference" not in anchore


class TestProOnlyInferenceIntegration:
    """End-to-end: write fragments from sample tarball, yield, assert inferred entries materialize."""

    def test_pro_only_record_synthesizes_base_envelope(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2012-5855 has ONLY Ubuntu:Pro:14.04:LTS / vlc in its affected[].
        # The base Ubuntu:14.04:LTS record has no entry for vlc in any fixture.
        # Inference should produce a synthetic base 14.04 envelope.
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        yielded = {t[0]: t[2] for t in p._iter_fragments()}

        synth = yielded.get("ubuntu-14.04-lts/ubuntu-cve-2012-5855")
        assert synth is not None, "expected synthetic base 14.04 envelope for CVE-2012-5855"
        affs = synth["affected"]
        assert len(affs) == 1
        vlc = affs[0]
        assert vlc["package"]["ecosystem"] == "Ubuntu:14.04:LTS"
        assert vlc["package"]["name"] == "vlc"
        assert "purl" not in vlc["package"]
        assert vlc["ranges"] == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
        anchore = vlc["database_specific"]["anchore"]
        assert anchore["status"] == "wont-fix"
        assert anchore["inference"] == {
            "kind": "pro-only-fix",
            "source_ecosystems": ["Ubuntu:Pro:14.04:LTS"],
        }

    def test_inferred_entries_merge_into_existing_base_envelope(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2016-20013 has base 14.04 / syslinux (real) AND Pro:14.04 / eglibc, zabbix.
        # The yielded base 14.04 envelope must contain BOTH real and inferred packages —
        # synthesizing a separate envelope would collide on identifier and overwrite the real one.
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        yielded = {t[0]: t[2] for t in p._iter_fragments()}

        payload = yielded["ubuntu-14.04-lts/ubuntu-cve-2016-20013"]
        by_name = {a["package"]["name"]: a for a in payload["affected"]}
        assert "syslinux" in by_name, "real base entry must survive"
        assert "eglibc" in by_name, "inferred entry from Pro:14.04/eglibc must be added"
        assert "zabbix" in by_name, "inferred entry from Pro:14.04/zabbix must be added"

        # Real syslinux entry has NO inference key — and may not have database_specific
        # at all if neither VEX nor fixdate annotated it.
        assert "inference" not in by_name["syslinux"].get("database_specific", {}).get("anchore", {})
        # Inferred eglibc DOES carry provenance
        assert by_name["eglibc"]["database_specific"]["anchore"]["inference"]["kind"] == "pro-only-fix"
        assert by_name["eglibc"]["database_specific"]["anchore"]["inference"]["source_ecosystems"] == [
            "Ubuntu:Pro:14.04:LTS",
        ]

    def test_base_present_for_same_package_suppresses_synthesis(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2021-3782 has both Ubuntu:18.04:LTS / wayland (real) and
        # Ubuntu:Pro:16.04:LTS / wayland (Pro). Base 18.04/wayland is already in
        # the record, so we must NOT synthesize a base entry that overrides it.
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        yielded = {t[0]: t[2] for t in p._iter_fragments()}

        # base 18.04 entry has the original Pro:16.04 → base 16.04 inference,
        # but base 18.04's own wayland entry is REAL — keep its fix event intact.
        payload = yielded["ubuntu-18.04-lts/ubuntu-cve-2021-3782"]
        wayland = next(a for a in payload["affected"] if a["package"]["name"] == "wayland")
        # Real entries have fix events; synthesized entries always have just introduced=0.
        events = [list(e.keys())[0] for r in wayland["ranges"] for e in r["events"]]
        assert "fixed" in events, "real base 18.04/wayland entry must keep its fixed event"
        # Real entries may not have database_specific at all if no VEX/fixdate annotations apply.
        assert "inference" not in wayland.get("database_specific", {}).get("anchore", {})

    def test_sub_tier_fragments_do_not_trigger_inference(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # No FIPS/Realtime/BlueField in our fixtures, so this is a structural check:
        # iterate fragments after a write and assert none of the synthesized base
        # entries reference a Pro:FIPS / Pro:Realtime / Nvidia-BlueField source.
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        forbidden_sources = ("FIPS", "Realtime", "Nvidia-BlueField")
        for _ident, _sch, payload in p._iter_fragments():
            for aff in payload.get("affected", []):
                inf = aff.get("database_specific", {}).get("anchore", {}).get("inference")
                if not inf:
                    continue
                for src in inf.get("source_ecosystems", []):
                    for marker in forbidden_sources:
                        assert marker not in src, f"inference fired off a sub-tier source ({src}); pro_to_base_ecosystem should have excluded this"

    def test_inference_survives_frozen_base_fragment(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Headline post-EOL scenario: imagine base 14.04 dropped from OSV but Pro:14.04
        # is still tracked. We simulate by writing fragments from today's fixture
        # (which has both base 14.04 and Pro:14.04), then deleting the base fragment
        # to mimic "base wasn't refreshed this run." Pro siblings should still produce
        # inferred base entries on yield.
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        base_fragment = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-14.04-lts.db")
        assert os.path.exists(base_fragment)
        os.remove(base_fragment)

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        # Inferred entries still come through from Pro:14.04 — base fragment isn't needed.
        synth = yielded.get("ubuntu-14.04-lts/ubuntu-cve-2012-5855")
        assert synth is not None, "inference must still fire when base fragment is absent"
        anchore = synth["affected"][0]["database_specific"]["anchore"]
        assert anchore["status"] == "wont-fix"
        assert anchore["inference"]["source_ecosystems"] == ["Ubuntu:Pro:14.04:LTS"]


# ---------------------------------------------------------------------------
# USN fix-date overlay — authoritative fix-ship dates from USN.published
# ---------------------------------------------------------------------------


class TestUSNFixDateOverlay:
    """Pure tests for the overlay class + ISO-date parsing."""

    def test_lookup_returns_usn_publish_date(self, fixture_dir, tmp_path):
        from vunnel.providers.ubuntu.usn_fixdate_overlay import USNFixDateOverlay
        import datetime as _dt

        archive = tmp_path / "sample-osv-all.tar.xz"
        _build_sample_archive(fixture_dir, "osv", "osv", str(archive))
        overlay = USNFixDateOverlay.from_archive(str(archive))

        # USN-5614-1 fixture covers wayland on 18.04/20.04/22.04, published 2022-09-15.
        # See tests/unit/providers/ubuntu/test-fixtures/osv/usn/USN-5614-1.json.
        assert overlay.lookup("Ubuntu:18.04:LTS", "wayland", "1.16.0-1ubuntu1.1~18.04.4") == _dt.date(2022, 9, 15)
        assert overlay.lookup("Ubuntu:20.04:LTS", "wayland", "1.18.0-1ubuntu0.1") == _dt.date(2022, 9, 15)
        assert overlay.lookup("Ubuntu:22.04:LTS", "wayland", "1.20.0-1ubuntu0.1") == _dt.date(2022, 9, 15)

    def test_lookup_misses_return_none(self, fixture_dir, tmp_path):
        from vunnel.providers.ubuntu.usn_fixdate_overlay import USNFixDateOverlay

        archive = tmp_path / "sample-osv-all.tar.xz"
        _build_sample_archive(fixture_dir, "osv", "osv", str(archive))
        overlay = USNFixDateOverlay.from_archive(str(archive))

        # tuples that don't exist in any USN in the fixture
        assert overlay.lookup("Ubuntu:18.04:LTS", "wayland", "9.9.9-bogus") is None
        assert overlay.lookup("Ubuntu:18.04:LTS", "nonexistent", "1.0") is None
        assert overlay.lookup("Ubuntu:99.99:LTS", "wayland", "1.16.0-1ubuntu1.1~18.04.4") is None

    def test_empty_overlay_lookups_return_none(self):
        from vunnel.providers.ubuntu.usn_fixdate_overlay import USNFixDateOverlay

        overlay = USNFixDateOverlay()
        assert overlay.lookup("any", "any", "any") is None
        assert len(overlay) == 0

    def test_iso_date_parsing(self):
        from vunnel.providers.ubuntu.usn_fixdate_overlay import _parse_iso_date
        import datetime as _dt

        # Real USN timestamp shapes we observed in the live feed
        assert _parse_iso_date("2023-10-11T11:34:51Z") == _dt.date(2023, 10, 11)
        assert _parse_iso_date("2023-10-17T11:22:48.353678Z") == _dt.date(2023, 10, 17)
        assert _parse_iso_date("2014-12-24T18:59:00Z") == _dt.date(2014, 12, 24)
        # Date-only form (defensive — not observed in real data, but parses correctly)
        assert _parse_iso_date("2023-10-11") == _dt.date(2023, 10, 11)
        # Garbage returns None — caller treats as "no USN date" and falls through
        assert _parse_iso_date("not a date") is None
        assert _parse_iso_date("") is None


class TestUSNOverlayIntegration:
    """End-to-end: USN overlay's authoritative date beats other fixdater sources."""

    def test_usn_date_overrides_first_observed(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Set up a first-observed finder that would return 2024-01-01 for everything
        # (the "wrong day — we just turned on Pro and grype-db is recording today"
        # failure mode the overlay was built to prevent).
        fake_fixdate_finder(
            responses=[Result(date=datetime.date(2024, 1, 1), kind="first-observed", accurate=True)],
        )
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        # _iter_fragments reads self._usn_overlay; populate it as get() would
        from vunnel.providers.ubuntu.usn_fixdate_overlay import USNFixDateOverlay

        p._usn_overlay = USNFixDateOverlay.from_archive(p.archive_path)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        # CVE-2021-3782 / wayland on 18.04 has a real USN (USN-5614-1) published 2022-09-15.
        # That should beat the first-observed mock's 2024-01-01.
        payload = yielded["ubuntu-18.04-lts/ubuntu-cve-2021-3782"]
        wayland = next(a for a in payload["affected"] if a["package"]["name"] == "wayland")
        fixes = wayland["ranges"][0]["database_specific"]["anchore"]["fixes"]
        usn_fix = next(f for f in fixes if f["version"] == "1.16.0-1ubuntu1.1~18.04.4")
        assert usn_fix["date"] == "2022-09-15", (
            f"USN-published date (2022-09-15) should override first-observed mock (2024-01-01); got {usn_fix['date']}"
        )

    def test_falls_back_to_first_observed_when_usn_missing(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # First-observed mock with a date EARLIER than CVE.published (2013-10-28) so it
        # beats the CVE.published fallback candidate in fixdater.best()'s ranking. Without
        # this, the test would pass for the wrong reason (CVE.published is the actual
        # earliest accurate candidate present and would win).
        fake_fixdate_finder(
            responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
        )
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        # CVE-2013-2208 fixes tpp@1.3.1-3 on Ubuntu:14.04:LTS; no USN in our fixture
        # ships that tuple, so the overlay lookup misses and the fixdater fallback applies.
        from vunnel.providers.ubuntu.usn_fixdate_overlay import USNFixDateOverlay

        p._usn_overlay = USNFixDateOverlay.from_archive(p.archive_path)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        payload = yielded["ubuntu-14.04-lts/ubuntu-cve-2013-2208"]
        fixes = payload["affected"][0]["ranges"][0]["database_specific"]["anchore"]["fixes"]
        tpp_fix = next(f for f in fixes if f["version"] == "1.3.1-3")
        assert tpp_fix["date"] == "2013-07-15", f"missing USN tuple should fall through to first-observed mock; got {tpp_fix['date']}"
        # And not carrying any USN advisory provenance.
        assert tpp_fix["kind"] == "first-observed"

    def test_missing_archive_disables_overlay_gracefully(self, fresh_workspace, auto_fake_fixdate_finder):
        # No tarball staged — _load_usn_overlay logs a warning and returns None.
        p = Parser(workspace=fresh_workspace)
        overlay = p._load_usn_overlay()
        assert overlay is None


# ---------------------------------------------------------------------------
# OSV → OS downconverter — opt-in compatibility path for grype-db builds
# that pre-date the OSV transformer
# ---------------------------------------------------------------------------


class TestOSDowncoverterHelpers:
    """Pure-function tests for the OSV→OS mapping primitives."""

    def test_base_ecosystem_to_namespace(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_ecosystem_to_os_namespace

        assert osv_ecosystem_to_os_namespace("Ubuntu:22.04:LTS") == "ubuntu:22.04"
        assert osv_ecosystem_to_os_namespace("Ubuntu:24.04:LTS") == "ubuntu:24.04"
        # non-LTS releases carry no `:LTS` suffix (real spellings seen in the feed).
        assert osv_ecosystem_to_os_namespace("Ubuntu:24.10") == "ubuntu:24.10"
        assert osv_ecosystem_to_os_namespace("Ubuntu:25.04") == "ubuntu:25.04"
        assert osv_ecosystem_to_os_namespace("Ubuntu:25.10") == "ubuntu:25.10"
        # both bare and `:LTS` spellings of the same release occur in the data.
        assert osv_ecosystem_to_os_namespace("Ubuntu:26.04") == "ubuntu:26.04"
        assert osv_ecosystem_to_os_namespace("Ubuntu:26.04:LTS") == "ubuntu:26.04"

    def test_plain_pro_maps_to_esm_channel(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_ecosystem_to_os_namespace

        # plain Ubuntu Pro (ESM) maps to the `ubuntu:X.YY+esm` distro channel,
        # mirroring RHEL EUS's `rhel:X.Y+eus`. LTS suffix optional.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:14.04:LTS") == "ubuntu:14.04+esm"
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:16.04:LTS") == "ubuntu:16.04+esm"
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:22.04:LTS") == "ubuntu:22.04+esm"
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:25.10") == "ubuntu:25.10+esm"

    def test_subtiers_skipped(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_ecosystem_to_os_namespace

        # FIPS / FIPS-updates / Realtime / Nvidia-BlueField rebuild against divergent
        # code (crypto modules, PREEMPT_RT kernel, separate product) — their fixes can't
        # resolve a base disclosure, so they never get a channel. The anchored plain-Pro
        # regex rejects any extra tier token or trailing segment by construction.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:FIPS:22.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:FIPS-updates:20.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:FIPS-preview:22.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:Realtime:24.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Nvidia-BlueField:22.04:LTS") is None
        # two real trap grammars from the feed put the tier token AFTER the version, so a
        # naive matcher can misread them: `Ubuntu:Pro:...:Realtime:Kernel` still starts with
        # `Ubuntu:Pro:` (would look like plain Pro), and `Ubuntu:...:for:NVIDIA:BlueField`
        # starts with `Ubuntu:<ver>` (would look like a base release). Both must drop.
        # Sources: CVE-2022-50031, CVE-2025-38213.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:22.04:LTS:Realtime:Kernel") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:24.04:LTS:Realtime:Kernel") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:22.04:LTS:for:NVIDIA:BlueField") is None
        assert osv_ecosystem_to_os_namespace("Garbage") is None

    def test_include_esm_flag_off_maps_plain_pro_to_none(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_ecosystem_to_os_namespace

        # with the emit gate off, plain Pro is dropped like the sub-tiers; base is unaffected.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:22.04:LTS", include_esm=False) is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:22.04:LTS", include_esm=False) == "ubuntu:22.04"


class TestOSDowncoverter:
    """Verify per-record translation: Severity, FixedIn shape, Available date."""

    def _osv_record(self, **overrides):
        # Minimal valid OSV record we can mutate per test
        rec = {
            "schema_version": "1.7.0",
            "id": "UBUNTU-CVE-2024-1",
            "upstream": ["CVE-2024-1"],
            "details": "test details",
            "severity": [{"type": "Ubuntu", "score": "medium"}],
            "affected": [
                {
                    "package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-1ubuntu2.20"}]}],
                },
            ],
        }
        rec.update(overrides)
        return rec

    def test_withdrawn_record_is_emitted(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        # Canonical sets `withdrawn` to mark a record it will not regenerate, not
        # to retract the finding, and most withdrawn records still carry a fix.
        rec = self._osv_record(withdrawn="2025-09-12T17:13:25Z")
        assert osv_to_os(rec) is not None

    def test_cve_program_rejection_is_skipped(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(details="** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.")
        assert osv_to_os(rec) is None

    def test_fixed_event_yields_fixedin_with_version(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        out = osv_to_os(self._osv_record())
        assert out is not None
        vuln = out["Vulnerability"]
        assert vuln["Name"] == "CVE-2024-1"
        assert vuln["NamespaceName"] == "ubuntu:22.04"
        assert vuln["Severity"] == "Medium"
        assert vuln["Link"] == "https://ubuntu.com/security/CVE-2024-1"
        assert vuln["Metadata"] == {}
        assert vuln["Description"] == ""
        assert len(vuln["FixedIn"]) == 1
        fi = vuln["FixedIn"][0]
        assert fi == {
            "Name": "openssl",
            "NamespaceName": "ubuntu:22.04",
            "VersionFormat": "dpkg",
            "Version": "1.1.1f-1ubuntu2.20",
            "VendorAdvisory": {"NoAdvisory": False},
            "Available": None,
        }

    def test_fixed_event_carries_anchore_fix_date_as_available(self):
        # Once `patch_fix_date` has run, database_specific.anchore.fixes[] holds the
        # date+kind that downconversion should surface as the v3 `Available` field.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        rec["affected"][0]["ranges"][0]["database_specific"] = {
            "anchore": {"fixes": [{"version": "1.1.1f-1ubuntu2.20", "date": "2022-09-15", "kind": "advisory"}]},
        }
        out = osv_to_os(rec)
        assert out is not None
        fi = out["Vulnerability"]["FixedIn"][0]
        assert fi["Version"] == "1.1.1f-1ubuntu2.20"
        assert fi["Available"] == {"Date": "2022-09-15", "Kind": "advisory"}

    def test_wont_fix_status_yields_version_none_no_advisory_true(self):
        # Mirrors what _annotate_wont_fix writes after consulting the VEX overlay,
        # OR what _build_synthetic_base_affected writes when Pro-only-fix inference
        # synthesizes a base entry.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:18.04:LTS", "name": "foo"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "database_specific": {"anchore": {"status": "wont-fix"}},
            },
        ]
        out = osv_to_os(rec)
        assert out is not None
        fi = out["Vulnerability"]["FixedIn"][0]
        assert fi["Version"] == "None"
        assert fi["VendorAdvisory"] == {"NoAdvisory": True}
        assert fi["Available"] is None
        assert out["Vulnerability"]["NamespaceName"] == "ubuntu:18.04"

    def test_no_fixed_event_yields_version_none_no_advisory_false(self):
        # "affected but no fix yet" — neither wont-fix nor a released fix version.
        # v3 represented this as Version="None", NoAdvisory=False.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "foo"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ]
        out = osv_to_os(rec)
        assert out is not None
        fi = out["Vulnerability"]["FixedIn"][0]
        assert fi["Version"] == "None"
        assert fi["VendorAdvisory"] == {"NoAdvisory": False}

    def test_severity_handling_falls_back_to_unknown(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        # missing severity entirely
        rec = self._osv_record()
        rec.pop("severity", None)
        assert osv_to_os(rec)["Vulnerability"]["Severity"] == "Unknown"
        # untriaged → Unknown (matches v3 parse_severity_from_priority)
        rec["severity"] = [{"type": "Ubuntu", "score": "untriaged"}]
        assert osv_to_os(rec)["Vulnerability"]["Severity"] == "Unknown"
        # CVSS scores alone don't supply the Ubuntu priority — fall through
        rec["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/..."}]
        assert osv_to_os(rec)["Vulnerability"]["Severity"] == "Unknown"

    def test_severity_capitalizes_canonical_priority(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        for score, expected in [
            ("negligible", "Negligible"),
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
            ("critical", "Critical"),
        ]:
            rec["severity"] = [{"type": "Ubuntu", "score": score}]
            assert osv_to_os(rec)["Vulnerability"]["Severity"] == expected

    def test_no_upstream_returns_none(self):
        # No CVE-* id to use as Vulnerability.Name → cannot produce a v3-shape record.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        rec.pop("upstream", None)
        assert osv_to_os(rec) is None

    def test_subtier_record_returns_none(self):
        # FIPS/Realtime/BlueField fragments don't get downconverted (divergent builds).
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:FIPS:22.04:LTS", "name": "openssl"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1+fips1"}]}],
            },
        ]
        assert osv_to_os(rec) is None

    def test_plain_pro_emits_esm_channel_with_verbatim_fix_version(self):
        # Real Canonical OSV data (CVE-2021-3782 wayland, xenial esm-infra) — a genuine
        # Pro-only fix. Source: https://ubuntu.com/security/cves/CVE-2021-3782.json
        # The `~esm`/`+esm` suffix must survive verbatim; VersionFormat stays dpkg.
        from vunnel.providers.ubuntu.os_downconvert import os_identifier_for, osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-2021-3782", upstream=["CVE-2021-3782"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "wayland"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.12.0-1~ubuntu16.04.3+esm1"}]}],
            },
        ]
        out = osv_to_os(rec)
        assert out is not None
        vuln = out["Vulnerability"]
        assert vuln["NamespaceName"] == "ubuntu:16.04+esm"
        fi = vuln["FixedIn"][0]
        assert fi["Name"] == "wayland"
        assert fi["NamespaceName"] == "ubuntu:16.04+esm"
        assert fi["Version"] == "1.12.0-1~ubuntu16.04.3+esm1"
        assert fi["VersionFormat"] == "dpkg"
        assert fi["VendorAdvisory"] == {"NoAdvisory": False}
        assert os_identifier_for(out) == "ubuntu:16.04+esm/cve-2021-3782"

    def test_plain_pro_epoch_fix_version_passthrough(self):
        # Real Canonical OSV data (CVE-2025-61985 openssh, focal esm-infra) — Pro-only fix
        # with an epoch. Source: https://ubuntu.com/security/cves/CVE-2025-61985.json
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-2025-61985", upstream=["CVE-2025-61985"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:20.04:LTS", "name": "openssh"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:8.2p1-4ubuntu0.13+esm1"}]}],
            },
        ]
        out = osv_to_os(rec)
        assert out is not None
        assert out["Vulnerability"]["NamespaceName"] == "ubuntu:20.04+esm"
        assert out["Vulnerability"]["FixedIn"][0]["Version"] == "1:8.2p1-4ubuntu0.13+esm1"

    def test_plain_pro_dropped_when_include_esm_off(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-2021-3782", upstream=["CVE-2021-3782"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "wayland"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.12.0-1~ubuntu16.04.3+esm1"}]}],
            },
        ]
        assert osv_to_os(rec, include_esm=False) is None

    def test_plain_pro_no_fix_emits_no_esm_record(self):
        # A plain-Pro slice with only `introduced:0` and no fixed event (real shape from
        # CVE-2016-20013's Pro slices) must NOT produce a `ubuntu:X.YY+esm` record. The
        # `+esm` channel carries fixes only; the unfixed disclosure lives on the base
        # `ubuntu:X.YY` record, so a Version="None" +esm entry would just duplicate it.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-2016-20013", upstream=["CVE-2016-20013"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "glibc"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ]
        assert osv_to_os(rec) is None

    def test_plain_pro_wont_fix_status_emits_no_esm_record(self):
        # Same as above but with an explicit wont-fix marker (what _annotate_wont_fix
        # stamps): a wont-fix Pro slice still yields no `+esm` record — no Version="None".
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-2016-20013", upstream=["CVE-2016-20013"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "glibc"},
                "database_specific": {"anchore": {"status": "wont-fix"}},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ]
        assert osv_to_os(rec) is None

    def test_esm_apps_and_infra_share_the_same_channel(self):
        # esm-apps and esm-infra are both plain Ubuntu:Pro:X.YY ecosystems (the channel lives
        # in the purl, which the namespace mapping does not consult) — so both resolve to the
        # same `ubuntu:X.YY+esm`. Real fixes: cobbler (esm-apps) & harfbuzz (esm-infra), xenial.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        def _one(name, fixed, purl):
            rec = self._osv_record(id="UBUNTU-CVE-x", upstream=["CVE-2000-1"])
            rec["affected"] = [
                {
                    "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": name, "purl": purl},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                },
            ]
            return osv_to_os(rec)

        apps = _one("cobbler", "2.4.1-0ubuntu2+esm1", "pkg:deb/ubuntu/cobbler@2.4.1?arch=source&distro=esm-apps/xenial")
        infra = _one("harfbuzz", "1.0.1-1ubuntu0.1+esm1", "pkg:deb/ubuntu/harfbuzz@1.0.1?arch=source&distro=esm-infra/xenial")
        assert apps["Vulnerability"]["NamespaceName"] == "ubuntu:16.04+esm"
        assert infra["Vulnerability"]["NamespaceName"] == "ubuntu:16.04+esm"
        assert apps["Vulnerability"]["FixedIn"][0]["Version"] == "2.4.1-0ubuntu2+esm1"
        assert infra["Vulnerability"]["FixedIn"][0]["Version"] == "1.0.1-1ubuntu0.1+esm1"

    @pytest.mark.parametrize(
        "fixed",
        [
            "1:2.2.2+dfsg-1ubuntu1+esm5",  # epoch + multi +esm (CVE-2022-35229)
            "1:1.3-1ubuntu0.1~esm1",  # epoch + ~esm (CVE-2019-15531)
            "1.8.3-1~ubuntu0.1+esm1",  # ~ubuntu backport + +esm (CVE-2017-5838)
            "2.6.8-1~ubuntu14.04.0~esm1",  # ~ubuntu + ~esm tilde form (CVE-2019-10899)
            "2:4.7.6+dfsg~ubuntu-0ubuntu2.29+esm1",  # epoch + +dfsg~ubuntu + +esm (CVE-2022-42898)
            "1.0.0~rc7+git20190403.029124da-0ubuntu1~16.04.4+esm4",  # rc + git + backport + esm (CVE-2022-29162)
        ],
    )
    def test_weird_pro_fix_versions_pass_through_verbatim(self, fixed):
        # Real Pro fix strings from the feed must survive byte-for-byte; VersionFormat stays dpkg.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-x", upstream=["CVE-2000-1"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            },
        ]
        out = osv_to_os(rec)
        fi = out["Vulnerability"]["FixedIn"][0]
        assert fi["Version"] == fixed
        assert fi["VersionFormat"] == "dpkg"

    def test_multiple_packages_become_multiple_fixedin(self):
        # Sliced by ecosystem, an envelope still has one affected[] entry per source
        # package. Each becomes one FixedIn (in input order).
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record()
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "linux"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "linux-aws"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "database_specific": {"anchore": {"status": "wont-fix"}},
            },
            {
                "package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "linux-gcp"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4.0-100.113"}]}],
            },
        ]
        out = osv_to_os(rec)
        assert out is not None
        names = [fi["Name"] for fi in out["Vulnerability"]["FixedIn"]]
        assert names == ["linux", "linux-aws", "linux-gcp"]
        # The wont-fix one carries NoAdvisory=True; the no-fix-yet one False; the fixed one carries the version.
        by_name = {fi["Name"]: fi for fi in out["Vulnerability"]["FixedIn"]}
        assert by_name["linux"]["Version"] == "None" and by_name["linux"]["VendorAdvisory"]["NoAdvisory"] is False
        assert by_name["linux-aws"]["Version"] == "None" and by_name["linux-aws"]["VendorAdvisory"]["NoAdvisory"] is True
        assert by_name["linux-gcp"]["Version"] == "5.4.0-100.113"

    def test_identifier_for_returns_v3_shape(self):
        from vunnel.providers.ubuntu.os_downconvert import os_identifier_for, osv_to_os

        rec = self._osv_record()
        assert os_identifier_for(osv_to_os(rec)) == "ubuntu:22.04/cve-2024-1"

    def test_esm_mixed_fixed_and_no_fix_packages_keeps_only_fixed(self):
        # within a single `+esm` fragment, a fixed package survives while an unfixed one
        # is dropped entirely — no Version="None" line leaks onto the channel (the inner
        # per-entry guard) and the record still emits because a fix remains (the outer guard).
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os

        rec = self._osv_record(id="UBUNTU-CVE-x", upstream=["CVE-2000-1"])
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "fixed-pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-1ubuntu0.1+esm1"}]}],
            },
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "unfixed-pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ]
        out = osv_to_os(rec)
        assert out is not None
        fixed_in = out["Vulnerability"]["FixedIn"]
        assert [fi["Name"] for fi in fixed_in] == ["fixed-pkg"]
        assert fixed_in[0]["Version"] == "1.0-1ubuntu0.1+esm1"


class TestOSDowncoverterIntegration:
    """Verify the parser actually yields OS-shape records when the toggle is on."""

    def test_get_yields_os_records_when_enabled(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # downconvert_osv_to_os=True swaps fragment yields to OS shape; legacy passthrough
        # (which also produces OS) is unaffected.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())

        # Every yielded record should be OS-shape.
        assert records, "expected non-empty yield"
        for identifier, sch, payload in records:
            assert "/os/" in sch.url, f"expected OS schema, got {sch.url}"
            assert "Vulnerability" in payload, f"expected v3 Vulnerability shape, got {list(payload)}"
            # Identifier shape: ubuntu:X.YY/cve-...
            assert identifier.startswith("ubuntu:"), identifier

        # Every namespace is either a base `ubuntu:X.YY` or a plain-Pro `ubuntu:X.YY+esm`
        # channel. FIPS/Realtime/BlueField slices are still filtered out entirely.
        namespaces = {p["Vulnerability"]["NamespaceName"] for _, _, p in records}
        assert all(ns.startswith("ubuntu:") and ":Pro" not in ns and "-" not in ns.split(":")[1].split("+")[0] for ns in namespaces), namespaces

    def test_inferred_wont_fix_lands_in_downconverted_output(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The Pro-only-fix inference path synthesizes base envelopes with
        # status=wont-fix; downconversion should render them as Version="None"
        # / NoAdvisory=True FixedIn entries on the base ecosystem.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())

        # Find the ubuntu:16.04 envelope for CVE-2021-3782 (wayland). It's inferred from
        # the Ubuntu:Pro:16.04:LTS fragment via _yield_base_with_inferences.
        # (See TestProOnlyInferenceIntegration for the underlying fixture coverage.)
        by_id = {i: payload for i, _, payload in records}
        target = by_id.get("ubuntu:16.04/cve-2021-3782")
        assert target is not None, sorted(by_id)
        fixed = target["Vulnerability"]["FixedIn"]
        wayland = next(fi for fi in fixed if fi["Name"] == "wayland")
        assert wayland["Version"] == "None"
        assert wayland["VendorAdvisory"]["NoAdvisory"] is True

    def test_plain_pro_dual_emit_base_wontfix_and_esm_fix(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Real fixture CVE-2021-3782 (wayland) has a Pro-only fix on Ubuntu:Pro:16.04:LTS
        # (1.12.0-1~ubuntu16.04.3+esm1) and NO base 16.04 entry. Downconvert must emit the
        # paired split: base `ubuntu:16.04` carries the synthesized Version="None" wont-fix,
        # and `ubuntu:16.04+esm` carries the real, verbatim ESM fix version.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())
        by_id = {i: payload for i, _, payload in records}

        base = by_id.get("ubuntu:16.04/cve-2021-3782")
        assert base is not None, sorted(by_id)
        base_wayland = next(fi for fi in base["Vulnerability"]["FixedIn"] if fi["Name"] == "wayland")
        assert base_wayland["Version"] == "None"
        assert base_wayland["VendorAdvisory"]["NoAdvisory"] is True

        esm = by_id.get("ubuntu:16.04+esm/cve-2021-3782")
        assert esm is not None, sorted(by_id)
        assert esm["Vulnerability"]["NamespaceName"] == "ubuntu:16.04+esm"
        esm_wayland = next(fi for fi in esm["Vulnerability"]["FixedIn"] if fi["Name"] == "wayland")
        assert esm_wayland["Version"] == "1.12.0-1~ubuntu16.04.3+esm1"
        assert esm_wayland["VersionFormat"] == "dpkg"
        assert esm_wayland["NamespaceName"] == "ubuntu:16.04+esm"

        # A base CVE fixed in a standard pocket must NOT get a +esm record. Wayland is
        # released in the standard pocket on 18.04/20.04/22.04 (no Pro slice for them).
        assert "ubuntu:18.04+esm/cve-2021-3782" not in by_id
        assert "ubuntu:20.04+esm/cve-2021-3782" not in by_id
        assert "ubuntu:22.04+esm/cve-2021-3782" not in by_id

    def test_include_esm_flag_off_suppresses_esm_records(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # VUN-4: the gate off drops every +esm record while base records (incl. the
        # synthesized base wont-fix) are untouched.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True, downconvert_emit_esm=False)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())
        ids = {i for i, _, _ in records}
        assert not any("+esm" in i for i in ids), sorted(i for i in ids if "+esm" in i)
        # base wont-fix disclosure still present
        assert "ubuntu:16.04/cve-2021-3782" in ids

    def test_real_multi_release_esm_fanout_netty(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Real Canonical record CVE-2022-24823 (netty). Source: ubuntu.com/security/CVE-2022-24823.json.
        # One CVE spanning 7 Pro releases: 5 carry real Pro fixes (16/18/20/22/24), 14.04 and 26.04
        # are Pro-tracked-but-unfixed, plus a base non-LTS 25.10 slice. Exercises: multi-release
        # `+esm` fanout, verbatim passthrough of epoch / `~esm` / `+esm` / `+deb11u2` fix strings,
        # no-`+esm` for the unfixed Pro slices, and no `+esm` for the base non-LTS release.
        _seed_esm_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())
        by_id = {i: payload for i, _, payload in records}

        # the 5 fixed Pro releases each emit a `+esm` record with the real fix version verbatim.
        expected_esm = {
            "ubuntu:16.04+esm/cve-2022-24823": "1:4.0.34-1ubuntu0.1~esm2",
            "ubuntu:18.04+esm/cve-2022-24823": "1:4.1.7-4ubuntu0.1+esm3",
            "ubuntu:20.04+esm/cve-2022-24823": "1:4.1.45-1ubuntu0.1~esm2",
            "ubuntu:22.04+esm/cve-2022-24823": "1:4.1.48-4+deb11u2ubuntu0.1~esm1",
            "ubuntu:24.04+esm/cve-2022-24823": "1:4.1.48-9ubuntu0.1~esm1",
        }
        for ident, version in expected_esm.items():
            rec = by_id.get(ident)
            assert rec is not None, sorted(i for i in by_id if "+esm" in i)
            fi = next(f for f in rec["Vulnerability"]["FixedIn"] if f["Name"] == "netty")
            assert fi["Version"] == version
            assert fi["VersionFormat"] == "dpkg"
            assert fi["VendorAdvisory"] == {"NoAdvisory": False}

        # unfixed Pro slices (14.04, 26.04) and the base non-LTS 25.10 slice get no `+esm` record.
        assert "ubuntu:14.04+esm/cve-2022-24823" not in by_id
        assert "ubuntu:26.04+esm/cve-2022-24823" not in by_id
        assert "ubuntu:25.10+esm/cve-2022-24823" not in by_id
        # the emitted `+esm` set for this CVE is exactly the 5 fixed releases — no extras.
        assert {i for i in by_id if "+esm" in i and "2022-24823" in i} == set(expected_esm)

    def test_real_mixed_base_and_esm_fix_unzip(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Real record CVE-2014-9913 (unzip): fixed in Pro on 14.04 (`6.0-9ubuntu1.6`) and in the
        # standard pocket on 16.04 (`6.0-20ubuntu1.1`). The Pro release emits both a base wont-fix
        # and a `+esm` fix; the base-fixed release emits only a base record — never a `+esm`.
        _seed_esm_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())
        by_id = {i: payload for i, _, payload in records}

        esm = by_id.get("ubuntu:14.04+esm/cve-2014-9913")
        assert esm is not None, sorted(by_id)
        esm_fi = next(f for f in esm["Vulnerability"]["FixedIn"] if f["Name"] == "unzip")
        assert esm_fi["Version"] == "6.0-9ubuntu1.6"

        base16 = by_id.get("ubuntu:16.04/cve-2014-9913")
        assert base16 is not None, sorted(by_id)
        base16_fi = next(f for f in base16["Vulnerability"]["FixedIn"] if f["Name"] == "unzip")
        assert base16_fi["Version"] == "6.0-20ubuntu1.1"

        # 16.04 is fixed in the standard pocket (no Pro slice) — no `+esm` channel record.
        assert "ubuntu:16.04+esm/cve-2014-9913" not in by_id

    def test_real_withdrawn_pro_record_is_emitted_wolfssl(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Real withdrawn record CVE-2014-2901 (wolfssl) carrying a plain-Pro slice. Its
        # details are an ordinary description, so the withdrawal is Canonical saying it
        # will not regenerate the record, and the finding still stands.
        _seed_esm_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())
        ids = {i for i, _, _ in records}
        assert any("2014-2901" in i for i in ids), sorted(ids)

    def test_real_no_fix_pro_slices_emit_no_esm_records(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Real fixture CVE-2016-20013: its plain-Pro slices (14/16/18/20) are all `introduced:0`
        # with no fixed event. None may produce a `+esm` record — the base wont-fix is the sole
        # disclosure. Regression guard for the "+esm Version=None noise" the channel used to emit.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())
        ids = {i for i, _, _ in records}
        assert not any("+esm" in i and "2016-20013" in i for i in ids), \
            sorted(i for i in ids if "+esm" in i and "2016-20013" in i)
        # the base disclosure is still present.
        assert "ubuntu:14.04/cve-2016-20013" in ids

    def test_provider_config_emit_esm_off_drops_esm_records(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        # Frozen-v5 lane, end-to-end: downconvert on but `downconvert_emit_esm` off through the
        # real Config -> Provider -> Parser plumbing. No `+esm` record lands on disk.
        import json

        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.downconvert_osv_to_os = True
        c.downconvert_emit_esm = False

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"), _patch_calendar_download(p.parser, fixture_dir):
            p.update(None)

        namespaces = []
        for f in ws.result_files():
            with open(f) as fh:
                namespaces.append(json.load(fh)["item"]["Vulnerability"]["NamespaceName"])
        assert namespaces, "expected downconverted records"
        assert not any(ns.endswith("+esm") for ns in namespaces), sorted(set(namespaces))

    def test_default_still_yields_osv_records(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Sanity: with the toggle off (default), OSV envelopes flow through unchanged.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"), _patch_calendar_download(p, fixture_dir):
            records = list(p.get())

        schemas = {sch.url for _, sch, _ in records}
        assert all("/osv/" in s for s in schemas), schemas

    def test_provider_config_wires_toggle_through(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        # End-to-end through Provider.update with the Config flag on, exercising
        # the actual Provider plumbing (not just Parser.__init__).
        import json

        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.downconvert_osv_to_os = True

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"), _patch_calendar_download(p.parser, fixture_dir):
            p.update(None)

        schemas = []
        for f in ws.result_files():
            with open(f) as fh:
                schemas.append(json.load(fh)["schema"])
        # Every emitted record uses the OS schema; no OSV envelopes leak through.
        assert all("/os/schema-" in s for s in schemas), schemas


# ---------------------------------------------------------------------------
# Canonical release identity — one release, one fragment, whatever it's spelled
# ---------------------------------------------------------------------------


def _seed_canonical_identity_archive(fresh_workspace, fixture_dir):
    # Real Canonical records for 26.04, which the feed publishes under both
    # `Ubuntu:26.04` (pre-GA, withdrawn) and `Ubuntu:26.04:LTS` (current).
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv-canonical-identity",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


def _seed_pro_inference_archive(fresh_workspace, fixture_dir):
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv-pro-inference",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


class TestReleaseIdentity:
    def test_suffixed_and_unsuffixed_spellings_are_one_release(self):
        assert canonical_ecosystem("Ubuntu:26.04") == canonical_ecosystem("Ubuntu:26.04:LTS")
        assert canonical_ecosystem("Ubuntu:26.04") == "Ubuntu:26.04:LTS"
        assert canonical_slug("Ubuntu:26.04") == canonical_slug("Ubuntu:26.04:LTS") == "ubuntu-26.04-lts"

    def test_channels_stay_distinct(self):
        assert canonical_ecosystem("Ubuntu:20.04:LTS") != canonical_ecosystem("Ubuntu:Pro:20.04:LTS")
        assert canonical_ecosystem("Ubuntu:Pro:20.04:LTS") == "Ubuntu:Pro:20.04:LTS"

    def test_ecosystems_with_no_output_namespace_keep_their_own_identity(self):
        # os_downconvert maps all three to no namespace; they are separate builds,
        # so they must not collapse onto the base release or onto each other.
        distinct = {
            canonical_ecosystem(e)
            for e in (
                "Ubuntu:22.04:LTS",
                "Ubuntu:Pro:22.04:LTS",
                "Ubuntu:Pro:FIPS:20.04:LTS",
                "Ubuntu:Pro:FIPS-updates:22.04:LTS",
                "Ubuntu:Pro:Realtime:22.04:LTS",
                "Ubuntu:Nvidia-BlueField:22.04:LTS",
            )
        }
        assert len(distinct) == 6

    @pytest.mark.parametrize(
        "ecosystem",
        [
            "Ubuntu:Pro:14.04:LTS",
            "Ubuntu:Pro:16.04:LTS",
            "Ubuntu:Pro:FIPS:20.04:LTS",
            "Ubuntu:Pro:FIPS-updates:24.04:LTS",
            "Ubuntu:Pro:FIPS-preview:22.04:LTS",
            "Ubuntu:Pro:Realtime:24.04:LTS",
            "Ubuntu:Nvidia-BlueField:22.04:LTS",
        ],
    )
    def test_every_extended_support_shape_reports_an_lts_base_version(self, ecosystem):
        identity = release_identity(ecosystem)
        assert identity is not None
        # the freeze rule and the husk list both key on this version
        assert identity.version in {"14.04", "16.04", "20.04", "22.04", "24.04"}
        assert identity.is_lts is True

    def test_interim_releases_are_not_lts(self):
        for version, eco in (("24.10", "Ubuntu:24.10"), ("25.04", "Ubuntu:25.04"), ("25.10", "Ubuntu:25.10")):
            identity = release_identity(eco)
            assert identity.version == version
            assert identity.is_lts is False
            assert identity.slug == f"ubuntu-{version}"

    def test_unrecognized_ecosystems_keep_their_spelling(self):
        # Canonical publishes a handful of malformed strings; they are out of scope
        # and must not be merged onto anything.
        for eco in ("Ubuntu:22.04:LTS:for:NVIDIA:BlueField", "Ubuntu:Pro:22.04:LTS:Realtime:Kernel"):
            assert release_identity(eco) is None
            assert canonical_ecosystem(eco) == eco
            assert canonical_slug(eco) == ecosystem_to_slug(eco)


class TestCanonicalIdentityFragments:
    def test_both_spellings_of_a_release_share_one_fragment(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2026-7246 is a real withdrawn record naming `Ubuntu:26.04`;
        # UBUNTU-CVE-2026-41293 names `Ubuntu:26.04:LTS`. One release, one file.
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        present = _fragment_paths(fresh_workspace)
        assert "ubuntu-26.04-lts.db" in present
        assert "ubuntu-26.04.db" not in present

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-26.04-lts.db")
        with result.SQLiteReader(path) as reader:
            ids = {e.identifier for e in reader.each()}
        assert ids == {
            "ubuntu-26.04-lts/ubuntu-cve-2026-7246",
            "ubuntu-26.04-lts/ubuntu-cve-2026-41293",
        }

    def test_pairing_survives_canonicalisation_and_real_records_survive(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2026-41293 has real base 26.04 entries (tomcat9, tomcat10) and a
        # Pro:26.04 sibling (tomcat11). CVE-2026-7734 is Pro-only (gobgp).
        # If pairing breaks, the base pass synthesizes a whole envelope and,
        # sorting last, replaces the real records with Version:"None" stubs.
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}

        tomcat = yielded["ubuntu-26.04-lts/ubuntu-cve-2026-41293"]
        by_pkg = {a["package"]["name"]: a for a in tomcat["affected"]}
        # the real records are still real: they carry their own purl and a fixed event
        for pkg in ("tomcat9", "tomcat10"):
            assert "purl" in by_pkg[pkg]["package"], f"{pkg} was replaced by a synthesized stub"
            assert "inference" not in (by_pkg[pkg].get("database_specific") or {}).get("anchore", {})
        # and the Pro-only package is inferred onto the same envelope
        assert "inference" in by_pkg["tomcat11"]["database_specific"]["anchore"]

        gobgp = yielded["ubuntu-26.04-lts/ubuntu-cve-2026-7734"]
        assert [a["package"]["name"] for a in gobgp["affected"]] == ["gobgp"]
        assert gobgp["affected"][0]["database_specific"]["anchore"]["inference"]["kind"] == "pro-only-fix"

    def test_unpairable_base_fragment_emits_its_real_records(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # A fragment whose ecosystem can't be read is yielded verbatim and never
        # paired. The Pro sibling then synthesizes a whole envelope under the same
        # identifier; the real record must win.
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        # rewrite the base fragment so its envelopes carry no readable ecosystem
        real_payload = {"id": "UBUNTU-CVE-2026-7734", "upstream": ["CVE-2026-7734"], "affected": [{"package": {"name": "gobgp"}, "ranges": []}]}
        with result.Writer(
            workspace=fresh_workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=os.path.join(fragments_dir, "ubuntu-26.04-lts.db"),
        ) as w:
            w.write(
                identifier="ubuntu-26.04-lts/ubuntu-cve-2026-7734",
                schema=schema.OSVSchema(version="1.7.0"),
                payload=real_payload,
            )

        yielded = [t for t in p._iter_fragments() if t[0] == "ubuntu-26.04-lts/ubuntu-cve-2026-7734"]
        assert len(yielded) == 1
        affected = yielded[0][2]["affected"]
        assert [a["package"]["name"] for a in affected] == ["gobgp"]
        assert "anchore" not in (affected[0].get("database_specific") or {}), "a synthesized stub replaced the real record"

    def test_pro_to_base_inference_still_fires(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-0021 is Pro:14.04-only (chrony); CVE-2015-20107 has a
        # Pro:18.04 python3.7 entry with no base 18.04 sibling for that package.
        _seed_pro_inference_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}

        chrony = yielded["ubuntu-14.04-lts/ubuntu-cve-2014-0021"]
        assert [a["package"]["name"] for a in chrony["affected"]] == ["chrony"]
        assert chrony["affected"][0]["database_specific"]["anchore"]["inference"]["source_ecosystems"] == ["Ubuntu:Pro:14.04:LTS"]

        python = yielded["ubuntu-18.04-lts/ubuntu-cve-2015-20107"]
        inferred = {a["package"]["name"] for a in python["affected"] if "inference" in (a.get("database_specific") or {}).get("anchore", {})}
        assert "python3.7" in inferred
        # the real base entries are untouched
        real = {a["package"]["name"] for a in python["affected"] if "inference" not in (a.get("database_specific") or {}).get("anchore", {})}
        assert real == {"python2.7", "python3.6"}


# ---------------------------------------------------------------------------
# Release calendar — the freeze rule's only input besides the clock
# ---------------------------------------------------------------------------


def _calendar_bytes(fixture_dir) -> bytes:
    """The real distro-info-data ubuntu.csv, fetched 2026-09-10.

    Never hand-write a calendar: the real file carries the ` LTS` suffix, the
    empty tier columns on interim rows, and a release that hasn't shipped yet.
    """
    with open(os.path.join(fixture_dir, "distro-info", "ubuntu.csv"), "rb") as fh:
        return fh.read()


class _FakeCalendarResponse:
    """Stand-in for http.get's streaming response, as TestParserDownload uses."""

    def __init__(self, data: bytes):
        self._data = data

    def iter_content(self, chunk_size: int):  # noqa: ARG002
        yield self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None


def _patch_calendar_download(target, fixture_dir):
    """Serve the release calendar from the fixture file instead of the network."""
    payload = _calendar_bytes(fixture_dir)

    def fake(url, path):  # noqa: ARG001
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(payload)

    return patch.object(target, "_download_calendar", side_effect=fake)


def _redirect_calendar_download(payload: bytes):
    return patch("vunnel.providers.ubuntu.parser.http.get", return_value=_FakeCalendarResponse(payload))


def _load_fixture_calendar(fresh_workspace, fixture_dir):
    p = Parser(workspace=fresh_workspace)
    with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
        return p._load_calendar()


def _utc(text: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(text)


class TestEOLCalendar:
    def test_questing_freezes_exactly_at_midnight_utc_on_its_eol_date(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        # questing's published eol is 2026-07-09
        assert calendar.frozen("25.10", _utc("2026-07-08T23:59:59+00:00")) is False
        assert calendar.frozen("25.10", _utc("2026-07-09T00:00:00+00:00")) is True
        # and by codename, which is how VEX names it
        assert calendar.frozen("questing", _utc("2026-07-09T00:00:00+00:00")) is True

    def test_lts_releases_never_freeze(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        # past xenial's eol-legacy (2031-04-30), the furthest date in the file
        far_future = _utc("2045-01-01T00:00:00+00:00")
        lts = [r for r in calendar.releases if r.lts]
        assert lts, "the fixture calendar has no LTS rows"
        for release in lts:
            assert calendar.frozen(release.version, far_future) is False, release.version
            assert calendar.frozen(release.series, far_future) is False, release.series

    def test_lts_version_column_is_read_with_its_space(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        resolute = calendar.get("26.04")
        assert resolute is not None
        assert resolute.lts is True
        assert resolute.series == "resolute"
        assert calendar.get("resolute") is resolute

    def test_unknown_release_is_live(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        assert calendar.get("99.04") is None
        assert calendar.frozen("99.04", _utc("2099-01-01T00:00:00+00:00")) is False

    def test_row_for_an_unreleased_release_parses(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        stonking = calendar.get("26.10")
        assert stonking is not None
        assert stonking.series == "stonking"
        assert stonking.lts is False

    def test_empty_eol_column_means_live(self):
        calendar = eol_calendar.parse(
            "version,codename,series,created,release,eol\n27.04,Nameless,nameless,2026-10-15,2027-04-22,\n",
        )
        assert calendar.get("27.04").eol is None
        assert calendar.frozen("27.04", _utc("2099-01-01T00:00:00+00:00")) is False

    def test_frozen_versions_is_the_set_the_write_pass_consults(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        frozen = calendar.frozen_versions(_utc("2026-09-10T00:00:00+00:00"))
        assert {"24.10", "25.04", "25.10"} <= frozen
        assert "26.04" not in frozen
        assert "26.10" not in frozen

    def test_approaching_eol_names_live_interims_only(self, fresh_workspace, fixture_dir):
        calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        # two days before questing's instant
        approaching = calendar.approaching_eol(_utc("2026-07-07T00:00:00+00:00"))
        assert [r.series for r in approaching] == ["questing"]
        # and once frozen it is no longer "approaching"
        assert calendar.approaching_eol(_utc("2026-07-09T00:00:00+00:00")) == []

    def test_a_corrected_date_takes_effect(self, fresh_workspace, fixture_dir):
        moved = _calendar_bytes(fixture_dir).replace(b"questing,2025-04-17,2025-10-09,2026-07-09", b"questing,2025-04-17,2025-10-09,2026-09-01")
        p = Parser(workspace=fresh_workspace)
        with _redirect_calendar_download(moved):
            corrected = p._load_calendar()
        assert corrected.frozen("25.10", _utc("2026-08-15T00:00:00+00:00")) is False

        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            real = p._load_calendar()
        assert real.frozen("25.10", _utc("2026-08-15T00:00:00+00:00")) is True


class TestEOLCalendarFailurePaths:
    def _cached(self, fresh_workspace, fixture_dir) -> str:
        path = eol_calendar.cached_path(fresh_workspace.input_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(_calendar_bytes(fixture_dir))
        return path

    def test_download_failure_falls_back_to_the_cached_copy(self, fresh_workspace, fixture_dir, caplog):
        path = self._cached(fresh_workspace, fixture_dir)
        before = open(path, "rb").read()

        p = Parser(workspace=fresh_workspace)
        with patch("vunnel.providers.ubuntu.parser.http.get", side_effect=RuntimeError("connection refused")), caplog.at_level("WARNING"):
            calendar = p._load_calendar()

        assert calendar.frozen("25.10", _utc("2026-07-09T00:00:00+00:00")) is True
        assert open(path, "rb").read() == before
        assert "falling back to the cached copy" in caplog.text

    def test_download_failure_with_no_cached_copy_fails_the_run(self, fresh_workspace):
        p = Parser(workspace=fresh_workspace)
        with patch("vunnel.providers.ubuntu.parser.http.get", side_effect=RuntimeError("connection refused")), pytest.raises(eol_calendar.CalendarError):
            p._load_calendar()

    def test_truncated_download_does_not_overwrite_the_cached_copy(self, fresh_workspace, fixture_dir, caplog):
        path = self._cached(fresh_workspace, fixture_dir)
        before = open(path, "rb").read()

        p = Parser(workspace=fresh_workspace)
        with _redirect_calendar_download(b"version,codena"), caplog.at_level("WARNING"):
            calendar = p._load_calendar()

        # the good copy is still on disk, byte for byte, and is what the run used
        assert open(path, "rb").read() == before
        assert calendar.frozen("25.10", _utc("2026-07-09T00:00:00+00:00")) is True
        assert not os.path.exists(path + ".tmp")
        assert "falling back to the cached copy" in caplog.text

    def test_a_successful_fetch_replaces_the_cached_copy(self, fresh_workspace, fixture_dir):
        path = self._cached(fresh_workspace, fixture_dir)
        moved = _calendar_bytes(fixture_dir).replace(b"questing,2025-04-17,2025-10-09,2026-07-09", b"questing,2025-04-17,2025-10-09,2026-09-01")
        p = Parser(workspace=fresh_workspace)
        with _redirect_calendar_download(moved):
            p._load_calendar()
        assert open(path, "rb").read() == moved

    def test_calendar_url_is_reported_with_the_other_inputs(self, fresh_workspace):
        p = Parser(workspace=fresh_workspace)
        assert eol_calendar.CALENDAR_URL in p.urls


# ---------------------------------------------------------------------------
# Freeze at the published end-of-life date
# ---------------------------------------------------------------------------


def _build_archive_from_payloads(dst_path: str, payloads: list[dict], prefix: str = "osv/cve/2026") -> None:
    """Write an OSV tarball from in-memory records.

    Used where the shape under test is the ecosystem string rather than the
    record: a release the calendar doesn't list has no real record to pull, and
    two of the extended-support shapes the freeze rule has to get right are not
    in today's feed. Every such payload is derived from a real fixture record
    with its ecosystem relabelled, never composed from nothing.
    """
    import io

    with tarfile.open(dst_path, mode="w:xz") as tar:
        for payload in payloads:
            body = orjson.dumps(payload)
            ti = tarfile.TarInfo(f"{prefix}/{payload['id']}.json")
            ti.size = len(body)
            tar.addfile(ti, io.BytesIO(body))


def _relabel(fixture_dir: str, source: str, ecosystem: str, record_id: str) -> dict:
    with open(os.path.join(fixture_dir, source), "rb") as fh:
        record = orjson.loads(fh.read())
    record["id"] = record_id
    for aff in record["affected"]:
        aff["package"]["ecosystem"] = ecosystem
    return record


def _plant_fragment(fresh_workspace, slug: str, identifier: str, payload: dict) -> str:
    fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
    os.makedirs(fragments_dir, exist_ok=True)
    path = os.path.join(fragments_dir, f"{slug}.db")
    with result.Writer(
        workspace=fresh_workspace,
        result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        store_strategy=result.StoreStrategy.SQLITE,
        write_location=path,
    ) as w:
        w.write(identifier=identifier, schema=schema.OSVSchema(version="1.7.0"), payload=payload)
    return path


def _plant_envelope(fresh_workspace, slug: str, identifier: str, payload: dict) -> str:
    """Add one more envelope to a fragment that already exists, keeping what is there."""
    path = os.path.join(fresh_workspace.input_path, "fragments", f"{slug}.db")
    with result.Writer(
        workspace=fresh_workspace,
        result_state_policy=result.ResultStatePolicy.KEEP,
        store_strategy=result.StoreStrategy.SQLITE,
        write_location=path,
    ) as w:
        w.write(identifier=identifier, schema=schema.OSVSchema(version="1.7.0"), payload=payload)
    return path


def _fragment_identifiers(path: str) -> set[str]:
    with result.SQLiteReader(path) as reader:
        return {e.identifier for e in reader.each()}


class TestParserFreezeAtEOL:
    """The calendar decides which releases today's feed may write.

    `Ubuntu:25.10` (questing) has a published eol of 2026-07-09 and appears in
    the canonical-identity fixture records, so it is the release these pin.
    """

    def _write(self, fresh_workspace, fixture_dir, now: str):
        p = Parser(workspace=fresh_workspace)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        p._write_fragments(calendar=calendar, now=_utc(now))
        return p

    def test_live_interim_is_replaced_one_second_before_its_eol_instant(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        path = _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-stale-1",
            {"id": "UBUNTU-CVE-STALE-1", "details": "stale", "affected": []},
        )
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)

        self._write(fresh_workspace, fixture_dir, "2026-07-08T23:59:59+00:00")

        ids = _fragment_identifiers(path)
        assert "ubuntu-25.10/ubuntu-cve-stale-1" not in ids
        assert "ubuntu-25.10/ubuntu-cve-2026-7246" in ids

    def test_interim_freezes_at_its_eol_instant(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        path = _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-stale-1",
            {"id": "UBUNTU-CVE-STALE-1", "details": "stale", "affected": []},
        )
        before = open(path, "rb").read()
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)

        self._write(fresh_workspace, fixture_dir, "2026-07-09T00:00:00+00:00")

        assert open(path, "rb").read() == before

    def test_frozen_release_ignores_additions(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        path = _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-frozen-1",
            {"id": "UBUNTU-CVE-FROZEN-1", "details": "frozen", "affected": []},
        )
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)

        self._write(fresh_workspace, fixture_dir, "2026-09-10T00:00:00+00:00")

        # the archive carries three 25.10 records the fragment does not have
        assert _fragment_identifiers(path) == {"ubuntu-25.10/ubuntu-cve-frozen-1"}

    def test_frozen_release_with_no_fragment_gets_none(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the OSV cache is not a new cache kind and takes no bootstrap: a frozen
        # release with no fragment stays with no fragment.
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)
        self._write(fresh_workspace, fixture_dir, "2026-09-10T00:00:00+00:00")
        assert "ubuntu-25.10.db" not in _fragment_paths(fresh_workspace)
        assert "ubuntu-26.04-lts.db" in _fragment_paths(fresh_workspace)

    def test_extended_support_ecosystems_are_never_frozen(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # 2031-05-01 is past focal's eol (2025-05-29), xenial's eol-esm
        # (2026-04-23) and xenial's eol-legacy (2031-04-30) — every LTS date in
        # the file bar the ones that run into the 2030s.
        ecosystems = [
            "Ubuntu:20.04:LTS",
            "Ubuntu:Pro:16.04:LTS",
            "Ubuntu:Pro:FIPS:22.04:LTS",
            "Ubuntu:Nvidia-BlueField:22.04:LTS",
        ]
        payloads = [
            _relabel(fixture_dir, "osv/cve/2026/UBUNTU-CVE-2026-1403.json", eco, f"UBUNTU-CVE-LTS-{i}")
            for i, eco in enumerate(ecosystems)
        ]
        _build_archive_from_payloads(os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"), payloads)

        planted = {
            eco: _plant_fragment(
                fresh_workspace,
                canonical_slug(eco),
                f"{canonical_slug(eco)}/ubuntu-cve-stale",
                {"id": "UBUNTU-CVE-STALE", "details": "stale", "affected": []},
            )
            for eco in ecosystems
        }

        self._write(fresh_workspace, fixture_dir, "2031-05-01T00:00:00+00:00")

        for eco, path in planted.items():
            ids = _fragment_identifiers(path)
            assert f"{canonical_slug(eco)}/ubuntu-cve-stale" not in ids, f"{eco} was not replaced"
            assert len(ids) == 1

    def test_release_absent_from_the_calendar_is_live(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        payload = _relabel(fixture_dir, "osv/cve/2026/UBUNTU-CVE-2026-1403.json", "Ubuntu:99.04", "UBUNTU-CVE-UNKNOWN-1")
        _build_archive_from_payloads(os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"), [payload])

        self._write(fresh_workspace, fixture_dir, "2099-01-01T00:00:00+00:00")

        assert "ubuntu-99.04.db" in _fragment_paths(fresh_workspace)

    def test_empty_archive_touches_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        path = _plant_fragment(
            fresh_workspace,
            "ubuntu-22.04-lts",
            "ubuntu-22.04-lts/ubuntu-cve-keep",
            {"id": "UBUNTU-CVE-KEEP", "details": "keep", "affected": []},
        )
        before = open(path, "rb").read()
        _build_archive_from_payloads(os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"), [])

        self._write(fresh_workspace, fixture_dir, "2026-09-10T00:00:00+00:00")

        assert open(path, "rb").read() == before
        assert _fragment_paths(fresh_workspace) == ["ubuntu-22.04-lts.db"]

    def test_archive_with_no_cve_members_touches_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        path = _plant_fragment(
            fresh_workspace,
            "ubuntu-22.04-lts",
            "ubuntu-22.04-lts/ubuntu-cve-keep",
            {"id": "UBUNTU-CVE-KEEP", "details": "keep", "affected": []},
        )
        before = open(path, "rb").read()
        payload = _relabel(fixture_dir, "osv/cve/2026/UBUNTU-CVE-2026-1403.json", "Ubuntu:22.04:LTS", "UBUNTU-CVE-USN-ONLY")
        # osv/usn/** is in the tarball but is not a CVE record
        _build_archive_from_payloads(os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"), [payload], prefix="osv/usn")

        self._write(fresh_workspace, fixture_dir, "2026-09-10T00:00:00+00:00")

        assert open(path, "rb").read() == before

    def test_log_lines_report_the_freeze_without_changing_output(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, caplog):
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)
        # two days before questing's instant the approaching-eol line fires; a
        # `now` past it makes questing a frozen release still in the feed.
        with caplog.at_level("INFO"):
            self._write(fresh_workspace, fixture_dir, "2026-07-07T00:00:00+00:00")
        assert "ubuntu 25.10 (questing) freezes at 2026-07-09T00:00:00+00:00" in caplog.text

        caplog.clear()
        shutil.rmtree(os.path.join(fresh_workspace.input_path, "fragments"))
        with caplog.at_level("INFO"):
            p_logged = self._write(fresh_workspace, fixture_dir, "2026-09-10T00:00:00+00:00")
        assert "Ubuntu:25.10 is past its end of life; skipped 3 records still in the feed" in caplog.text
        logged = sorted((t[0], orjson.dumps(t[2], option=orjson.OPT_SORT_KEYS)) for t in p_logged._iter_fragments())

        shutil.rmtree(os.path.join(fresh_workspace.input_path, "fragments"))
        p_silent = Parser(workspace=fresh_workspace, logger=logging.getLogger("silent"))
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p_silent._load_calendar()
        logging.getLogger("silent").disabled = True
        try:
            p_silent._write_fragments(calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
            silent = sorted((t[0], orjson.dumps(t[2], option=orjson.OPT_SORT_KEYS)) for t in p_silent._iter_fragments())
        finally:
            logging.getLogger("silent").disabled = False

        assert logged == silent


# ---------------------------------------------------------------------------
# Retiring the fragments written from a post-sweep husk
# ---------------------------------------------------------------------------


def _seed_husk_archive(fresh_workspace, fixture_dir):
    """Real feed records for the two swept releases, plus their live stragglers.

    UBUNTU-CVE-2023-38313/38314 are withdrawn 24.10 records and
    UBUNTU-CVE-2022-21695 a withdrawn 25.04 one — the residue Canonical leaves
    behind. UBUNTU-CVE-2025-46336 is one of plucky's three live stragglers.
    """
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv-husk",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


def _seed_husk_normalized(fresh_workspace, fixture_dir):
    shutil.copytree(
        os.path.join(fixture_dir, "normalized-cve-data-husk"),
        os.path.join(fresh_workspace.input_path, "normalized-cve-data"),
    )


def _plant_husk_fragment(fresh_workspace, filename: str, ecosystem: str, cve: str) -> str:
    fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
    os.makedirs(fragments_dir, exist_ok=True)
    path = os.path.join(fragments_dir, filename)
    with result.Writer(
        workspace=fresh_workspace,
        result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        store_strategy=result.StoreStrategy.SQLITE,
        write_location=path,
    ) as w:
        w.write(
            identifier=f"{ecosystem_to_slug(ecosystem)}/{cve.lower()}",
            schema=schema.OSVSchema(version="1.7.0"),
            payload={
                "id": cve,
                "upstream": [cve.replace("UBUNTU-", "")],
                "withdrawn": "2026-01-20T00:00:00Z",
                "affected": [{"package": {"ecosystem": ecosystem, "name": "husk"}, "ranges": []}],
            },
        )
    # the production workspace has WAL sidecars beside every fragment
    for suffix in ("-wal", "-shm"):
        with open(path + suffix, "wb") as fh:
            fh.write(b"")
    return path


class TestParserHuskRetirement:
    """The two releases swept before the freeze rule existed are served from the tracker cache.

    The other half of this behaviour is in TestParserLegacyPassthrough, which
    covers the rule that decides whether a namespace falls through to
    normalized-cve-data at all.
    """

    def test_known_husk_fragments_are_retired_on_the_first_run(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        plucky = _plant_husk_fragment(fresh_workspace, "ubuntu-25.04.db", "Ubuntu:25.04", "UBUNTU-CVE-2022-21695")
        oracular = _plant_husk_fragment(fresh_workspace, "ubuntu-24.10.db", "Ubuntu:24.10", "UBUNTU-CVE-2023-38313")
        questing = _plant_husk_fragment(fresh_workspace, "ubuntu-25.10.db", "Ubuntu:25.10", "UBUNTU-CVE-2026-7246")
        questing_before = open(questing, "rb").read()

        _seed_husk_archive(fresh_workspace, fixture_dir)
        _seed_husk_normalized(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        with (
            patch.object(p, "_download_archive"),
            patch.object(p, "_download_vex_archive"),
            _patch_calendar_download(p, fixture_dir),
        ):
            identifiers = {t[0] for t in p.get()}

        for path in (plucky, oracular):
            assert not os.path.exists(path)
            assert not os.path.exists(path + "-wal")
            assert not os.path.exists(path + "-shm")

        # not recreated by the write pass that follows in the same run
        assert "ubuntu-25.04.db" not in _fragment_paths(fresh_workspace)
        assert "ubuntu-24.10.db" not in _fragment_paths(fresh_workspace)

        # and the releases are emitted from the tracker cache instead
        assert any(i.startswith("ubuntu:25.04/") for i in identifiers)
        assert any(i.startswith("ubuntu:24.10/") for i in identifiers)

        # a healthy past-EOL release is kept and frozen, not retired
        assert open(questing, "rb").read() == questing_before

    def test_retirement_is_keyed_on_identity_not_file_name(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # a husk whose file name says LTS but whose envelopes name Ubuntu:25.04
        path = _plant_husk_fragment(fresh_workspace, "ubuntu-25.04-lts.db", "Ubuntu:25.04", "UBUNTU-CVE-2022-21695")
        Parser(workspace=fresh_workspace)._clean_input()
        assert not os.path.exists(path)

    def test_unreadable_husk_fragment_is_retired_by_name(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        fragments_dir = os.path.join(fresh_workspace.input_path, "fragments")
        os.makedirs(fragments_dir, exist_ok=True)
        path = os.path.join(fragments_dir, "ubuntu-24.10.db")
        with open(path, "wb") as fh:
            fh.write(b"not a database")

        Parser(workspace=fresh_workspace)._clean_input()
        assert not os.path.exists(path)

    def test_non_canonical_spelling_is_retired_beside_the_canonical_one(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the real residue of 26.04's rename: withdrawn records under the pre-GA
        # spelling, beside the fragment that holds the release today
        residue = _plant_husk_fragment(fresh_workspace, "ubuntu-26.04.db", "Ubuntu:26.04", "UBUNTU-CVE-2026-7246")
        canonical = _plant_husk_fragment(fresh_workspace, "ubuntu-26.04-lts.db", "Ubuntu:26.04:LTS", "UBUNTU-CVE-2026-41293")
        canonical_before = open(canonical, "rb").read()

        Parser(workspace=fresh_workspace)._clean_input()

        assert not os.path.exists(residue)
        assert not os.path.exists(residue + "-wal")
        assert open(canonical, "rb").read() == canonical_before

    def test_retirement_is_idempotent(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, caplog):
        # nothing in this workspace is a known husk or a superseded spelling
        _plant_husk_fragment(fresh_workspace, "ubuntu-22.04-lts.db", "Ubuntu:22.04:LTS", "UBUNTU-CVE-2026-1403")
        _plant_husk_fragment(fresh_workspace, "ubuntu-25.10.db", "Ubuntu:25.10", "UBUNTU-CVE-2026-7246")

        p = Parser(workspace=fresh_workspace)
        with caplog.at_level("INFO"):
            p._clean_input()
            p._clean_input()

        assert [f for f in _fragment_paths(fresh_workspace) if f.endswith(".db")] == ["ubuntu-22.04-lts.db", "ubuntu-25.10.db"]
        assert "retiring fragment" not in caplog.text

    def test_retired_release_not_covered_by_a_pro_fragment(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # a Pro fragment for the release must not read as OSV coverage of the base
        _plant_husk_fragment(fresh_workspace, "ubuntu-pro-14.04-lts.db", "Ubuntu:Pro:14.04:LTS", "UBUNTU-CVE-2014-0021")
        p = Parser(workspace=fresh_workspace)
        assert p._osv_covers_legacy_namespace("ubuntu:14.04") is False
        _plant_husk_fragment(fresh_workspace, "ubuntu-14.04-lts.db", "Ubuntu:14.04:LTS", "UBUNTU-CVE-2014-0021")
        assert p._osv_covers_legacy_namespace("ubuntu:14.04") is True

    def test_tracker_cache_not_affected_package_emits_one_zero_version_fixedin(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # grype reads a package group whose every FixedIn is exactly "0" as an
        # unaffected package that suppresses and never matches. The sentinel is an
        # exact string compare, so a second FixedIn for the same package on the
        # same namespace would drop the group back onto the affected path.
        _seed_husk_normalized(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        by_id = {t[0]: t[2] for t in p._iter_normalized_cve_data()}

        plucky = by_id["ubuntu:25.04/cve-2019-1010305"]["Vulnerability"]
        clamav = [f for f in plucky["FixedIn"] if f["Name"] == "clamav"]
        assert len(clamav) == 1
        assert clamav[0]["Version"] == "0"
        # and a released package on the same record still carries its real version
        libmspack = [f for f in plucky["FixedIn"] if f["Name"] == "libmspack"]
        assert len(libmspack) == 1
        assert libmspack[0]["Version"] == "0.10.1-1"


# ---------------------------------------------------------------------------
# The VEX cache — per distro token, same freeze rule as OSV
# ---------------------------------------------------------------------------
#
# The fixtures under test-fixtures/vex-cases/ are real Canonical VEX documents
# with their binary-architecture products dropped. Only `arch=source` products
# are ever read, so nothing under test is lost, and a verbatim copy of one of
# these documents is over a megabyte.


def _seed_vex_cases_archive(fresh_workspace, fixture_dir, subdir: str = "vex-cases") -> str:
    dst = os.path.join(fresh_workspace.input_path, "vex-all.tar.xz")
    _build_sample_archive(fixture_dir, subdir, "vex", dst)
    return dst


def _vex_store(fresh_workspace) -> vex_cache.VEXFragmentStore:
    return vex_cache.VEXFragmentStore(fresh_workspace, logging.getLogger("test"))


def _vex_index(fresh_workspace, fixture_dir) -> VEXOverlay:
    """Write the legacy `vex/` fixture into fragments and index it."""
    archive = os.path.join(fresh_workspace.input_path, "vex-all.tar.xz")
    _build_sample_archive(fixture_dir, "vex", "vex", archive)
    store = _vex_store(fresh_workspace)
    store.write(archive, calendar=None, now=_utc("2026-09-10T00:00:00+00:00"))
    return VEXOverlay(store.fragment_paths(), store.statements_at)


def _vex_fragment_names(fresh_workspace) -> list[str]:
    directory = os.path.join(fresh_workspace.input_path, "vex-fragments")
    if not os.path.isdir(directory):
        return []
    return sorted(os.listdir(directory))


class TestVEXTokens:
    def test_codename_resolution_handles_both_token_shapes(self):
        assert vex_cache.codename_of_token("focal") == "focal"
        assert vex_cache.codename_of_token("esm-infra/focal") == "focal"
        assert vex_cache.codename_of_token("fips-updates/xenial") == "xenial"
        # the pocket is on the other side here; taking the tail gives "esm"
        assert vex_cache.codename_of_token("trusty/esm") == "trusty"

    def test_the_two_spellings_of_the_oldest_esm_pocket_join(self):
        assert canonical_token("trusty/esm") == canonical_token("esm-infra-legacy/trusty")
        # and nothing else is folded
        assert canonical_token("esm-infra/focal") == "esm-infra/focal"
        assert canonical_token("focal") == "focal"

    def test_slug_is_filesystem_safe(self):
        assert vex_cache.token_to_slug("esm-infra/focal") == "esm-infra-focal"
        assert vex_cache.token_to_slug("focal") == "focal"

    @pytest.mark.parametrize(
        ("token", "pocket", "ecosystem"),
        [
            # a release's own archive speaks for the release
            ("focal", "", "Ubuntu:20.04:LTS"),
            ("questing", "", "Ubuntu:25.10"),
            ("resolute", "", "Ubuntu:26.04:LTS"),
            # extended support pockets speak for the release too, both
            # spellings of the oldest one, but only to clear a package
            ("esm-infra/focal", "esm-infra", "Ubuntu:20.04:LTS"),
            ("esm-apps/focal", "esm-apps", "Ubuntu:20.04:LTS"),
            ("esm-infra-legacy/trusty", "esm-infra-legacy", "Ubuntu:14.04:LTS"),
            ("trusty/esm", "esm", "Ubuntu:14.04:LTS"),
            # separate builds, which map to no output namespace at all
            ("fips/focal", "fips", None),
            ("fips-updates/focal", "fips-updates", None),
            ("fips-preview/jammy", "fips-preview", None),
            ("realtime/jammy", "realtime", None),
            ("bluefield/noble", "bluefield", None),
            ("ros-esm/xenial", "ros-esm", None),
            # a release the vendored codename table stops short of, which the
            # calendar still knows
            ("natty", "", "Ubuntu:11.04"),
            # a codename neither knows resolves to nothing
            ("nonesuch", "", None),
        ],
    )
    def test_which_tokens_speak_for_which_release(self, fresh_workspace, fixture_dir, token, pocket, ecosystem):
        # One table decides both halves of this: `_POCKETS_THAT_ASSERT` says which
        # pockets may state anything about a release, and the calendar's series
        # column resolves the codename to the release itself.
        assert vex_cache.pocket_of_token(token) == pocket
        p = Parser(workspace=fresh_workspace)
        p._calendar = _load_fixture_calendar(fresh_workspace, fixture_dir)
        assert p._assertion_ecosystem_for_token(token) == ecosystem
        # and only a release's own archive may put a finding in its namespace
        assert vex_cache.token_asserts_findings(token) is (pocket == "")


class TestVEXFragmentStore:
    def _calendar(self, fresh_workspace, fixture_dir):
        return _load_fixture_calendar(fresh_workspace, fixture_dir)

    def test_all_four_statuses_round_trip_as_published(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        store.write(archive, calendar=None, now=_utc("2026-09-10T00:00:00+00:00"))

        rows = {(s.cve, s.token, s.package): s for s in store.statements()}
        statuses = {s.status for s in rows.values()}
        assert statuses == {"affected", "not_affected", "fixed", "under_investigation"}

        # CVE-2014-3566 (POODLE): a real statement of each shape
        wont_fix = rows[("CVE-2014-3566", "trusty", "openssl098")]
        assert wont_fix.status == "affected"
        assert wont_fix.action_statement.startswith("This package (for the given release)")

        cleared = rows[("CVE-2014-3566", "fips/xenial", "openssl")]
        assert cleared.status == "not_affected"
        assert cleared.justification == "vulnerable_code_not_present"

        absent = rows[("CVE-2014-3566", "xenial", "openjdk-6")]
        assert absent.status == "not_affected"
        assert absent.justification == "component_not_present"

        undetermined = rows[("CVE-2014-3566", "resolute", "pound")]
        assert undetermined.status == "under_investigation"

        # no verdict field is stored, and no version is taken from a product URL
        payload = vex_cache.VexStatement.to_payload(wont_fix)
        assert set(payload) == {"cve", "token", "package", "status", "justification", "action_statement"}

    def test_live_token_is_replaced_wholesale(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)
        store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        before = {(s.cve, s.token, s.package) for s in store.statements()}
        assert ("CVE-2014-3566", "focal", "openssl") in before

        # a download that no longer carries CVE-2014-3566 at all
        _seed_vex_cases_archive(fresh_workspace, fixture_dir, subdir="vex")
        store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))

        after = {(s.cve, s.token, s.package) for s in store.statements()}
        assert ("CVE-2014-3566", "focal", "openssl") not in after

    def test_frozen_token_keeps_its_statements(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)
        # before questing's eol: written like any live token
        store.write(archive, calendar=calendar, now=_utc("2026-07-08T00:00:00+00:00"))
        path = store.path_for("questing")
        before = open(path, "rb").read()

        # a later run, past the instant, whose download has no questing products
        _seed_vex_cases_archive(fresh_workspace, fixture_dir, subdir="vex")
        store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))

        assert open(path, "rb").read() == before

    def test_every_pocket_of_an_lts_is_live_and_plucky_is_not(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)
        # marker in place, so the ordinary rule applies with no bootstrap exception
        os.makedirs(store.directory, exist_ok=True)
        open(store.marker_path, "wb").close()

        store.write(archive, calendar=calendar, now=_utc("2031-05-01T00:00:00+00:00"))

        names = _vex_fragment_names(fresh_workspace)
        for token in ("focal", "esm-infra/focal", "trusty/esm", "esm-infra-legacy/trusty"):
            assert f"{vex_cache.token_to_slug(token)}.db" in names, token
        assert "plucky.db" not in names
        assert "questing.db" not in names

    def test_missing_archive_leaves_every_fragment_untouched(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        store.write(archive, calendar=None, now=_utc("2026-09-10T00:00:00+00:00"))
        before = {name: open(os.path.join(store.directory, name), "rb").read() for name in _vex_fragment_names(fresh_workspace)}

        os.remove(archive)
        store.write(archive, calendar=None, now=_utc("2026-09-11T00:00:00+00:00"))

        after = {name: open(os.path.join(store.directory, name), "rb").read() for name in _vex_fragment_names(fresh_workspace)}
        assert after == before

        # and the OSV write pass is unaffected by a missing VEX archive
        _seed_archive(fresh_workspace, fixture_dir)
        Parser(workspace=fresh_workspace)._write_fragments()
        assert "ubuntu-24.04-lts.db" in _fragment_paths(fresh_workspace)


class TestVEXBootstrap:
    def _calendar(self, fresh_workspace, fixture_dir):
        return _load_fixture_calendar(fresh_workspace, fixture_dir)

    def test_bootstrap_writes_a_frozen_token_once(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)
        assert not store.bootstrapped

        store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"), husk_releases=frozenset({"24.10", "25.04"}))

        names = _vex_fragment_names(fresh_workspace)
        # questing is frozen and gets its one initial write; plucky is a known husk
        assert "questing.db" in names
        assert "plucky.db" not in names
        assert vex_cache.BOOTSTRAP_MARKER in names
        questing_before = open(store.path_for("questing"), "rb").read()

        # a second run, with a changed questing statement in the feed
        changed = os.path.join(fixture_dir, "vex-cases", "cve", "2014", "CVE-2014-3566.json")
        with open(changed, "rb") as fh:
            original = fh.read()
        try:
            with open(changed, "wb") as fh:
                fh.write(original.replace(b"under_investigation", b"affected"))
            _seed_vex_cases_archive(fresh_workspace, fixture_dir)
            store.write(archive, calendar=calendar, now=_utc("2026-09-11T00:00:00+00:00"), husk_releases=frozenset({"24.10", "25.04"}))
        finally:
            with open(changed, "wb") as fh:
                fh.write(original)

        assert open(store.path_for("questing"), "rb").read() == questing_before

    def test_an_interrupted_bootstrap_resumes(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)

        real_writer = store._open_writer
        opened = []

        def explode(token):
            opened.append(token)
            if len(opened) > 1:
                raise RuntimeError("interrupted mid-pass")
            return real_writer(token)

        with patch.object(store, "_open_writer", side_effect=explode), pytest.raises(RuntimeError):
            store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))

        assert not store.bootstrapped

        # the next run is still a bootstrap run and finishes the job
        store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        assert store.bootstrapped
        assert "questing.db" in _vex_fragment_names(fresh_workspace)

    def test_after_the_marker_a_frozen_token_is_never_written(self, fresh_workspace, fixture_dir):
        archive = _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        store = _vex_store(fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)
        os.makedirs(store.directory, exist_ok=True)
        open(store.marker_path, "wb").close()

        store.write(archive, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))

        assert "questing.db" not in _vex_fragment_names(fresh_workspace)

    def test_the_osv_cache_gets_no_bootstrap(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # a frozen release with no fragment and records in the archive stays with none,
        # marker or no marker: the OSV cache is not a new cache kind.
        _seed_canonical_identity_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        calendar = self._calendar(fresh_workspace, fixture_dir)
        p._write_fragments(calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        assert "ubuntu-25.10.db" not in _fragment_paths(fresh_workspace)

        _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        assert p.vex_store.bootstrapped
        p._write_fragments(calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        assert "ubuntu-25.10.db" not in _fragment_paths(fresh_workspace)


# ---------------------------------------------------------------------------
# VEX judgements applied when records are emitted
# ---------------------------------------------------------------------------


def _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir):
    """Real records for the two pinned contradictions, trimmed to the releases under test."""
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv-vex-cases",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


def _run_with_vex(fresh_workspace, fixture_dir, downconvert: bool = False, now: str = "2026-09-10T00:00:00+00:00"):
    p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=downconvert)
    with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
        calendar = p._load_calendar()
    p._write_fragments(calendar=calendar, now=_utc(now))
    p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc(now), husk_releases=frozenset())
    p._vex_overlay = p._load_vex_overlay()
    if downconvert:
        return p, {t[0]: t[2] for t in p._iter_fragments_downconverted()}
    return p, {t[0]: t[2] for t in p._iter_fragments()}


def _xenial_affected(name: str) -> dict:
    return {
        "package": {"ecosystem": "Ubuntu:16.04:LTS", "name": name, "purl": f"pkg:deb/ubuntu/{name}@4.15.0-1?arch=source&distro=xenial"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
    }


def _pro_affected(name: str, fixed: str, token: str) -> dict:
    return {
        "package": {"ecosystem": "Ubuntu:Pro:20.04:LTS", "name": name, "purl": f"pkg:deb/ubuntu/{name}@{fixed}?arch=source&distro={token}"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


def _anchore_status(aff: dict) -> str | None:
    return ((aff.get("database_specific") or {}).get("anchore") or {}).get("status")


def _fixed_in_for(record: dict, package: str) -> list[dict]:
    return [f for f in record["Vulnerability"]["FixedIn"] if f["Name"] == package]


class TestVEXAtEmitTime:
    def test_confirmed_not_vulnerable_is_suppressed_on_both_emit_paths(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2023-2640 on linux-gke-5.15 / focal: OSV lists it as affected with no
        # fix, VEX states vulnerable_code_not_present. A live false positive today.
        # No finding is emitted for it on either path; what is emitted in its place
        # is the assertion, which test_a_clearance_replaces_an_osv_entry pins.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, osv_native = _run_with_vex(fresh_workspace, fixture_dir)
        entries = {a["package"]["name"]: a for a in osv_native["ubuntu-20.04-lts/ubuntu-cve-2023-2640"]["affected"]}
        assert _anchore_status(entries["linux-gke-5.15"]) == "not-affected"
        assert _anchore_status(entries["linux-gkeop-5.15"]) == "not-affected"
        # a package VEX does not clear is still a finding
        assert _anchore_status(entries["linux-hwe-5.11"]) != "not-affected"

        _p, downconverted = _run_with_vex(fresh_workspace, fixture_dir, downconvert=True)
        record = downconverted["ubuntu:20.04/cve-2023-2640"]
        assert [f["Version"] for f in _fixed_in_for(record, "linux-gke-5.15")] == ["0"]
        assert [f["Version"] for f in _fixed_in_for(record, "linux-hwe-5.11")] == ["None"]

    def test_a_clearance_replaces_an_osv_entry(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2023-2640 on linux-gke-5.15 / focal, where OSV lists the package as
        # affected and VEX says not_affected. The entry is replaced rather than
        # dropped: dropping it emits nothing, and nothing is what a consumer
        # already believes. The `"0"` has to be the package's only FixedIn in the
        # record or the group stops reading as a clearance.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, downconverted = _run_with_vex(fresh_workspace, fixture_dir, downconvert=True)
        cleared = _fixed_in_for(downconverted["ubuntu:20.04/cve-2023-2640"], "linux-gke-5.15")
        assert len(cleared) == 1
        assert cleared[0]["Version"] == "0"
        assert cleared[0]["VendorAdvisory"] == {"NoAdvisory": False}

    def test_a_vendor_clearance_osv_never_mentioned_is_asserted(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-3566 / pound / focal is not_affected in VEX and absent from the
        # OSV feed's 20.04 records entirely, so the whole record is the assertion.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, downconverted = _run_with_vex(fresh_workspace, fixture_dir, downconvert=True)
        record = downconverted["ubuntu:20.04/cve-2014-3566"]
        # pound is cleared at the base token and nss at esm-infra/focal; both
        # are the vendor's answer about the release and neither is in OSV
        assert record["Vulnerability"]["FixedIn"] == [
            {
                "Name": "pound",
                "NamespaceName": "ubuntu:20.04",
                "VersionFormat": "dpkg",
                "Version": "0",
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": None,
            },
            {
                "Name": "nss",
                "NamespaceName": "ubuntu:20.04",
                "VersionFormat": "dpkg",
                "Version": "0",
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": None,
            },
        ]

    def test_an_assertion_outranks_an_inference(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2022-49688 at xenial. Base 16.04 carries only linux-hwe-edge, which VEX
        # marks affected; the five Pro kernel flavours would each synthesize a base
        # entry, and VEX states vulnerable_code_not_present for every one of them.
        # Synthesized entries carry no purl, so this only works if the triple is
        # looked up explicitly at the base codename.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, downconverted = _run_with_vex(fresh_workspace, fixture_dir, downconvert=True)
        record = downconverted["ubuntu:16.04/cve-2022-49688"]
        inferred = {"linux-aws-hwe", "linux-azure", "linux-gcp", "linux-hwe", "linux-oracle"}
        for package in inferred:
            assert [f["Version"] for f in _fixed_in_for(record, package)] == ["0"], package
        # the one real base entry, which VEX agrees is affected, keeps its own shape
        assert [f["Version"] for f in _fixed_in_for(record, "linux-hwe-edge")] == ["None"]

    def test_inference_is_not_suppressed_without_an_assertion(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the same records with no VEX cache at all: all six entries emit
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _p, yielded = _run_with_vex(fresh_workspace, fixture_dir)
        packages = {a["package"]["name"] for a in yielded["ubuntu-16.04-lts/ubuntu-cve-2022-49688"]["affected"]}
        assert len(packages) == 6
        assert "linux-hwe-edge" in packages

    def test_an_undetermined_status_still_emits(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-3566 / resolute / pound is under_investigation in VEX. It emitted
        # as vulnerable-with-no-fix before this provider read OSV at all, and
        # suppressing it here would drop tens of thousands of real findings.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-26.04-lts",
            "ubuntu-26.04-lts/ubuntu-cve-2014-3566",
            {
                "id": "UBUNTU-CVE-2014-3566",
                "upstream": ["CVE-2014-3566"],
                "affected": [
                    {
                        "package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "pound", "purl": "pkg:deb/ubuntu/pound@4.14?arch=source&distro=resolute"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    },
                    {
                        "package": {"ecosystem": "Ubuntu:26.04:LTS", "name": "nss", "purl": "pkg:deb/ubuntu/nss@3.1?arch=source&distro=resolute"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    },
                ],
            },
        )
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        p.vex_store.write(p.vex_archive_path, calendar=None, now=_utc("2026-09-10T00:00:00+00:00"))
        p._vex_overlay = p._load_vex_overlay()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        entries = {a["package"]["name"]: a for a in yielded["ubuntu-26.04-lts/ubuntu-cve-2014-3566"]["affected"]}
        assert "pound" in entries, "under_investigation must not be treated as a clearance"
        assert _anchore_status(entries["pound"]) != "not-affected"
        # nss on resolute is not_affected, so that one stops being a finding
        assert _anchore_status(entries["nss"]) == "not-affected"

    def test_a_frozen_release_is_suppressed_by_its_own_frozen_statements(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # questing is frozen, its VEX fragment was written on the bootstrap run, and
        # today's download carries nothing for it.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-2014-3566",
            {
                "id": "UBUNTU-CVE-2014-3566",
                "upstream": ["CVE-2014-3566"],
                "affected": [
                    {
                        "package": {"ecosystem": "Ubuntu:25.10", "name": "nss", "purl": "pkg:deb/ubuntu/nss@3.1?arch=source&distro=questing"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    },
                ],
            },
        )
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        assert os.path.isfile(p.vex_store.path_for("questing"))

        # today's download has no questing statements at all
        _build_sample_archive(fixture_dir, "vex", "vex", p.vex_archive_path)
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-11T00:00:00+00:00"))
        p._calendar = calendar
        p._vex_overlay = p._load_vex_overlay()

        yielded = {t[0]: t[2] for t in p._iter_fragments()}
        entries = {a["package"]["name"]: a for a in yielded["ubuntu-25.10/ubuntu-cve-2014-3566"]["affected"]}
        assert _anchore_status(entries["nss"]) == "not-affected", "the frozen statements still answer for the frozen release"

    def test_a_frozen_token_still_asserts(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the same frozen questing fragment, read on the downconverted path: the
        # cached statements are the only thing that can state the clearance, since
        # neither feed carries the release any more.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-2014-3566",
            {
                "id": "UBUNTU-CVE-2014-3566",
                "upstream": ["CVE-2014-3566"],
                "affected": [
                    {
                        "package": {"ecosystem": "Ubuntu:25.10", "name": "nss", "purl": "pkg:deb/ubuntu/nss@3.1?arch=source&distro=questing"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    },
                ],
            },
        )
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))

        # today's download has no questing statements at all
        _build_sample_archive(fixture_dir, "vex", "vex", p.vex_archive_path)
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-11T00:00:00+00:00"))
        p._calendar = calendar
        p._vex_overlay = p._load_vex_overlay()

        record = {t[0]: t[2] for t in p._iter_fragments_downconverted()}["ubuntu:25.10/cve-2014-3566"]
        assert [f["Version"] for f in _fixed_in_for(record, "nss")] == ["0"]

    def test_a_release_with_no_statements_is_not_suppressed_into_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _plant_fragment(
            fresh_workspace,
            "ubuntu-25.10",
            "ubuntu-25.10/ubuntu-cve-2014-3566",
            {
                "id": "UBUNTU-CVE-2014-3566",
                "upstream": ["CVE-2014-3566"],
                "affected": [
                    {
                        "package": {"ecosystem": "Ubuntu:25.10", "name": "nss", "purl": "pkg:deb/ubuntu/nss@3.1?arch=source&distro=questing"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    },
                ],
            },
        )
        p = Parser(workspace=fresh_workspace)
        p._vex_overlay = p._load_vex_overlay()
        assert "ubuntu-25.10/ubuntu-cve-2014-3566" in {t[0] for t in p._iter_fragments()}

    def test_vex_supplies_no_fix_version_and_a_fixed_statement_states_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-3566 carries a `fixed` VEX statement for focal/openssl at
        # 1.1.1f-1ubuntu2.24, and no OSV record for it exists in this workspace.
        # The version on a `fixed` statement is the pocket's current version
        # rather than the version that fixed the CVE, so there is nothing to
        # state for openssl and the version must appear nowhere.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        _p, yielded = _run_with_vex(fresh_workspace, fixture_dir)

        named = {a["package"]["name"] for payload in yielded.values() for a in payload["affected"]}
        assert "openssl" not in named
        # the same CVE's not_affected statement for focal is stated, so the
        # absence above is the `fixed` status and not the record going missing
        assert "ubuntu-20.04-lts/ubuntu-cve-2014-3566" in yielded

        fixed_versions = {
            s.package: s
            for s in _vex_store(fresh_workspace).statements()
            if s.status == "fixed" and s.token == "focal"
        }
        assert "openssl" in fixed_versions
        assert not hasattr(fixed_versions["openssl"], "version")
        emitted = orjson.dumps(yielded).decode()
        assert "1.1.1f-1ubuntu2.24" not in emitted


class TestUnionEnumeration:
    """What is emitted for a release is the union of its OSV records and its VEX statements.

    The OSV feed lists what is affected, so a package the vendor has cleared is
    absent from it and indistinguishable from one nobody has looked at. The
    statements are the vendor's complete word on the release, and the two are
    joined per (CVE, source package) at yield.
    """

    def test_a_pocket_clearance_is_asserted_and_the_esm_channel_is_not(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # linux-bluefield on CVE-2023-2640 is not_affected at esm-infra/focal and
        # has a real Pro fix on the fragment. The clearance removes the `+esm`
        # entry, as it always did, and states the `"0"` row in the base namespace
        # — over the Pro-to-base inference, which would otherwise call the
        # package vulnerable with no fix. The `+esm` channel carries fix versions
        # only and never a clearance.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-pro-20.04-lts",
            "ubuntu-pro-20.04-lts/ubuntu-cve-2023-2640",
            {
                "id": "UBUNTU-CVE-2023-2640",
                "upstream": ["CVE-2023-2640"],
                "affected": [
                    _pro_affected("linux-bluefield", "5.4.0-1096.104", "esm-infra/focal"),
                    _pro_affected("linux-hwe-5.15", "5.15.0-177.187~20.04.1", "esm-infra/focal"),
                ],
            },
        )
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        p._calendar = calendar
        p._vex_overlay = p._load_vex_overlay()
        emitted = {t[0]: t[2] for t in p._iter_fragments_downconverted()}

        esm = {f["Name"] for f in emitted["ubuntu:20.04+esm/cve-2023-2640"]["Vulnerability"]["FixedIn"]}
        assert esm == {"linux-hwe-5.15"}, "the pocket clearance still removes the extended-support entry"

        base = emitted["ubuntu:20.04/cve-2023-2640"]
        # the pocket clearance is the answer for the base release, over the
        # inference that would have called it vulnerable
        assert [f["Version"] for f in _fixed_in_for(base, "linux-bluefield")] == ["0"]
        # and the base token's own clearances are unchanged
        assert [f["Version"] for f in _fixed_in_for(base, "linux-gke")] == ["0"]
        # nothing anywhere in the `+esm` channel is a clearance
        for identifier, record in emitted.items():
            if "+esm" not in identifier:
                continue
            assert [f["Version"] for f in record["Vulnerability"]["FixedIn"] if f["Version"] == "0"] == []

    def test_a_vex_only_affected_becomes_a_finding_and_a_fixed_one_does_not(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2022-50031 at jammy: `linux` carries the needs-fixing prose and
        # `linux-riscv` the won't-fix prose, neither has an OSV entry, and
        # `linux-aws-6.8` is not_affected. CVE-2014-3566 at jammy carries a
        # `fixed` statement for openssl and nothing else for it.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-22.04-lts",
            "ubuntu-22.04-lts/ubuntu-cve-2026-1403",
            {
                "id": "UBUNTU-CVE-2026-1403",
                "upstream": ["CVE-2026-1403"],
                "affected": [
                    {
                        "package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "gitlab", "purl": "pkg:deb/ubuntu/gitlab@1.0?arch=source&distro=jammy"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    },
                ],
            },
        )
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        p._calendar = calendar
        p._vex_overlay = p._load_vex_overlay()
        emitted = {t[0]: t[2] for t in p._iter_fragments_downconverted()}

        record = emitted["ubuntu:22.04/cve-2022-50031"]
        assert _fixed_in_for(record, "linux")[0]["Version"] == "None"
        assert _fixed_in_for(record, "linux")[0]["VendorAdvisory"] == {"NoAdvisory": False}
        assert _fixed_in_for(record, "linux-riscv")[0]["Version"] == "None"
        assert _fixed_in_for(record, "linux-riscv")[0]["VendorAdvisory"] == {"NoAdvisory": True}
        assert _fixed_in_for(record, "linux-aws-6.8")[0]["Version"] == "0"

        fixed_statement = emitted["ubuntu:22.04/cve-2014-3566"]
        assert _fixed_in_for(fixed_statement, "openssl") == []
        assert {f["Name"] for f in fixed_statement["Vulnerability"]["FixedIn"]} == {"nss", "pound"}

    def test_a_component_not_present_statement_states_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # `component_not_present` is the tracker's DNE: the release does not ship
        # the package at all, so there is nothing for a record to be about and the
        # pre-OSV provider emitted nothing for it. It is not
        # `vulnerable_code_not_present`, which is a researched conclusion about a
        # package the release does ship and is worth stating.
        #
        # At xenial, CVE-2023-2640 and CVE-2022-49688 both carry
        # component_not_present for linux-azure-edge. The first has no OSV entry
        # for it; the second is planted with one.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-16.04-lts",
            "ubuntu-16.04-lts/ubuntu-cve-2023-2640",
            {
                "id": "UBUNTU-CVE-2023-2640",
                "upstream": ["CVE-2023-2640"],
                "affected": [_xenial_affected("linux-hwe-edge")],
            },
        )
        _plant_envelope(
            fresh_workspace,
            "ubuntu-16.04-lts",
            "ubuntu-16.04-lts/ubuntu-cve-2022-49688",
            {
                "id": "UBUNTU-CVE-2022-49688",
                "upstream": ["CVE-2022-49688"],
                "affected": [_xenial_affected("linux-azure-edge"), _xenial_affected("linux-hwe-edge")],
            },
        )
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"))
        p._calendar = calendar
        p._vex_overlay = p._load_vex_overlay()
        emitted = {t[0]: t[2] for t in p._iter_fragments_downconverted()}

        # no OSV entry: nothing is stated for it
        assert _fixed_in_for(emitted["ubuntu:16.04/cve-2023-2640"], "linux-azure-edge") == []
        # an OSV entry: dropped, and nothing stated in its place
        assert _fixed_in_for(emitted["ubuntu:16.04/cve-2022-49688"], "linux-azure-edge") == []
        # while a vulnerable_code_not_present clearance for the same release is stated
        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:16.04/cve-2022-49688"], "linux-kvm")] == ["0"]
        # and the package neither clears is still a finding
        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:16.04/cve-2022-49688"], "linux-hwe-edge")] == ["None"]

    def test_a_rejection_learned_from_another_release_is_not_rebuilt(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2026-38969, CVE-2026-41603 and CVE-2026-58212 are CVE-program
        # rejections in the `Rejected reason:` form. Each names only Ubuntu:25.10
        # in OSV — the one release Canonical was still publishing for when the
        # rejection landed — while VEX carries a clearance for jammy and noble.
        # A rejection is a fact about the CVE, so 22.04 and 24.04 have to inherit
        # it from the record that states it or they rebuild the CVE from their
        # own statements, which carry no `details` to be asked.
        for slug, eco in (("ubuntu-22.04-lts", "Ubuntu:22.04:LTS"), ("ubuntu-24.04-lts", "Ubuntu:24.04:LTS")):
            _plant_fragment(
                fresh_workspace,
                slug,
                f"{slug}/ubuntu-cve-2026-1403",
                {
                    "id": "UBUNTU-CVE-2026-1403",
                    "upstream": ["CVE-2026-1403"],
                    "affected": [
                        {
                            "package": {"ecosystem": eco, "name": "gitlab", "purl": "pkg:deb/ubuntu/gitlab@1.0?arch=source&distro=jammy"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                        },
                    ],
                },
            )
        _build_sample_archive(fixture_dir, "osv-rejection-echo", "osv", os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"))
        _seed_vex_cases_archive(fresh_workspace, fixture_dir, subdir="vex-rejection-echo")

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            calendar = p._load_calendar()
        now = _utc("2026-09-10T00:00:00+00:00")
        # questing is frozen at this instant, so the rejected records are read for
        # their `details` and written nowhere
        p._write_fragments(calendar=calendar, now=now)
        assert not os.path.exists(os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-25.10.db"))
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=now, husk_releases=frozenset())
        p._calendar = calendar
        p._vex_overlay = p._load_vex_overlay()

        emitted = {t[0] for t in p._iter_fragments_downconverted()}
        for cve in ("cve-2026-38969", "cve-2026-41603", "cve-2026-58212"):
            for namespace in ("ubuntu:22.04", "ubuntu:24.04"):
                assert f"{namespace}/{cve}" not in emitted
        # the run did emit, so the assertion above is not vacuous
        assert "ubuntu:22.04/cve-2026-1403" in emitted

    def test_the_whole_group_sentinel_holds_across_a_run(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The consumer reads a package group as unaffected only when every FixedIn
        # in it is exactly the one character `0`. A stray second entry for the same
        # package turns a suppression into a `< 0` constraint, which `0~`-prefixed
        # dpkg versions satisfy.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        _p, emitted = _run_with_vex(fresh_workspace, fixture_dir, downconvert=True)

        asserted = 0
        for identifier, record in emitted.items():
            by_package = {}
            for entry in record["Vulnerability"]["FixedIn"]:
                by_package.setdefault(entry["Name"], []).append(entry["Version"])
            for package, versions in by_package.items():
                if "0" not in versions:
                    continue
                asserted += 1
                assert versions == ["0"], f"{identifier} {package} mixes a clearance with {versions}"
        assert asserted > 0


# ---------------------------------------------------------------------------
# A researched clearance outranks everything said about the combination
#
# The fixtures under test-fixtures/osv-clearance-cases/ and
# test-fixtures/vex-clearance-cases/ are the real records behind the two
# findings the quality gate turned up, trimmed on the VEX side to the
# `arch=source` products of the focal and xenial tokens.


def _run_clearance_cases(fresh_workspace, fixture_dir, tracker: bool = False):
    _build_sample_archive(fixture_dir, "osv-clearance-cases", "osv", os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"))
    _seed_vex_cases_archive(fresh_workspace, fixture_dir, subdir="vex-clearance-cases")
    if tracker:
        _seed_tracker_snapshot(fresh_workspace, fixture_dir, subdir="tracker-clearance-cases")

    p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
    with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
        calendar = p._load_calendar()
    now = _utc("2026-09-10T00:00:00+00:00")
    p._write_fragments(calendar=calendar, now=now)
    p.vex_store.write(p.vex_archive_path, calendar=calendar, now=now, husk_releases=frozenset())
    p._calendar = calendar
    p._vex_overlay = p._load_vex_overlay()
    p.tracker_index.build(p.normalized_cve_dir)
    return p, {t[0]: t[2] for t in p._iter_fragments_downconverted()}


class TestClearanceOutranksEverything:
    """A `vulnerable_code_not_present` statement at any token of the release wins."""

    @pytest.mark.parametrize("cve", ["cve-2020-19185", "cve-2020-19186", "cve-2020-19187", "cve-2020-19188", "cve-2020-19190"])
    def test_a_pocket_clearance_outranks_an_osv_fix(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, cve):
        # Canonical's tracker says `not-affected (6.2-0ubuntu2.1)` for ncurses on
        # focal, and its OSV generator re-encodes that as a range fixed at the
        # same version — byte-identical to the encoding of the real fix for
        # CVE-2021-39537. OSV cannot tell the two apart; VEX can, and clears
        # these five at esm-infra/focal.
        _p, emitted = _run_clearance_cases(fresh_workspace, fixture_dir)
        assert [f["Version"] for f in _fixed_in_for(emitted[f"ubuntu:20.04/{cve}"], "ncurses")] == ["0"]

    def test_the_control_fix_on_the_same_package_survives(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2021-39537 on the same package and the same version, `released` in
        # the tracker and `fixed` in VEX. Nothing clears it, so it keeps its fix.
        _p, emitted = _run_clearance_cases(fresh_workspace, fixture_dir)
        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:20.04/cve-2021-39537"], "ncurses")] == ["6.2-0ubuntu2.1"]

    def test_a_base_needs_triage_yields_to_a_pocket_clearance(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The gate's finding A. The base release is `needs-triage` in the frozen
        # snapshot — an absence of research — while the ESM team that maintains
        # the same source package cleared it. The pre-OSV provider had this rule
        # and the OSV rewrite lost it.
        _p, emitted = _run_clearance_cases(fresh_workspace, fixture_dir, tracker=True)

        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:20.04/cve-2019-20788"], "x11vnc")] == ["0"]
        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:20.04/cve-2021-37529"], "fig2dev")] == ["0"]

        # nasm is the third package in that finding and it is the one that needs
        # both halves of the rule. Canonical publishes no VEX statement clearing
        # it at any focal token — base focal says `affected` — so its only
        # clearance is the ESM pocket's row in the snapshot's `ignored_patches`,
        # which is where `3032ece` read it from. Reading only VEX leaves this a
        # false positive that the pre-OSV provider suppressed.
        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:20.04/cve-2020-21685"], "nasm")] == ["0"]

        # The cost, recorded where it will be seen rather than asserted here,
        # because it needs fixtures this case does not carry: CVE-2021-33452 on
        # the same package holds the identical esm-apps/focal clearance and was
        # labelled a true positive by hand. The clearance cannot tell it apart
        # from the two false positives, and neither could 3032ece.

    def test_a_pocket_clearance_outranks_a_base_affected(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2022-4450 on xenial openssl: the base token says `affected`, which
        # on a release past standard support is the lifecycle boilerplate, and
        # esm-infra-legacy/xenial says the vulnerable code is not there.
        _p, emitted = _run_clearance_cases(fresh_workspace, fixture_dir)
        assert [f["Version"] for f in _fixed_in_for(emitted["ubuntu:16.04/cve-2022-4450"], "openssl")] == ["0"]

    def test_a_fips_clearance_asserts_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # fips/focal and fips-updates/focal clear four kernel builds for
        # CVE-2023-2640. They are separate builds that map to no output
        # namespace, so they say nothing about the base release either way.
        _seed_osv_vex_cases_archive(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)
        _p, emitted = _run_with_vex(fresh_workspace, fixture_dir, downconvert=True)

        named = {f["Name"] for record in emitted.values() for f in record["Vulnerability"]["FixedIn"]}
        for package in ("linux-fips", "linux-aws-fips", "linux-azure-fips", "linux-gcp-fips"):
            assert package not in named

    def test_a_pocket_component_not_present_asserts_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The other justification stays what it was: the pocket does not ship the
        # package, which is a fact about the pocket's own entry and not a
        # clearance to assert anywhere. Only seven such rows exist on
        # esm-infra/focal feed-wide and none is in the fixture set, so the
        # statement is written straight into the cache in the shape it is held.
        _plant_fragment(
            fresh_workspace,
            "ubuntu-pro-20.04-lts",
            "ubuntu-pro-20.04-lts/ubuntu-cve-2023-2640",
            {
                "id": "UBUNTU-CVE-2023-2640",
                "upstream": ["CVE-2023-2640"],
                "affected": [_pro_affected("linux-hwe-5.15", "5.15.0-177.187~20.04.1", "esm-infra/focal")],
            },
        )
        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            p._calendar = p._load_calendar()
        _plant_vex_statement(
            fresh_workspace,
            "esm-infra/focal",
            [
                vex_cache.VexStatement(
                    cve="CVE-2023-2640",
                    token="esm-infra/focal",
                    package="linux-hwe-5.15",
                    status="not_affected",
                    justification="component_not_present",
                ),
            ],
        )
        p._vex_overlay = p._load_vex_overlay()
        emitted = {t[0]: t[2] for t in p._iter_fragments_downconverted()}

        # the pocket's own entry is gone, so the +esm record is gone with it
        assert "ubuntu:20.04+esm/cve-2023-2640" not in emitted
        # and nothing is asserted in the base namespace in its place: the base
        # entry is the Pro-to-base inference's, which this statement does not
        # speak to either way
        base = emitted["ubuntu:20.04/cve-2023-2640"]
        assert [f["Version"] for f in _fixed_in_for(base, "linux-hwe-5.15")] == ["None"]
        assert [f for f in base["Vulnerability"]["FixedIn"] if f["Version"] == "0"] == []


# ---------------------------------------------------------------------------
# The frozen tracker snapshot, read where neither current feed speaks
#
# The fixtures under test-fixtures/tracker-snapshot/ are two real files from
# `normalized-cve-data/`, copied whole. CVE-2014-3566 carries every status the
# emit path maps — `released`, `not-affected`, `needed`, `DNE` — and
# CVE-2006-2692 carries the `ignored` one.


def _seed_tracker_snapshot(fresh_workspace, fixture_dir, subdir: str = "tracker-snapshot") -> str:
    dst = os.path.join(fresh_workspace.input_path, "normalized-cve-data")
    shutil.copytree(os.path.join(fixture_dir, subdir), dst, dirs_exist_ok=True)
    return dst


def _trusty_affected(name: str, fixed: str | None = None) -> dict:
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {
        "package": {"ecosystem": "Ubuntu:14.04:LTS", "name": name, "purl": f"pkg:deb/ubuntu/{name}@1.0?arch=source&distro=trusty"},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
    }


def _plant_vex_statement(fresh_workspace, token: str, statements: list[vex_cache.VexStatement]) -> str:
    """Write VEX rows straight into a token's fragment, in the shape the cache holds."""
    directory = os.path.join(fresh_workspace.input_path, "vex-fragments")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{vex_cache.token_to_slug(token)}.db")
    with result.Writer(
        workspace=fresh_workspace,
        result_state_policy=result.ResultStatePolicy.KEEP,
        store_strategy=result.StoreStrategy.SQLITE,
        write_location=path,
    ) as w:
        for statement in statements:
            w.write(identifier=statement.identifier, schema=schema.AnnotatedOpenVEXSchema(), payload=statement.to_payload())
    return path


def _run_with_tracker(fresh_workspace, fixture_dir, vex: bool = True, downconvert: bool = True):
    p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=downconvert)
    with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
        calendar = p._load_calendar()
    if vex:
        p.vex_store.write(p.vex_archive_path, calendar=calendar, now=_utc("2026-09-10T00:00:00+00:00"), husk_releases=frozenset())
    p._calendar = calendar
    p._vex_overlay = p._load_vex_overlay()
    p.tracker_index.build(p.normalized_cve_dir)
    emitted = p._iter_fragments_downconverted() if downconvert else p._iter_fragments()
    return p, {t[0]: t[2] for t in emitted}


class TestTrackerSnapshot:
    """The third source: what the frozen snapshot still says and neither feed does."""

    def _plant_trusty(self, fresh_workspace):
        # one unrelated envelope, so 14.04 is a release the emit path walks
        _plant_fragment(
            fresh_workspace,
            "ubuntu-14.04-lts",
            "ubuntu-14.04-lts/ubuntu-cve-2026-1403",
            {"id": "UBUNTU-CVE-2026-1403", "upstream": ["CVE-2026-1403"], "affected": [_trusty_affected("gitlab")]},
        )

    def test_every_tracker_status_maps_as_the_legacy_path_mapped_it(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Compare against parser_legacy.map_parsed, which still emits from these
        # same files for releases the OSV feed does not cover: `released` is a
        # fix at the version, `ignored` is won't-fix, `not-affected` is the "0"
        # row, `needed` is a finding with no fix, and `DNE` is nothing at all.
        self._plant_trusty(fresh_workspace)
        _plant_fragment(
            fresh_workspace,
            "ubuntu-16.04-lts",
            "ubuntu-16.04-lts/ubuntu-cve-2026-1403",
            {
                "id": "UBUNTU-CVE-2026-1403",
                "upstream": ["CVE-2026-1403"],
                "affected": [_xenial_affected("gitlab")],
            },
        )
        _seed_tracker_snapshot(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, emitted = _run_with_tracker(fresh_workspace, fixture_dir)

        trusty = emitted["ubuntu:14.04/cve-2014-3566"]
        # released: the tracker's own version, and the fix date the run found for it
        assert [f["Version"] for f in _fixed_in_for(trusty, "openssl")] == ["1.0.1f-1ubuntu2.7"]
        assert _fixed_in_for(trusty, "openssl")[0]["Available"] == {"Date": "2024-01-01", "Kind": "first-observed"}
        # not-affected: the "0" row
        assert [f["Version"] for f in _fixed_in_for(trusty, "nss")] == ["0"]
        # needed: a finding with no fix, and an advisory is not ruled out
        assert _fixed_in_for(trusty, "pound")[0]["Version"] == "None"
        assert _fixed_in_for(trusty, "pound")[0]["VendorAdvisory"] == {"NoAdvisory": False}
        # ignored: a finding with no fix and no advisory coming
        ignored = emitted["ubuntu:14.04/cve-2006-2692"]
        assert _fixed_in_for(ignored, "amule")[0]["Version"] == "None"
        assert _fixed_in_for(ignored, "amule")[0]["VendorAdvisory"] == {"NoAdvisory": True}
        # DNE: xenial never shipped openssl098, and the snapshot says so, so
        # nothing is emitted for it
        assert _fixed_in_for(emitted["ubuntu:16.04/cve-2014-3566"], "openssl098") == []

    def test_a_vex_fixed_statement_takes_the_trackers_version(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # VEX marks trusty/openjdk-6 and trusty/openjdk-7 fixed for CVE-2014-3566
        # and no OSV record carries them, so before the snapshot was read there
        # was a statement that a fix exists and no version to state.
        self._plant_trusty(fresh_workspace)
        _seed_tracker_snapshot(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, emitted = _run_with_tracker(fresh_workspace, fixture_dir)
        trusty = emitted["ubuntu:14.04/cve-2014-3566"]
        assert [f["Version"] for f in _fixed_in_for(trusty, "openjdk-6")] == ["6b34-1.13.6-1ubuntu0.14.04.1"]
        assert [f["Version"] for f in _fixed_in_for(trusty, "openjdk-7")] == ["7u75-2.5.4-1~trusty1"]

    def test_a_vex_fixed_statement_with_no_tracker_row_states_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the same statements against a snapshot that does not carry the CVE at
        # all: a `fixed` statement has no version of its own, so there is still
        # nothing to say
        self._plant_trusty(fresh_workspace)
        _seed_tracker_snapshot(fresh_workspace, fixture_dir, subdir="normalized-cve-data")
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        _p, emitted = _run_with_tracker(fresh_workspace, fixture_dir)
        trusty = emitted["ubuntu:14.04/cve-2014-3566"]
        assert _fixed_in_for(trusty, "openjdk-6") == []
        assert _fixed_in_for(trusty, "openjdk-7") == []

    def test_the_trackers_version_loses_to_osvs(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the OSV feed is authoritative for a fix version wherever it has one
        _plant_fragment(
            fresh_workspace,
            "ubuntu-14.04-lts",
            "ubuntu-14.04-lts/ubuntu-cve-2014-3566",
            {
                "id": "UBUNTU-CVE-2014-3566",
                "upstream": ["CVE-2014-3566"],
                "affected": [_trusty_affected("openssl", fixed="1.0.1f-9ubuntu9.9")],
            },
        )
        _seed_tracker_snapshot(fresh_workspace, fixture_dir)

        _p, emitted = _run_with_tracker(fresh_workspace, fixture_dir, vex=False)
        versions = [f["Version"] for f in _fixed_in_for(emitted["ubuntu:14.04/cve-2014-3566"], "openssl")]
        assert versions == ["1.0.1f-9ubuntu9.9"], "the tracker's 1.0.1f-1ubuntu2.7 must not be added beside it"

    def test_a_current_statement_outranks_the_snapshot(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Two shapes. openssl098 is `needed` in the snapshot and won't-fix in
        # VEX, so the emitted finding rules out an advisory. openjdk-6 is
        # `released` in the snapshot with a real version, and the planted
        # statement says the release does not ship the package at all — which
        # the live feeds never say together, so it is planted rather than found.
        self._plant_trusty(fresh_workspace)
        _seed_tracker_snapshot(fresh_workspace, fixture_dir)
        _seed_vex_cases_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with _redirect_calendar_download(_calendar_bytes(fixture_dir)):
            p._calendar = p._load_calendar()
        p.vex_store.write(p.vex_archive_path, calendar=p._calendar, now=_utc("2026-09-10T00:00:00+00:00"), husk_releases=frozenset())
        _plant_vex_statement(
            fresh_workspace,
            "trusty",
            [
                vex_cache.VexStatement(
                    cve="CVE-2014-3566",
                    token="trusty",
                    package="openjdk-6",
                    status="not_affected",
                    justification="component_not_present",
                ),
            ],
        )
        p._vex_overlay = p._load_vex_overlay()
        p.tracker_index.build(p.normalized_cve_dir)
        emitted = {t[0]: t[2] for t in p._iter_fragments_downconverted()}

        trusty = emitted["ubuntu:14.04/cve-2014-3566"]
        assert _fixed_in_for(trusty, "openjdk-6") == []
        assert _fixed_in_for(trusty, "openssl098")[0]["Version"] == "None"
        assert _fixed_in_for(trusty, "openssl098")[0]["VendorAdvisory"] == {"NoAdvisory": True}

    def test_the_index_is_built_once_and_not_rebuilt(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_tracker_snapshot(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        assert p.tracker_index.codenames_on_disk() == []

        p.tracker_index.build(p.normalized_cve_dir)
        assert p.tracker_index.built
        codenames = p.tracker_index.codenames_on_disk()
        assert "trusty" in codenames
        before = {c: os.stat(p.tracker_index.path_for(c)).st_mtime_ns for c in codenames}

        # the snapshot cannot change, so a later run reads the index rather than
        # paying for it again — even if the files underneath it change
        os.remove(os.path.join(p.normalized_cve_dir, "CVE-2014-3566"))
        p.tracker_index.build(p.normalized_cve_dir)
        assert {c: os.stat(p.tracker_index.path_for(c)).st_mtime_ns for c in codenames} == before
        assert p.tracker_index.rows_for("trusty")[("CVE-2014-3566", "openssl")].version == "1.0.1f-1ubuntu2.7"


# ---------------------------------------------------------------------------
# Withdrawn records, and the one class of them that is a real retraction
# ---------------------------------------------------------------------------


def _seed_withdrawn_archive(fresh_workspace, fixture_dir):
    """Real feed records covering every published rejection prefix, and two that aren't.

    UBUNTU-CVE-2014-6422  withdrawn, ordinary description, carries a released fix
    UBUNTU-CVE-2014-0177  withdrawn, ordinary description, Pro-only (drives the inference)
    UBUNTU-CVE-2021-23334 withdrawn, `** REJECT **`
    UBUNTU-CVE-2011-4898  withdrawn, `** DISPUTED **`
    UBUNTU-CVE-2014-9297  NOT withdrawn, `Rejected reason:`, carries a released fix
    UBUNTU-CVE-2014-1850  withdrawn, `** REJECT **`, carries a released fix
    """
    _build_sample_archive(
        fixture_dir,
        source_subdir="osv-withdrawn",
        archive_prefix="osv",
        dst_path=os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
    )


class TestCVEProgramRejection:
    @pytest.mark.parametrize(
        "details",
        [
            "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.",
            "** DISPUTED ** wp-admin/setup-config.php in the installation component",
            "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.",
            "  ** reject ** leading whitespace and lower case",
            "\n\t** Disputed ** mixed case",
        ],
    )
    def test_every_published_form_is_recognized(self, details):
        assert is_cve_program_rejection({"details": details}) is True

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"details": None},
            {"details": ""},
            {"details": "The SDP dissector in Wireshark 1.10.x before 1.10.10 creates duplicate"},
            {"details": "a record that merely mentions ** REJECT ** halfway through"},
        ],
    )
    def test_ordinary_records_are_not_rejections(self, payload):
        assert is_cve_program_rejection(payload) is False


class TestWithdrawnRecords:
    def _run(self, fresh_workspace, fixture_dir, downconvert: bool):
        _seed_withdrawn_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=downconvert)
        with (
            patch.object(p, "_download_archive"),
            patch.object(p, "_download_vex_archive"),
            _patch_calendar_download(p, fixture_dir),
        ):
            return {t[0]: t[2] for t in p.get()}

    def test_withdrawn_record_with_a_fix_is_emitted(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2014-6422: withdrawn, wireshark on 14.04, fixed at
        # 1.12.1+g01b65bf-4+deb8u11ubuntu0.14.04.1. Real fix data that used to be dropped.
        yielded = self._run(fresh_workspace, fixture_dir, downconvert=True)
        vuln = yielded["ubuntu:14.04/cve-2014-6422"]["Vulnerability"]
        wireshark = next(f for f in vuln["FixedIn"] if f["Name"] == "wireshark")
        assert wireshark["Version"] == "1.12.1+g01b65bf-4+deb8u11ubuntu0.14.04.1"
        assert wireshark["VendorAdvisory"]["NoAdvisory"] is False

    def test_withdrawn_record_is_emitted_on_the_osv_native_path_too(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        yielded = self._run(fresh_workspace, fixture_dir, downconvert=False)
        assert "ubuntu-14.04-lts/ubuntu-cve-2014-6422" in yielded

    @pytest.mark.parametrize(
        ("cve", "marker"),
        [
            ("2021-23334", "** REJECT **"),
            ("2011-4898", "** DISPUTED **"),
            ("2014-9297", "Rejected reason:"),
            ("2014-1850", "** REJECT ** with a released fix"),
        ],
    )
    def test_every_rejection_form_is_suppressed(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, cve, marker):
        yielded = self._run(fresh_workspace, fixture_dir, downconvert=True)
        assert not any(cve in identifier for identifier in yielded), f"{marker} was emitted"

    def test_rejections_are_suppressed_on_the_osv_native_path_too(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        yielded = self._run(fresh_workspace, fixture_dir, downconvert=False)
        for cve in ("2021-23334", "2011-4898", "2014-9297", "2014-1850"):
            assert not any(cve in identifier for identifier in yielded), cve

    def test_emitting_withdrawn_records_adds_inferred_entries(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2014-0177 is withdrawn and Pro-only (nodejs on Pro:14.04/16.04/18.04).
        # Dropping withdrawn records lost the inference as well as the record.
        yielded = self._run(fresh_workspace, fixture_dir, downconvert=False)
        synth = yielded["ubuntu-14.04-lts/ubuntu-cve-2014-0177"]
        nodejs = synth["affected"][0]
        assert nodejs["package"]["name"] == "nodejs"
        assert nodejs["database_specific"]["anchore"]["inference"]["kind"] == "pro-only-fix"

    def test_a_rejected_pro_record_synthesizes_no_base_entry(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2021-23334 is `** REJECT **` and Pro-only (node-static-eval on
        # Pro:18.04/20.04). `_add_synthetic_envelope` copies `details` verbatim, so
        # without a check on the merge path the rejection would come back as a base record.
        yielded = self._run(fresh_workspace, fixture_dir, downconvert=False)
        assert not any("2021-23334" in identifier for identifier in yielded)
