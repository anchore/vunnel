from __future__ import annotations

import datetime
import os
import shutil
import tarfile
from unittest.mock import patch

import orjson
import pytest

from vunnel import provider, result, schema, workspace
from vunnel.providers.ubuntu import Config, Provider
from vunnel.providers.ubuntu.parser import (
    Parser,
    _annotate_wont_fix,
    _build_synthetic_base_affected,
    ecosystem_to_slug,
    pro_to_base_ecosystem,
    slice_by_ecosystem,
)
from vunnel.providers.ubuntu.vex_overlay import (
    VEXOverlay,
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
            assert "anchore" not in r.get("database_specific", {}), \
                "fragment payload should be raw OSV record, no fix-date patching at write time"

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
        fake_fixdate_finder(responses={
            "CVE-2013-2208": [Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)],
        })
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
        # 2026-1403 and 2020-36325 have only {"introduced": "0"} — patch_fix_date is a no-op
        for ident in ("ubuntu-16.04-lts/ubuntu-cve-2026-1403", "ubuntu-pro-14.04-lts/ubuntu-cve-2020-36325"):
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
        #   2020-36325 has only Ubuntu:Pro:14.04:LTS (jansson) → synthesize base 14.04/jansson
        #   2021-3782 has Ubuntu:Pro:16.04:LTS (wayland) but no base 16.04 for wayland in any
        #     fixture record → synthesize base 16.04/wayland (the existing 16.04 entry from
        #     CVE-2026-1403 is for gitlab, different package → doesn't suppress)
        assert ids == [
            "ubuntu-14.04-lts/ubuntu-cve-2013-2208",
            "ubuntu-14.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-14.04-lts/ubuntu-cve-2020-36325",   # ← inferred from Pro:14.04/jansson
            "ubuntu-16.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-16.04-lts/ubuntu-cve-2021-3782",    # ← inferred from Pro:16.04/wayland
            "ubuntu-16.04-lts/ubuntu-cve-2026-1403",
            "ubuntu-18.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-18.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-20.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-20.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-22.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-22.04-lts/ubuntu-cve-2021-3782",
            "ubuntu-24.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-pro-14.04-lts/ubuntu-cve-2016-20013",
            "ubuntu-pro-14.04-lts/ubuntu-cve-2020-36325",
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
        assert bionic_filtered_calls == [], (
            f"expected zero fixdater calls for OSV-covered CVE-2022-31258, got {bionic_filtered_calls}"
        )
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
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"):
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

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        # 17 real OSV envelopes + 2 inferred-from-Pro base envelopes
        # (Pro:14.04/jansson → base 14.04; Pro:16.04/wayland → base 16.04). See
        # test_iter_fragments_yields_envelopes_from_every_db_file for the breakdown.
        assert ws.num_result_entries() == 19

    def test_writes_per_record_osv_schema(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.downconvert_osv_to_os = False

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
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

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        # 17 real OSV + 2 inferred-from-Pro base envelopes + 5 legacy envelopes
        # (CVE-2022-31258 bionic filtered by OSV coverage on 18.04).
        # Legacy: 2012-5124×2 + 2013-6627×3 = 5
        assert ws.num_result_entries() == 24

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

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        ws.assert_result_snapshots()


# ---------------------------------------------------------------------------
# VEX overlay — wont-fix annotation from Canonical's OpenVEX feed
# ---------------------------------------------------------------------------


class TestVEXHelpers:
    """Pure-function tests for the VEX module."""

    def test_distro_label_from_purl(self):
        assert distro_label_from_purl(
            "pkg:deb/ubuntu/glibc@2.39-0ubuntu8.7?arch=source&distro=noble",
        ) == "noble"
        # ESM/Pro channels use compound distro labels
        assert distro_label_from_purl(
            "pkg:deb/ubuntu/eglibc@2.19-0ubuntu6.15+esm4?arch=source&distro=esm-infra-legacy/trusty",
        ) == "esm-infra-legacy/trusty"
        # No distro qualifier → None
        assert distro_label_from_purl("pkg:deb/ubuntu/foo@1.0") is None
        assert distro_label_from_purl("") is None

    def test_source_package_from_purl(self):
        assert source_package_from_purl(
            "pkg:deb/ubuntu/glibc@2.39-0ubuntu8.7?arch=source&distro=noble",
        ) == "glibc"
        assert source_package_from_purl("not-a-purl") is None
        assert source_package_from_purl("") is None

    def test_is_wont_fix_action_matches_both_canonical_openings(self):
        decided = (
            "This package (for the given release) is vulnerable to the CVE, "
            "the problem is understood, but the Ubuntu Security Team decided "
            "to not fix it. CVE Notes: ..."
        )
        assert is_wont_fix_action(decided) is True

        no_longer_supported = (
            "This package (for the given release) is no longer supported. "
            "CVE Notes: ..."
        )
        assert is_wont_fix_action(no_longer_supported) is True

    def test_is_wont_fix_action_rejects_needs_fixing(self):
        assert is_wont_fix_action(
            "This package (for the given release) is vulnerable to the CVE and needs fixing.",
        ) is False
        assert is_wont_fix_action(
            "This package (for the given release) is vulnerable to the CVE, "
            "needs fixing, and it is being actively worked on.",
        ) is False
        assert is_wont_fix_action(None) is False
        assert is_wont_fix_action("") is False
        assert is_wont_fix_action("some random text") is False


class TestVEXOverlay:
    """End-to-end overlay-from-tarball tests using the real-record fixture."""

    def test_builds_from_archive_and_indexes_wont_fix_entries(self, sample_vex_archive):
        overlay = VEXOverlay.from_archive(sample_vex_archive)
        # CVE-2016-20013 is marked won't-fix on every release where Canonical's UCT
        # used status: "ignored". The fixture has the real record verbatim — every
        # (noble, jammy, focal, etc.) × (glibc, syslinux, dietlibc, sssd, zabbix) tuple
        # that's `ignored` upstream should be present.
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "glibc") is True
        assert overlay.is_wont_fix("CVE-2016-20013", "jammy", "glibc") is True
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "syslinux") is True
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "dietlibc") is True

    def test_does_not_index_needs_fixing_entries(self, sample_vex_archive):
        overlay = VEXOverlay.from_archive(sample_vex_archive)
        # CVE-2023-38545 (curl) has status "affected" but action_statement "needs fixing"
        # on jammy and noble — Canonical will ship a fix. Should NOT be indexed as wont-fix.
        assert overlay.is_wont_fix("CVE-2023-38545", "jammy", "curl") is False
        assert overlay.is_wont_fix("CVE-2023-38545", "noble", "curl") is False

    def test_unknown_lookups_return_false(self, sample_vex_archive):
        overlay = VEXOverlay.from_archive(sample_vex_archive)
        assert overlay.is_wont_fix("CVE-9999-9999", "noble", "glibc") is False
        assert overlay.is_wont_fix("CVE-2016-20013", "noble", "no-such-pkg") is False
        # right CVE/pkg, but a release Canonical doesn't cover anymore
        assert overlay.is_wont_fix("CVE-2016-20013", "natty", "glibc") is False

    def test_empty_overlay_is_safely_queryable(self):
        # An overlay that's never been built (e.g. archive missing) should not blow up
        overlay = VEXOverlay()
        assert overlay.is_wont_fix("any", "any", "any") is False
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

    def test_annotates_only_wont_fix_packages(self, sample_vex_archive):
        overlay = VEXOverlay.from_archive(sample_vex_archive)
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

    def test_no_upstream_means_no_annotation(self, sample_vex_archive):
        overlay = VEXOverlay.from_archive(sample_vex_archive)
        rec = self._record()
        rec["upstream"] = []  # without an upstream CVE we have no join key
        sliced = slice_by_ecosystem(rec)
        _annotate_wont_fix(sliced, rec, overlay)

        for slice_payload in sliced.values():
            for aff in slice_payload["affected"]:
                assert "database_specific" not in aff or "anchore" not in aff.get("database_specific", {})

    def test_preserves_other_database_specific_keys(self, sample_vex_archive):
        overlay = VEXOverlay.from_archive(sample_vex_archive)
        rec = self._record()
        # pre-existing database_specific data on glibc should be preserved
        rec["affected"][0]["database_specific"] = {"anchore": {"other_key": "stays"}, "vendor": "x"}
        sliced = slice_by_ecosystem(rec)
        _annotate_wont_fix(sliced, rec, overlay)

        glibc = next(a for a in sliced["Ubuntu:24.04:LTS"]["affected"] if a["package"]["name"] == "glibc")
        assert glibc["database_specific"]["anchore"] == {"other_key": "stays", "status": "wont-fix"}
        assert glibc["database_specific"]["vendor"] == "x"


class TestParserVEXIntegration:
    """Bake-at-write-time semantics: VEX wont-fix lands in the fragment payload on disk."""

    def test_wont_fix_baked_into_fragment_payload(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        overlay = p._load_vex_overlay()
        p._write_fragments(vex_overlay=overlay)

        # CVE-2016-20013 / noble / glibc — Canonical's "ignored" case, the user's regression
        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-24.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2016-20013" in e.identifier)
        glibc = next(a for a in env.item["affected"] if a["package"]["name"] == "glibc")
        assert glibc["database_specific"]["anchore"]["status"] == "wont-fix"

    def test_no_overlay_means_no_annotations(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Without a VEX archive on disk, parser proceeds and writes raw fragments
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        overlay = p._load_vex_overlay()  # returns None — file is missing
        assert overlay is None
        p._write_fragments(vex_overlay=overlay)

        path = os.path.join(fresh_workspace.input_path, "fragments", "ubuntu-24.04-lts.db")
        with result.SQLiteReader(path) as reader:
            env = next(e for e in reader.each() if "2016-20013" in e.identifier)
        # nothing should have database_specific.anchore on a no-overlay run
        for aff in env.item["affected"]:
            assert "database_specific" not in aff or "anchore" not in aff.get("database_specific", {})

    def test_frozen_fragment_retains_wont_fix_after_overlay_disappears(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Headline behavior: write with overlay → freeze (VEX gone) → wont-fix survives
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)
        p1 = Parser(workspace=fresh_workspace)
        p1._write_fragments(vex_overlay=p1._load_vex_overlay())

        # Now simulate: the VEX archive is gone, but the fragment file remains.
        # Read it via _iter_fragments and confirm wont-fix is still there.
        os.remove(os.path.join(fresh_workspace.input_path, "vex-all.tar.xz"))

        p2 = Parser(workspace=fresh_workspace)
        yielded = {t[0]: t[2] for t in p2._iter_fragments()}
        payload = yielded["ubuntu-24.04-lts/ubuntu-cve-2016-20013"]
        glibc = next(a for a in payload["affected"] if a["package"]["name"] == "glibc")
        assert glibc["database_specific"]["anchore"]["status"] == "wont-fix"


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
        return {"package": pkg, "ecosystem_specific": eco_spec, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31+esm1"}]},
        ]}

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
        # UBUNTU-CVE-2020-36325 has ONLY Ubuntu:Pro:14.04:LTS / jansson in its affected[].
        # The base Ubuntu:14.04:LTS record has no entry for jansson in any fixture.
        # Inference should produce a synthetic base 14.04 envelope.
        _seed_archive(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._write_fragments()
        yielded = {t[0]: t[2] for t in p._iter_fragments()}

        synth = yielded.get("ubuntu-14.04-lts/ubuntu-cve-2020-36325")
        assert synth is not None, "expected synthetic base 14.04 envelope for CVE-2020-36325"
        affs = synth["affected"]
        assert len(affs) == 1
        jansson = affs[0]
        assert jansson["package"]["ecosystem"] == "Ubuntu:14.04:LTS"
        assert jansson["package"]["name"] == "jansson"
        assert "purl" not in jansson["package"]
        assert jansson["ranges"] == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
        anchore = jansson["database_specific"]["anchore"]
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
                        assert marker not in src, (
                            f"inference fired off a sub-tier source ({src}); "
                            "pro_to_base_ecosystem should have excluded this"
                        )

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
        synth = yielded.get("ubuntu-14.04-lts/ubuntu-cve-2020-36325")
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
        assert tpp_fix["date"] == "2013-07-15", (
            f"missing USN tuple should fall through to first-observed mock; got {tpp_fix['date']}"
        )
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
        assert osv_ecosystem_to_os_namespace("Ubuntu:24.10") == "ubuntu:24.10"
        assert osv_ecosystem_to_os_namespace("Ubuntu:25.04") == "ubuntu:25.04"

    def test_pro_and_subtiers_skipped(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_ecosystem_to_os_namespace
        # v3 never emitted Vulnerability records for Pro/FIPS/Realtime/BlueField namespaces;
        # they have no entry in cve-tracker's codename map. Pro-only-fix data still surfaces
        # in OS output because inference layers it into the base ecosystem's affected[] list
        # upstream of this code.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:14.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:16.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:FIPS:22.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:FIPS-updates:20.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:Realtime:24.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:Nvidia-BlueField:22.04:LTS") is None
        assert osv_ecosystem_to_os_namespace("Garbage") is None


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

    def test_withdrawn_record_is_skipped(self):
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os
        rec = self._osv_record(withdrawn="2025-09-12T17:13:25Z")
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

    def test_pro_only_record_returns_none(self):
        # Pro/FIPS/Realtime/BlueField fragments don't get downconverted.
        from vunnel.providers.ubuntu.os_downconvert import osv_to_os
        rec = self._osv_record()
        rec["affected"] = [
            {
                "package": {"ecosystem": "Ubuntu:Pro:FIPS:22.04:LTS", "name": "openssl"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1+fips1"}]}],
            },
        ]
        assert osv_to_os(rec) is None

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
        from vunnel.providers.ubuntu.os_downconvert import os_identifier_for
        rec = self._osv_record()
        assert os_identifier_for(rec) == "ubuntu:22.04/cve-2024-1"


class TestOSDowncoverterIntegration:
    """Verify the parser actually yields OS-shape records when the toggle is on."""

    def test_get_yields_os_records_when_enabled(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # downconvert_osv_to_os=True swaps fragment yields to OS shape; legacy passthrough
        # (which also produces OS) is unaffected.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"):
            records = list(p.get())

        # Every yielded record should be OS-shape.
        assert records, "expected non-empty yield"
        for identifier, sch, payload in records:
            assert "/os/" in sch.url, f"expected OS schema, got {sch.url}"
            assert "Vulnerability" in payload, f"expected v3 Vulnerability shape, got {list(payload)}"
            # Identifier shape: ubuntu:X.YY/cve-...
            assert identifier.startswith("ubuntu:"), identifier

        # Every Pro/FIPS/BlueField slice should be filtered out — only base namespaces remain.
        namespaces = {p["Vulnerability"]["NamespaceName"] for _, _, p in records}
        assert all(ns.startswith("ubuntu:") and ":Pro" not in ns and "-" not in ns.split(":")[1] for ns in namespaces), namespaces

    def test_inferred_wont_fix_lands_in_downconverted_output(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The Pro-only-fix inference path synthesizes base envelopes with
        # status=wont-fix; downconversion should render them as Version="None"
        # / NoAdvisory=True FixedIn entries on the base ecosystem.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace, downconvert_osv_to_os=True)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"):
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

    def test_default_still_yields_osv_records(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Sanity: with the toggle off (default), OSV envelopes flow through unchanged.
        _seed_archive(fresh_workspace, fixture_dir)
        _seed_vex_archive(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"):
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

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        schemas = []
        for f in ws.result_files():
            with open(f) as fh:
                schemas.append(json.load(fh)["schema"])
        # Every emitted record uses the OS schema; no OSV envelopes leak through.
        assert all("/os/schema-" in s for s in schemas), schemas
