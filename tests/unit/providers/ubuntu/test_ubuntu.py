from __future__ import annotations

import datetime
import io
import os
import shutil
import tarfile
from unittest.mock import patch

import orjson
import pytest

from vunnel import provider, result, workspace
from vunnel.providers.ubuntu import Config, Provider, parser_legacy, tracker, vex_cache
from vunnel.providers.ubuntu.cve_rows import OsvEntry, OsvRow, RowStore, distil_osv
from vunnel.providers.ubuntu.os_downconvert import (
    PackageState,
    fixed_in_for,
    is_cve_program_rejection,
    os_identifier_for,
    os_record,
    osv_ecosystem_to_os_namespace,
    severity_of,
)
from vunnel.providers.ubuntu.parser import (
    Parser,
    ReleaseIdentity,
    canonical_ecosystem,
    pro_to_base_ecosystem,
    release_identity,
)
from vunnel.providers.ubuntu.usn_fixdate_overlay import USNFixDateOverlay
from vunnel.providers.ubuntu.vex_overlay import (
    NO_FIX,
    NOT_AFFECTED,
    WONT_FIX,
    canonical_token,
    distro_label_from_purl,
    is_wont_fix_action,
    source_package_from_purl,
)
from vunnel.tool.fixdate.finder import Result
from vunnel.utils import http_wrapper as http


@pytest.fixture
def fixture_dir(helpers):
    return helpers.local_dir("test-fixtures")


@pytest.fixture
def fresh_workspace(tmpdir):
    return workspace.Workspace(tmpdir, "ubuntu", create=True)


# ---------------------------------------------------------------------------
# Seeding the two archives
#
# Binary tar.xz fixtures don't live in the repo — the loose JSON files under
# test-fixtures/ are the source of truth (reviewable diffs, no LFS pressure).
# Each test builds the archive it needs on demand; ~5ms for these trees, cheap
# enough not to bother memoizing.
#
# Both files and directories are explicitly sorted: os.walk's directory order is
# filesystem-dependent (ext4 vs APFS vs CI overlayfs all differ), and the
# archive's member order is the order the rows are written in.
# ---------------------------------------------------------------------------


def _write_archive(dst: str, fixture_dir: str | None, subdir: str | None, prefix: str, extra: list[dict] | None = None) -> str:
    with tarfile.open(dst, mode="w:xz") as tar:
        if fixture_dir and subdir:
            src = os.path.join(fixture_dir, subdir)
            for root, dirs, files in os.walk(src):
                dirs.sort()
                for fname in sorted(files):
                    if not fname.endswith(".json"):
                        continue
                    full = os.path.join(root, fname)
                    tar.add(full, arcname=f"{prefix}/" + os.path.relpath(full, src).replace(os.sep, "/"))
        for i, obj in enumerate(extra or []):
            raw = orjson.dumps(obj)
            info = tarfile.TarInfo(name=f"{prefix}/cve/planted/{i:04d}.json")
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return dst


def _seed_osv(fresh_workspace, fixture_dir=None, subdir: str | None = "osv", extra: list[dict] | None = None) -> str:
    return _write_archive(os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"), fixture_dir, subdir, "osv", extra)


def _seed_vex(fresh_workspace, fixture_dir=None, subdir: str | None = "vex", extra: list[dict] | None = None) -> str:
    return _write_archive(os.path.join(fresh_workspace.input_path, "vex-all.tar.xz"), fixture_dir, subdir, "vex", extra)


def _seed_normalized(fresh_workspace, fixture_dir, subdir: str = "normalized-cve-data") -> str:
    dst = os.path.join(fresh_workspace.input_path, "normalized-cve-data")
    shutil.copytree(os.path.join(fixture_dir, subdir), dst, dirs_exist_ok=True)
    return dst


# Two of the rules below are contradictions between Canonical's own feeds — one
# feed states something the other's shape cannot carry beside it — and Canonical
# does not publish them together, so there is no record in the fixture trees that
# exercises them. Those cases, and only those, hand a record or a document to the
# archive builder directly. Every one of them says in its own comment why it is
# stated rather than found, and uses the real release, token and package names of
# the case it stands in for.


def _osv_record(cve: str, affected: list[dict], **overrides) -> dict:
    record = {
        "schema_version": "1.7.0",
        "id": f"UBUNTU-{cve}",
        "upstream": [cve],
        "severity": [{"type": "Ubuntu", "score": "medium"}],
        "affected": affected,
    }
    record.update(overrides)
    return record


def _affected(ecosystem: str, name: str, token: str, fixed: str | None = None) -> dict:
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {
        "package": {"ecosystem": ecosystem, "name": name, "purl": f"pkg:deb/ubuntu/{name}@1.0?arch=source&distro={token}"},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
    }


def _vex_document(cve: str, statements: list[tuple]) -> dict:
    """Each statement is `(token, package, status[, justification])`."""
    out = []
    for token, package, status, *rest in statements:
        body: dict = {"vulnerability": {"name": cve}, "status": status}
        if rest and rest[0]:
            body["justification"] = rest[0]
        body["products"] = [{"@id": f"pkg:deb/ubuntu/{package}@1.0?arch=source&distro={token}"}]
        out.append(body)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "statements": out}


def _fixture_record(fixture_dir: str, relative_path: str) -> dict:
    with open(os.path.join(fixture_dir, relative_path), "rb") as fh:
        return orjson.loads(fh.read())


def _fixture_records(fixture_dir: str, subdir: str) -> list[dict]:
    """Every record in one fixture tree, for seeding two trees into one archive."""
    out = []
    root = os.path.join(fixture_dir, subdir)
    for directory, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            if name.endswith(".json"):
                out.append(_fixture_record(directory, name))
    return out


def _run(fresh_workspace, emit_esm: bool = True, **kwargs) -> dict[str, dict]:
    """Read both archives and return every record the merge emits, by identifier."""
    p = Parser(workspace=fresh_workspace, downconvert_emit_esm=emit_esm, **kwargs)
    p._read_osv_archive()
    p._read_vex_archive()
    try:
        return {t[0]: t[2] for t in p._iter_merged()}
    finally:
        p._osv_rows.close()
        p._vex_rows.close()


def _run_get(fresh_workspace, **kwargs) -> dict[str, dict]:
    """The whole of `get()`, with the downloads stubbed out."""
    p = Parser(workspace=fresh_workspace, **kwargs)
    with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"):
        return {t[0]: t[2] for t in p.get()}


def _fixed_in_for(record: dict, package: str) -> list[dict]:
    return [f for f in record["Vulnerability"]["FixedIn"] if f["Name"] == package]


def _versions(record: dict, package: str) -> list[str]:
    return [f["Version"] for f in _fixed_in_for(record, package)]


def _names(record: dict) -> set[str]:
    return {f["Name"] for f in record["Vulnerability"]["FixedIn"]}


# ---------------------------------------------------------------------------
# Provider static attrs and config validation
# ---------------------------------------------------------------------------


class TestProvider:
    def test_static_attrs(self):
        assert Provider.name() == "ubuntu"
        assert Provider.tags() == ["vulnerability", "os", "large"]
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

    def test_the_removed_downconvert_switch_still_loads(self, fresh_workspace, caplog):
        # an operator's config may still carry it; it is accepted, warned about
        # once, and changes nothing about what is emitted
        with caplog.at_level("WARNING"):
            Parser(workspace=fresh_workspace, downconvert_osv_to_os=False)
        assert "downconvert_osv_to_os" in caplog.text
        assert Config().downconvert_osv_to_os is True


# ---------------------------------------------------------------------------
# Release identity — one release, two spellings over its life
# ---------------------------------------------------------------------------


class TestReleaseIdentity:
    def test_suffixed_and_unsuffixed_spellings_are_one_release(self):
        assert canonical_ecosystem("Ubuntu:26.04") == canonical_ecosystem("Ubuntu:26.04:LTS")
        assert canonical_ecosystem("Ubuntu:26.04") == "Ubuntu:26.04:LTS"

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
        # the known-husk list keys on this version
        assert identity.version in {"14.04", "16.04", "20.04", "22.04", "24.04"}
        assert identity.is_lts is True

    def test_interim_releases_are_not_lts(self):
        for version, eco in (("24.10", "Ubuntu:24.10"), ("25.04", "Ubuntu:25.04"), ("25.10", "Ubuntu:25.10")):
            identity = release_identity(eco)
            assert identity.version == version
            assert identity.is_lts is False
            assert identity.ecosystem == eco

    def test_unrecognized_ecosystems_keep_their_spelling(self):
        # Canonical publishes a handful of malformed strings; they are out of scope
        # and must not be merged onto anything.
        for eco in ("Ubuntu:22.04:LTS:for:NVIDIA:BlueField", "Ubuntu:Pro:22.04:LTS:Realtime:Kernel"):
            assert release_identity(eco) is None
            assert canonical_ecosystem(eco) == eco

    def test_both_spellings_of_a_release_land_in_one_namespace(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The real residue of 26.04's rename: UBUNTU-CVE-2026-7246 names
        # `Ubuntu:26.04`, written before the release reached general availability,
        # and UBUNTU-CVE-2026-41293 names `Ubuntu:26.04:LTS`, written after it.
        # One release, one namespace, and nothing under a second spelling.
        _seed_osv(fresh_workspace, fixture_dir, "osv-canonical-identity")
        emitted = _run(fresh_workspace)
        assert _versions(emitted["ubuntu:26.04/cve-2026-7246"], "python-click") == ["None"]
        assert _versions(emitted["ubuntu:26.04/cve-2026-41293"], "tomcat9") == ["9.0.115-1ubuntu0.1"]
        assert not any(identifier.startswith("ubuntu:26.04-lts") for identifier in emitted)


class TestProToBaseEcosystem:
    """Only the plain ESM tier is inferable; the sub-tiers rebuild divergent code."""

    def test_plain_pro_with_lts_suffix(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:20.04:LTS") == "Ubuntu:20.04:LTS"

    def test_plain_pro_oldest_esm_release(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:14.04:LTS") == "Ubuntu:14.04:LTS"

    def test_plain_pro_without_lts_suffix(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:25.10") == "Ubuntu:25.10"

    def test_fips_rejected(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:FIPS:20.04:LTS") is None
        assert pro_to_base_ecosystem("Ubuntu:Pro:FIPS-updates:22.04:LTS") is None
        assert pro_to_base_ecosystem("Ubuntu:Pro:FIPS-preview:22.04:LTS") is None

    def test_realtime_rejected(self):
        assert pro_to_base_ecosystem("Ubuntu:Pro:Realtime:24.04:LTS") is None

    def test_nvidia_bluefield_rejected(self):
        assert pro_to_base_ecosystem("Ubuntu:Nvidia-BlueField:22.04:LTS") is None

    def test_already_base_returns_none(self):
        assert pro_to_base_ecosystem("Ubuntu:20.04:LTS") is None
        assert pro_to_base_ecosystem("Ubuntu:25.10") is None

    def test_malformed_inputs_return_none(self):
        for eco in ("", "Ubuntu", "Ubuntu:Pro", "Ubuntu:Pro:notaversion", "Ubuntu:Pro:20.04:NOTLTS", "Debian:Pro:20.04"):
            assert pro_to_base_ecosystem(eco) is None


# ---------------------------------------------------------------------------
# The scratch rows both archives are distilled into
# ---------------------------------------------------------------------------


class TestRowStore:
    def test_rows_are_readable_by_offset_in_any_order(self, tmp_path):
        store = RowStore(str(tmp_path / "rows.tsv"))
        with store as writing:
            for i in range(50):
                writing.write(f"CVE-2024-{i}", {"n": i, "pad": "x" * i})

        assert len(store) == 50
        # read back in an order unrelated to the order they were written in
        for cve in sorted(store.keys()):
            assert store.get(cve)["n"] == int(cve.rsplit("-", 1)[1])
        store.close()

    def test_ids_that_straddle_a_digit_count_boundary_join(self, tmp_path):
        # the key is compared as a plain string on every side of the join, so any
        # consistent ordering works and the numeric shape of the id never matters
        a = RowStore(str(tmp_path / "a.tsv"))
        b = RowStore(str(tmp_path / "b.tsv"))
        ids = ["CVE-2024-9", "CVE-2024-10", "CVE-2024-100", "CVE-2024-1000"]
        with a as writing:
            for cve in ids:
                writing.write(cve, {"cve": cve})
        with b as writing:
            for cve in reversed(ids):
                writing.write(cve, {"cve": cve})
        assert a.keys() == b.keys()
        for cve in sorted(a.keys() | b.keys()):
            assert a.get(cve) == b.get(cve) == {"cve": cve}
        a.close()
        b.close()

    def test_a_missing_cve_reads_as_nothing(self, tmp_path):
        store = RowStore(str(tmp_path / "rows.tsv"))
        with store as writing:
            writing.write("CVE-2024-1", {})
        assert store.get("CVE-2024-2") is None
        assert "CVE-2024-1" in store
        store.close()

    def test_a_read_inside_the_writing_context_sees_what_was_written(self, tmp_path):
        # the write handle is buffered, so a lookup made before it is flushed
        # reads short and fails on the JSON rather than saying what went wrong.
        # Nothing does this today; it is one line to keep it from being a wrong
        # answer if the distil pass ever grows a lookup.
        store = RowStore(str(tmp_path / "rows.tsv"))
        with store as writing:
            for i in range(500):
                writing.write(f"CVE-2024-{i}", {"cve": f"CVE-2024-{i}", "pad": "x" * 200})
            assert writing.get("CVE-2024-499") == {"cve": "CVE-2024-499", "pad": "x" * 200}
        store.close()

    def test_a_store_never_entered_reads_as_empty(self, tmp_path):
        # the missing-archive path never enters the writing context at all
        store = RowStore(str(tmp_path / "rows.tsv"))
        assert store.keys() == set()
        assert store.get("CVE-2024-1") is None
        store.close()

    def test_reset_drops_a_previous_runs_index(self, tmp_path):
        # a retry re-enters the archive readers on the same Parser; the rows the
        # first attempt wrote must not answer the second one
        store = RowStore(str(tmp_path / "rows.tsv"))
        with store as writing:
            writing.write("CVE-2024-1", {"cve": "CVE-2024-1"})
        assert store.keys() == {"CVE-2024-1"}
        store.reset()
        assert store.keys() == set()
        assert store.get("CVE-2024-1") is None
        store.close()

    def test_the_file_is_truncated_on_open(self, tmp_path):
        store = RowStore(str(tmp_path / "rows.tsv"))
        with store as writing:
            writing.write("CVE-2024-1", {"run": 1})
        with store as writing:
            writing.write("CVE-2024-2", {"run": 2})
        assert store.keys() == {"CVE-2024-2"}
        assert store.get("CVE-2024-2") == {"run": 2}
        store.close()


class TestOSVDistil:
    def test_entries_reduce_to_ecosystem_package_purl_and_fix_versions(self, fixture_dir):
        record = _fixture_record(fixture_dir, "osv/cve/2013/UBUNTU-CVE-2013-2208.json")
        row = distil_osv(record, rejected=is_cve_program_rejection(record))
        assert row is not None
        assert row.cve == "CVE-2013-2208"
        assert row.published == record["published"]
        assert row.rejected is False
        assert row.entries[0].ecosystem == "Ubuntu:14.04:LTS"
        assert row.entries[0].package == "tpp"
        assert row.entries[0].fixed == ("1.3.1-3",)
        assert "distro=trusty" in row.entries[0].purl

    def test_a_record_with_no_upstream_alias_is_dropped(self, fixture_dir):
        # UBUNTU-CVE-2011-4898 carries `"aliases": []` in the feed. Every emitted
        # record is named by the upstream CVE, so a record without one has no name
        # to be emitted under, no key to join the other two sources on, and
        # nothing to attribute a rejection to.
        record = _fixture_record(fixture_dir, "osv-withdrawn/cve/2011/UBUNTU-CVE-2011-4898.json")
        assert not record.get("upstream")
        assert distil_osv(record, rejected=False) is None

    def test_the_rejection_is_carried_as_a_boolean_and_the_prose_is_not(self, fixture_dir):
        record = _fixture_record(fixture_dir, "osv-withdrawn/cve/2021/UBUNTU-CVE-2021-23334.json")
        assert record["details"].startswith("** REJECT **")
        row = distil_osv(record, rejected=is_cve_program_rejection(record))
        assert row is not None and row.rejected is True
        assert "details" not in row.to_payload()

    def test_withdrawn_is_not_carried(self, fixture_dir):
        # Canonical sets `withdrawn` to mark a record it will not regenerate
        # rather than to retract the finding, and nothing downstream reads it.
        record = _fixture_record(fixture_dir, "osv-withdrawn/cve/2014/UBUNTU-CVE-2014-6422.json")
        assert record["withdrawn"]
        payload = distil_osv(record, rejected=False).to_payload()
        assert "withdrawn" not in orjson.dumps(payload).decode()

    def test_a_row_round_trips_through_the_scratch_file(self, fixture_dir, tmp_path):
        record = _fixture_record(fixture_dir, "osv/cve/2021/UBUNTU-CVE-2021-3782.json")
        row = distil_osv(record, rejected=False)
        store = RowStore(str(tmp_path / "rows.tsv"))
        with store as writing:
            writing.write(row.cve, row.to_payload())
        assert OsvRow.from_payload(store.get("CVE-2021-3782")) == row
        store.close()


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


class TestParserDownload:
    def test_download_streams_to_archive_path(self, fresh_workspace, fixture_dir, tmp_path, auto_fake_fixdate_finder):
        sample = str(tmp_path / "sample-osv-all.tar.xz")
        _write_archive(sample, fixture_dir, "osv", "osv")
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
        # the bytes stage in a sibling .part and are renamed on success, so a
        # finished download leaves no staging file behind
        assert not os.path.exists(archive + http.PARTIAL_SUFFIX)

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
# Enumeration: what the merge emits for the sample feed
# ---------------------------------------------------------------------------


class TestMergeEnumeration:
    # Real OSV fixtures in tests/unit/providers/ubuntu/test-fixtures/osv:
    #   UBUNTU-CVE-2013-2208   fixed events on Ubuntu:14.04:LTS
    #   UBUNTU-CVE-2016-20013  six base releases and four Pro slices
    #   UBUNTU-CVE-2012-5855   ONLY Ubuntu:Pro:14.04:LTS (drives the inference)
    #   UBUNTU-CVE-2020-36325  ONLY Ubuntu:Pro:14.04:LTS, details open `** DISPUTED **`
    #   UBUNTU-CVE-2021-3782   base 18/20/22.04 plus Ubuntu:Pro:16.04:LTS
    #   UBUNTU-CVE-2026-1403   Ubuntu:16.04:LTS

    def test_one_record_per_namespace_the_feed_speaks_for(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir)
        assert sorted(_run(fresh_workspace)) == [
            "ubuntu:14.04/cve-2013-2208",
            "ubuntu:14.04/cve-2016-20013",
            "ubuntu:16.04+esm/cve-2021-3782",
            "ubuntu:16.04/cve-2016-20013",
            "ubuntu:16.04/cve-2021-3782",
            "ubuntu:16.04/cve-2026-1403",
            "ubuntu:18.04/cve-2016-20013",
            "ubuntu:18.04/cve-2021-3782",
            "ubuntu:20.04/cve-2016-20013",
            "ubuntu:20.04/cve-2021-3782",
            "ubuntu:22.04/cve-2016-20013",
            "ubuntu:22.04/cve-2021-3782",
            "ubuntu:24.04/cve-2016-20013",
        ]

    def test_every_record_carries_the_os_schema(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._read_osv_archive()
        p._read_vex_archive()
        schemas = {sch.url for _identifier, sch, _payload in p._iter_merged()}
        assert schemas and all("/os/" in url for url in schemas)
        p._osv_rows.close()

    def test_a_record_with_no_upstream_alias_emits_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2012-5855 and UBUNTU-CVE-2020-36325 both carry `"aliases": []`
        # in the feed, so neither has an upstream CVE to be named by anywhere.
        _seed_osv(fresh_workspace, fixture_dir)
        emitted = _run(fresh_workspace)
        assert not any("2012-5855" in identifier or "2020-36325" in identifier for identifier in emitted)
        # the Pro-to-base inference still fires for a record that does have one
        assert _versions(emitted["ubuntu:14.04/cve-2016-20013"], "eglibc") == ["None"]

    def test_a_second_read_with_the_archive_gone_forgets_the_first(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # provider.update() re-enters _update() on the same Parser under a retry
        # policy, so a second _read_*_archive() is reachable with the archive no
        # longer there; it must not answer out of the first attempt's rows
        _seed_osv(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._read_osv_archive()
        p._read_vex_archive()
        assert p._osv_rows.keys() and p._vex_rows.keys() and p._served_versions

        os.remove(p.archive_path)
        os.remove(p.vex_archive_path)
        p._read_osv_archive()
        p._read_vex_archive()
        assert p._osv_rows.keys() == set()
        assert p._vex_rows.keys() == set()
        assert p._served_versions == set()
        p._osv_rows.close()
        p._vex_rows.close()

    def test_an_empty_workspace_emits_nothing(self, fresh_workspace, auto_fake_fixdate_finder):
        assert _run(fresh_workspace) == {}

    def test_a_missing_vex_archive_still_emits_from_osv(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir)
        assert "ubuntu:24.04/cve-2016-20013" in _run(fresh_workspace)


# ---------------------------------------------------------------------------
# Fix dates, resolved where the fix version is known
# ---------------------------------------------------------------------------


class TestFixDates:
    def test_a_fix_version_carries_the_date_the_finder_gave_it(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        fake_fixdate_finder(responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)])
        _seed_osv(fresh_workspace, fixture_dir)
        record = _run(fresh_workspace)["ubuntu:14.04/cve-2013-2208"]
        tpp = _fixed_in_for(record, "tpp")[0]
        assert tpp["Version"] == "1.3.1-3"
        assert tpp["Available"] == {"Date": "2013-07-15", "Kind": "first-observed"}

    def test_the_lookup_is_keyed_by_the_upstream_cve_not_canonicals_own_id(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Canonical's record id is `UBUNTU-CVE-*` and the fix-date cache keys by
        # the upstream `CVE-*`. Configure the finder with the upstream key only:
        # if the lookup used the internal id it would silently miss.
        fake_fixdate_finder(responses={"CVE-2013-2208": [Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)]})
        _seed_osv(fresh_workspace, fixture_dir)
        record = _run(fresh_workspace)["ubuntu:14.04/cve-2013-2208"]
        assert _fixed_in_for(record, "tpp")[0]["Available"] == {"Date": "2013-07-15", "Kind": "first-observed"}

    def test_a_package_with_no_fix_version_is_dated_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir)
        record = _run(fresh_workspace)["ubuntu:16.04/cve-2026-1403"]
        assert _fixed_in_for(record, "gitlab")[0]["Available"] is None

    def test_todays_finder_reaches_a_record_the_feed_has_not_changed(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # nothing is cached between the feed and the record, so a fix date the
        # finder learns today reaches every record on the next run without
        # anything upstream having to change. With a finder that knows nothing,
        # the record's own `published` is the low-confidence fallback.
        _seed_osv(fresh_workspace, fixture_dir)
        fake_fixdate_finder(responses=[])
        assert _fixed_in_for(_run(fresh_workspace)["ubuntu:14.04/cve-2013-2208"], "tpp")[0]["Available"] == {
            "Date": "2013-10-28",
            "Kind": "advisory",
        }
        fake_fixdate_finder(responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)])
        assert _fixed_in_for(_run(fresh_workspace)["ubuntu:14.04/cve-2013-2208"], "tpp")[0]["Available"] == {
            "Date": "2013-07-15",
            "Kind": "first-observed",
        }


# ---------------------------------------------------------------------------
# VEX helpers and the pocket tables
# ---------------------------------------------------------------------------


class TestVEXHelpers:
    """Pure-function tests for the VEX module."""

    def test_distro_label_from_purl(self):
        assert distro_label_from_purl("pkg:deb/ubuntu/glibc@2.31?arch=source&distro=focal") == "focal"
        assert distro_label_from_purl("pkg:deb/ubuntu/glibc@2.31?arch=source&distro=esm-infra/jammy") == "esm-infra/jammy"
        assert distro_label_from_purl("pkg:deb/ubuntu/glibc@2.31?arch=source") is None
        assert distro_label_from_purl("") is None

    def test_source_package_from_purl(self):
        assert source_package_from_purl("pkg:deb/ubuntu/glibc@2.31?arch=source&distro=focal") == "glibc"
        assert source_package_from_purl("pkg:deb/ubuntu/linux-hwe-5.15@5.15?arch=source&distro=focal") == "linux-hwe-5.15"
        assert source_package_from_purl("not a purl") is None

    def test_is_wont_fix_action_matches_both_canonical_openings(self):
        assert is_wont_fix_action(
            "This package (for the given release) is vulnerable to the CVE, the problem is understood, "
            "but the Ubuntu Security Team decided to not fix it.",
        )
        assert is_wont_fix_action("This package (for the given release) is no longer supported.")

    def test_is_wont_fix_action_rejects_needs_fixing(self):
        assert not is_wont_fix_action("This package (for the given release) needs fixing.")
        assert not is_wont_fix_action(None)
        assert not is_wont_fix_action("")


def _speaks_for(token: str) -> str | None:
    """The base ecosystem a token may assert into, by the two tables that decide it."""
    if not vex_cache.token_asserts(token):
        return None
    version = parser_legacy.ubuntu_version_names.get(vex_cache.codename_of_token(token))
    if version is None:
        return None
    return ReleaseIdentity(channel="Ubuntu", version=version).ecosystem


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
            # a release the vendored codename table stops short of resolves to
            # nothing, same as a codename neither knows
            ("natty", "", None),
            ("nonesuch", "", None),
        ],
    )
    def test_which_tokens_speak_for_which_release(self, token, pocket, ecosystem):
        # One table decides both halves of this: `_POCKETS_THAT_ASSERT` says which
        # pockets may state anything about a release, and
        # `parser_legacy.ubuntu_version_names` resolves the codename to the
        # release itself.
        assert vex_cache.pocket_of_token(token) == pocket
        assert _speaks_for(token) == ecosystem
        # and only a release's own archive may put a finding in its namespace
        assert vex_cache.token_asserts_findings(token) is (pocket == "")

    def test_each_status_becomes_the_disposition_it_means(self, fixture_dir):
        # CVE-2014-3566 carries every status Canonical publishes. At xenial it
        # clears nss and pound as researched, says the release never shipped
        # openjdk-6 and openjdk-7, and reports openssl fixed — and a `fixed`
        # statement carries no version this provider will use, so it makes no row.
        document = _fixture_record(fixture_dir, "vex-cases/cve/2014/CVE-2014-3566.json")
        cve, row = vex_cache.distil_row(document)
        assert cve == "CVE-2014-3566"
        by_token = vex_cache.dispositions_by_token(row)
        assert by_token["xenial"] == {
            "nss": "not-affected",
            "openjdk-6": "not-present",
            "openjdk-7": "not-present",
            "pound": "not-affected",
        }
        # under_investigation is vulnerable-with-no-fix, never a clearance
        assert by_token["resolute"]["pound"] == "no-fix"
        # and trusty's own archive says openssl098 is affected with the prose that
        # means the security team decided not to fix it
        assert by_token["trusty"]["openssl098"] == "wont-fix"

    def test_the_two_spellings_of_the_oldest_esm_pocket_fold_onto_one_key(self, fixture_dir):
        # CVE-2022-49688 states the same clearance at `esm-infra-legacy/trusty`
        # and CVE-2014-3566 at `trusty/esm`; both are the same pocket and the join
        # has to see them as one or about 23,000 OSV entries look uncovered.
        document = _fixture_record(fixture_dir, "vex-cases/cve/2014/CVE-2014-3566.json")
        _cve, row = vex_cache.distil_row(document)
        assert "esm-infra-legacy/trusty" in vex_cache.dispositions_by_token(row)
        assert "trusty/esm" not in vex_cache.dispositions_by_token(row)

    def test_only_source_architecture_products_are_read(self, fixture_dir):
        # the untrimmed documents repeat every statement across each binary
        # architecture; the source entry carries the same disposition and the OSV
        # side keys on source packages, so reading only those cuts the rows by an
        # order of magnitude and loses nothing
        document = _fixture_record(fixture_dir, "vex/cve/2016/CVE-2016-20013.json")
        products = [p["@id"] for s in document["statements"] for p in s["products"]]
        assert any("arch=amd64" in p for p in products), "fixture no longer carries a binary product"
        source_products = [p for p in products if "arch=source" in p]
        assert len(list(vex_cache.distill(document))) == len(source_products)


# ---------------------------------------------------------------------------
# The OS-schema record and the four FixedIn outcomes
# ---------------------------------------------------------------------------


class TestNamespaceMapping:
    def test_base_ecosystem_to_namespace(self):
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
        # plain Ubuntu Pro (ESM) maps to the `ubuntu:X.YY+esm` distro channel,
        # mirroring RHEL EUS's `rhel:X.Y+eus`. LTS suffix optional.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:14.04:LTS") == "ubuntu:14.04+esm"
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:16.04:LTS") == "ubuntu:16.04+esm"
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:22.04:LTS") == "ubuntu:22.04+esm"
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:25.10") == "ubuntu:25.10+esm"

    def test_subtiers_skipped(self):
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
        # with the emit gate off, plain Pro is dropped like the sub-tiers; base is unaffected.
        assert osv_ecosystem_to_os_namespace("Ubuntu:Pro:22.04:LTS", include_esm=False) is None
        assert osv_ecosystem_to_os_namespace("Ubuntu:22.04:LTS", include_esm=False) == "ubuntu:22.04"


class TestFixedInRules:
    """The four outcomes, and what the `+esm` channel does with each."""

    def test_a_fix_version_yields_a_fixedin_with_the_version(self):
        state = PackageState(package="openssl", ecosystem="Ubuntu:22.04:LTS", fixed=["3.0.2-0ubuntu1.8"])
        assert fixed_in_for(state, "ubuntu:22.04") == [
            {
                "Name": "openssl",
                "NamespaceName": "ubuntu:22.04",
                "VersionFormat": "dpkg",
                "Version": "3.0.2-0ubuntu1.8",
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": None,
            },
        ]

    def test_a_fix_version_carries_its_date_when_one_was_found(self):
        state = PackageState(
            package="wayland",
            ecosystem="Ubuntu:22.04:LTS",
            fixed=["1.20.0-1ubuntu0.1"],
            available={"1.20.0-1ubuntu0.1": {"Date": "2022-09-15", "Kind": "advisory"}},
        )
        assert fixed_in_for(state, "ubuntu:22.04")[0]["Available"] == {"Date": "2022-09-15", "Kind": "advisory"}

    def test_multiple_fix_versions_become_multiple_fixedin(self):
        # rare, but real where the tracker listed more than one released patch
        state = PackageState(package="ncurses", ecosystem="Ubuntu:20.04:LTS", fixed=["6.2-0ubuntu2.1", "6.3-2ubuntu0.1"])
        assert [f["Version"] for f in fixed_in_for(state, "ubuntu:20.04")] == ["6.2-0ubuntu2.1", "6.3-2ubuntu0.1"]

    def test_wont_fix_rules_out_an_advisory(self):
        state = PackageState(package="openssl", ecosystem="Ubuntu:22.04:LTS", wont_fix=True)
        out = fixed_in_for(state, "ubuntu:22.04")
        assert out[0]["Version"] == "None"
        assert out[0]["VendorAdvisory"] == {"NoAdvisory": True}

    def test_no_fix_yet_does_not_rule_one_out(self):
        state = PackageState(package="openssl", ecosystem="Ubuntu:22.04:LTS")
        out = fixed_in_for(state, "ubuntu:22.04")
        assert out[0]["Version"] == "None"
        assert out[0]["VendorAdvisory"] == {"NoAdvisory": False}

    def test_a_clearance_is_the_zero_row_and_nothing_else(self):
        state = PackageState(package="openssl", ecosystem="Ubuntu:22.04:LTS", fixed=["3.0.2-0ubuntu1.8"], wont_fix=True)
        state.clear()
        assert fixed_in_for(state, "ubuntu:22.04") == [
            {
                "Name": "openssl",
                "NamespaceName": "ubuntu:22.04",
                "VersionFormat": "dpkg",
                "Version": "0",
                "VendorAdvisory": {"NoAdvisory": False},
                "Available": None,
            },
        ]

    def test_the_esm_channel_carries_fixes_only(self):
        fixed = PackageState(package="netty", ecosystem="Ubuntu:Pro:22.04:LTS", fixed=["1:4.1.48-4+deb11u2ubuntu0.1~esm1"])
        no_fix = PackageState(package="netty", ecosystem="Ubuntu:Pro:22.04:LTS", wont_fix=True)
        cleared = PackageState(package="netty", ecosystem="Ubuntu:Pro:22.04:LTS", cleared=True)
        assert [f["Version"] for f in fixed_in_for(fixed, "ubuntu:22.04+esm")] == ["1:4.1.48-4+deb11u2ubuntu0.1~esm1"]
        assert fixed_in_for(no_fix, "ubuntu:22.04+esm") == []
        assert fixed_in_for(cleared, "ubuntu:22.04+esm") == []

    @pytest.mark.parametrize(
        "fixed",
        # real Pro fix versions from the feed: epochs, tildes, `+esm` and `~esm`
        # suffixes and a leading zero all pass through untouched
        [
            "1:4.0.34-1ubuntu0.1~esm2",
            "6.0-9ubuntu1.6",
            "9.0.16-3ubuntu0.18.04.2+esm8",
            "5.9+20140118-1ubuntu1+esm3",
            "11.0.18-1ubuntu0.1~esm1",
        ],
    )
    def test_real_fix_versions_pass_through_verbatim(self, fixed):
        state = PackageState(package="p", ecosystem="Ubuntu:Pro:22.04:LTS", fixed=[fixed])
        assert fixed_in_for(state, "ubuntu:22.04+esm")[0]["Version"] == fixed


class TestOSRecordShape:
    def test_severity_capitalizes_canonical_priority(self):
        assert severity_of([{"type": "Ubuntu", "score": "critical"}]) == "Critical"
        assert severity_of([{"type": "Ubuntu", "score": "negligible"}]) == "Negligible"

    def test_severity_falls_back_to_unknown(self):
        assert severity_of(None) == "Unknown"
        assert severity_of([]) == "Unknown"
        assert severity_of([{"type": "Ubuntu", "score": "untriaged"}]) == "Unknown"
        assert severity_of([{"type": "CVSS_V3", "score": "9.8"}]) == "Unknown"
        assert severity_of([{"type": "Ubuntu", "score": "nonsense"}]) == "Unknown"

    def test_identifier_is_namespace_and_lowercased_cve(self):
        payload = os_record("CVE-2022-4450", "ubuntu:22.04", "Medium", [])
        assert os_identifier_for(payload) == "ubuntu:22.04/cve-2022-4450"

    def test_the_record_carries_the_v3_field_set(self):
        payload = os_record("CVE-2022-4450", "ubuntu:22.04", "Medium", [])
        assert payload["Vulnerability"] == {
            "Name": "CVE-2022-4450",
            "NamespaceName": "ubuntu:22.04",
            "Description": "",
            "Severity": "Medium",
            "Metadata": {},
            "Link": "https://ubuntu.com/security/CVE-2022-4450",
            "FixedIn": [],
        }


# ---------------------------------------------------------------------------
# VEX judgements applied when records are emitted
#
# The fixtures under test-fixtures/vex-cases/ are real Canonical VEX documents
# with their binary-architecture products dropped. Only `arch=source` products
# are ever read, so nothing under test is lost, and a verbatim copy of one of
# these documents is over a megabyte. The fixtures under
# test-fixtures/osv-vex-cases/ are the real records behind the pinned
# contradictions, trimmed to the releases under test.
# ---------------------------------------------------------------------------


def _run_vex_cases(fresh_workspace, fixture_dir, osv_extra: list[dict] | None = None, vex_extra: list[dict] | None = None, **kwargs):
    _seed_osv(fresh_workspace, fixture_dir, "osv-vex-cases", extra=osv_extra)
    _seed_vex(fresh_workspace, fixture_dir, "vex-cases", extra=vex_extra)
    return _run(fresh_workspace, **kwargs)


class TestVEXAtEmitTime:
    def test_confirmed_not_vulnerable_is_stated_rather_than_emitted_as_a_finding(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2023-2640 on linux-gke-5.15 / focal: OSV lists it as affected with no
        # fix, VEX states vulnerable_code_not_present. A live false positive before
        # the statements were read. What is emitted in its place is the assertion.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        record = emitted["ubuntu:20.04/cve-2023-2640"]
        assert _versions(record, "linux-gke-5.15") == ["0"]
        assert _versions(record, "linux-gkeop-5.15") == ["0"]
        # a package VEX does not clear is still a finding
        assert _versions(record, "linux-hwe-5.11") == ["None"]

    def test_a_clearance_replaces_an_osv_entry_rather_than_dropping_it(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Dropping the entry emits nothing, and nothing is what a consumer already
        # believes. The `"0"` has to be the package's only FixedIn in the record or
        # the group stops reading as a clearance.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        cleared = _fixed_in_for(emitted["ubuntu:20.04/cve-2023-2640"], "linux-gke-5.15")
        assert len(cleared) == 1
        assert cleared[0]["Version"] == "0"
        assert cleared[0]["VendorAdvisory"] == {"NoAdvisory": False}

    def test_a_vendor_clearance_osv_never_mentioned_is_asserted(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-3566 / pound / focal is not_affected in VEX and absent from the
        # OSV feed's 20.04 records entirely, so the whole record is the assertion.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        record = emitted["ubuntu:20.04/cve-2014-3566"]
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
        # marks affected; the five Pro kernel flavours would each infer a base entry,
        # and VEX states vulnerable_code_not_present for every one of them. An
        # inferred package has no purl of its own, so this only works if the
        # statement is looked up at the base codename explicitly.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        record = emitted["ubuntu:16.04/cve-2022-49688"]
        for package in ("linux-aws-hwe", "linux-azure", "linux-gcp", "linux-hwe", "linux-oracle"):
            assert _versions(record, package) == ["0"], package
        # the one real base entry, which VEX agrees is affected, keeps its own shape
        assert _versions(record, "linux-hwe-edge") == ["None"]

    def test_inference_is_not_suppressed_without_an_assertion(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the same records with no VEX archive at all: all six packages emit
        _seed_osv(fresh_workspace, fixture_dir, "osv-vex-cases")
        record = _run(fresh_workspace)["ubuntu:16.04/cve-2022-49688"]
        assert len(_names(record)) == 6
        assert "linux-hwe-edge" in _names(record)

    def test_an_undetermined_status_still_emits(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-3566 / resolute / pound is under_investigation in VEX and no
        # OSV record carries the CVE at all. It emitted as vulnerable-with-no-fix
        # before this provider read OSV, and suppressing it here would drop tens
        # of thousands of real findings.
        _seed_osv(fresh_workspace, fixture_dir, "osv-canonical-identity")
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        record = _run(fresh_workspace)["ubuntu:26.04/cve-2014-3566"]
        assert _versions(record, "pound") == ["None"], "under_investigation must not be treated as a clearance"
        # nss on resolute is not_affected, so that one stops being a finding
        assert _versions(record, "nss") == ["0"]

    def test_vex_supplies_no_fix_version_and_a_fixed_statement_states_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2014-3566 carries a `fixed` VEX statement for focal/openssl at
        # 1.1.1f-1ubuntu2.24, and no OSV record for it exists in this workspace.
        # The version on a `fixed` statement is the pocket's current version
        # rather than the version that fixed the CVE, so there is nothing to
        # state for openssl and the version must appear nowhere.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        named = {name for record in emitted.values() for name in _names(record)}
        assert "openssl" not in named
        # the same CVE's not_affected statement for focal is stated, so the
        # absence above is the `fixed` status and not the record going missing
        assert "ubuntu:20.04/cve-2014-3566" in emitted
        assert "1.1.1f-1ubuntu2.24" not in orjson.dumps(emitted).decode()

    def test_wont_fix_comes_from_the_statement_prose(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2016-20013 / noble / glibc is Canonical's "decided not to fix" case.
        # OSV renders won't-fix and no-fix-yet identically, so the prose is the
        # only place the two are distinguishable.
        _seed_osv(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir)
        record = _run(fresh_workspace)["ubuntu:24.04/cve-2016-20013"]
        assert _fixed_in_for(record, "glibc")[0]["VendorAdvisory"] == {"NoAdvisory": True}

    def test_no_statements_means_no_wont_fix_label(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir)
        record = _run(fresh_workspace)["ubuntu:24.04/cve-2016-20013"]
        assert _fixed_in_for(record, "glibc")[0]["VendorAdvisory"] == {"NoAdvisory": False}


class TestUnionEnumeration:
    """What is emitted for a release is the union of its OSV records and its VEX statements.

    The OSV feed lists what is affected, so a package the vendor has cleared is
    absent from it and indistinguishable from one nobody has looked at. The
    statements are the vendor's complete word on the release, and the two are
    joined per (CVE, source package).
    """

    def test_a_clearance_reaches_the_base_namespace_and_the_esm_channel_carries_none(
        self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder,
    ):
        # CVE-2022-49688 at xenial. Five Pro kernel flavours carry real ESM fixes
        # and no base entry, so each would be inferred as vulnerable-with-no-fix
        # on the base release — and xenial's own archive states that the
        # vulnerable code is not in any of them. The clearance is the base
        # release's answer; the `+esm` channel keeps the real fix versions,
        # because `esm-infra/xenial` says `fixed` rather than clearing them, and
        # it never carries a clearance of its own.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)

        base = emitted["ubuntu:16.04/cve-2022-49688"]
        for package in ("linux-aws-hwe", "linux-azure", "linux-gcp", "linux-hwe", "linux-oracle"):
            assert _versions(base, package) == ["0"], package
        channel = emitted["ubuntu:16.04+esm/cve-2022-49688"]
        assert _versions(channel, "linux-hwe") == ["4.15.0-194.205~16.04.1"]
        for identifier, record in emitted.items():
            if "+esm" not in identifier:
                continue
            assert [f for f in record["Vulnerability"]["FixedIn"] if f["Version"] == "0"] == []

    def test_a_vex_only_affected_becomes_a_finding_and_a_fixed_one_does_not(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2022-50031 at jammy: `linux` carries the needs-fixing prose and
        # `linux-riscv` the won't-fix prose, neither has an OSV entry, and
        # `linux-aws-6.8` is not_affected. CVE-2014-3566 at jammy carries a
        # `fixed` statement for openssl and nothing else for it. Neither CVE has
        # an OSV record at all, so both records are the statements' alone.
        _seed_osv(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        emitted = _run(fresh_workspace)

        record = emitted["ubuntu:22.04/cve-2022-50031"]
        assert _fixed_in_for(record, "linux")[0]["Version"] == "None"
        assert _fixed_in_for(record, "linux")[0]["VendorAdvisory"] == {"NoAdvisory": False}
        assert _fixed_in_for(record, "linux-riscv")[0]["Version"] == "None"
        assert _fixed_in_for(record, "linux-riscv")[0]["VendorAdvisory"] == {"NoAdvisory": True}
        assert _fixed_in_for(record, "linux-aws-6.8")[0]["Version"] == "0"

        fixed_statement = emitted["ubuntu:22.04/cve-2014-3566"]
        assert _fixed_in_for(fixed_statement, "openssl") == []
        assert _names(fixed_statement) == {"nss", "pound"}

    def test_a_cve_with_no_statements_is_not_suppressed_into_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the vex-cases tree says nothing about CVE-2026-1403 at any token, which
        # is not the same as saying the package is not vulnerable
        _seed_osv(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        assert _versions(_run(fresh_workspace)["ubuntu:16.04/cve-2026-1403"], "gitlab") == ["None"]

    def test_a_component_not_present_statement_states_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # `component_not_present` is the tracker's DNE: the release does not ship
        # the package at all, so there is nothing for a record to be about and the
        # pre-OSV provider emitted nothing for it. It is not
        # `vulnerable_code_not_present`, which is a researched conclusion about a
        # package the release does ship and is worth stating.
        #
        # At xenial, CVE-2022-49688 carries component_not_present for
        # linux-azure-edge, vulnerable_code_not_present for linux-kvm, and
        # `affected` for linux-hwe-edge, which is the one the OSV record carries.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        record = emitted["ubuntu:16.04/cve-2022-49688"]

        assert _fixed_in_for(record, "linux-azure-edge") == []
        # while a vulnerable_code_not_present clearance for the same release is stated
        assert _versions(record, "linux-kvm") == ["0"]
        # and the package neither clears is still a finding
        assert _versions(record, "linux-hwe-edge") == ["None"]

    def test_a_component_not_present_statement_drops_an_osv_entry(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The other half, and the feeds do not state it together: OSV's
        # `affected[]` lists what is affected, so a package the vendor says the
        # release never shipped is absent from it by construction and no record in
        # the fixture trees carries the contradiction. The entry stated here is
        # the one CVE-2022-49688's xenial statement contradicts — linux-azure-edge
        # on Ubuntu:16.04:LTS — in the shape the feed would publish it.
        record = _fixture_record(fixture_dir, "osv-vex-cases/cve/2022/UBUNTU-CVE-2022-49688.json")
        record["affected"].append(_affected("Ubuntu:16.04:LTS", "linux-azure-edge", "xenial"))
        _seed_osv(fresh_workspace, fixture_dir, "osv-vex-cases", extra=[record])
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        emitted = _run(fresh_workspace)
        assert _fixed_in_for(emitted["ubuntu:16.04/cve-2022-49688"], "linux-azure-edge") == []
        # and the rest of the record is untouched
        assert _versions(emitted["ubuntu:16.04/cve-2022-49688"], "linux-hwe-edge") == ["None"]

    def test_a_rejection_learned_from_one_release_holds_on_every_release(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2026-38969, CVE-2026-41603 and CVE-2026-58212 are CVE-program
        # rejections in the `Rejected reason:` form. Each names only Ubuntu:25.10
        # in OSV — the one release Canonical was still publishing for when the
        # rejection landed — while VEX carries a clearance for jammy and noble.
        # A rejection is a fact about the CVE, so 22.04 and 24.04 have to inherit
        # it from the record that states it or they rebuild the CVE from their
        # own statements, which carry no `details` to be asked.
        # the `osv` tree is what makes 22.04 and 24.04 releases the merge walks
        _seed_osv(fresh_workspace, fixture_dir, "osv", extra=_fixture_records(fixture_dir, "osv-rejection-echo"))
        _seed_vex(fresh_workspace, fixture_dir, "vex-rejection-echo")
        emitted = _run(fresh_workspace)

        for cve in ("cve-2026-38969", "cve-2026-41603", "cve-2026-58212"):
            assert not any(cve in identifier for identifier in emitted)
        # the run did emit, so the assertion above is not vacuous
        assert "ubuntu:22.04/cve-2016-20013" in emitted

    def test_a_rejected_cve_is_not_resurrected_by_the_legacy_passthrough(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the merge drops a rejected CVE, but the passthrough builds its records
        # straight from the snapshot and never sees the OSV row. CVE-2026-38969
        # is a rejection naming only Ubuntu:25.10 in the feed; the snapshot gives
        # it a precise row, a release the feed does not serve, so the passthrough
        # is the only path that can emit it.
        _seed_osv(fresh_workspace, fixture_dir, "osv", extra=_fixture_records(fixture_dir, "osv-rejection-echo"))
        _seed_normalized(fresh_workspace, fixture_dir, "normalized-cve-data-rejection")
        emitted = _run_get(fresh_workspace)

        assert not any("2026-38969" in identifier for identifier in emitted)
        # the CVE beside it in the same snapshot directory is emitted by the same
        # pass, so the assertion above is not vacuous
        assert "ubuntu:12.04/cve-2012-5124" in emitted

    def test_the_whole_group_sentinel_holds_across_a_run(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The consumer reads a package group as unaffected only when every FixedIn
        # in it is exactly the one character `0`. A stray second entry for the same
        # package turns a suppression into a `< 0` constraint, which `0~`-prefixed
        # dpkg versions satisfy.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        asserted = 0
        for identifier, record in emitted.items():
            by_package: dict[str, list[str]] = {}
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
# ---------------------------------------------------------------------------


def _run_clearance_cases(fresh_workspace, fixture_dir, tracker_snapshot: bool = False):
    _seed_osv(fresh_workspace, fixture_dir, "osv-clearance-cases")
    _seed_vex(fresh_workspace, fixture_dir, "vex-clearance-cases")
    if tracker_snapshot:
        _seed_normalized(fresh_workspace, fixture_dir, subdir="tracker-clearance-cases")
    return _run(fresh_workspace)


class TestClearanceOutranksEverything:
    """A `vulnerable_code_not_present` statement at any token of the release wins."""

    @pytest.mark.parametrize("cve", ["cve-2020-19185", "cve-2020-19186", "cve-2020-19187", "cve-2020-19188", "cve-2020-19190"])
    def test_a_pocket_clearance_outranks_an_osv_fix(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, cve):
        # Canonical's tracker says `not-affected (6.2-0ubuntu2.1)` for ncurses on
        # focal, and its OSV generator re-encodes that as a range fixed at the
        # same version — byte-identical to the encoding of the real fix for
        # CVE-2021-39537. OSV cannot tell the two apart; VEX can, and clears
        # these five at esm-infra/focal.
        emitted = _run_clearance_cases(fresh_workspace, fixture_dir)
        assert _versions(emitted[f"ubuntu:20.04/{cve}"], "ncurses") == ["0"]

    def test_the_control_fix_on_the_same_package_survives(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2021-39537 on the same package and the same version, `released` in
        # the tracker and `fixed` in VEX. Nothing clears it, so it keeps its fix.
        emitted = _run_clearance_cases(fresh_workspace, fixture_dir)
        assert _versions(emitted["ubuntu:20.04/cve-2021-39537"], "ncurses") == ["6.2-0ubuntu2.1"]

    def test_a_base_needs_triage_yields_to_a_pocket_clearance(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The base release is `needs-triage` in the frozen snapshot — an absence
        # of research — while the ESM team that maintains the same source package
        # cleared it. The pre-OSV provider had this rule and the OSV rewrite lost
        # it.
        emitted = _run_clearance_cases(fresh_workspace, fixture_dir, tracker_snapshot=True)

        assert _versions(emitted["ubuntu:20.04/cve-2019-20788"], "x11vnc") == ["0"]
        assert _versions(emitted["ubuntu:20.04/cve-2021-37529"], "fig2dev") == ["0"]

        # nasm is the third package and it is the one that needs both halves of
        # the rule. Canonical publishes no VEX statement clearing it at any focal
        # token — base focal says `affected` — so its only clearance is the ESM
        # pocket's row in the snapshot's `ignored_patches`. Reading only VEX
        # leaves this a false positive that the pre-OSV provider suppressed.
        assert _versions(emitted["ubuntu:20.04/cve-2020-21685"], "nasm") == ["0"]

    def test_a_pocket_clearance_outranks_a_base_affected(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2022-4450 on xenial openssl: the base token says `affected`, which
        # on a release past standard support is the lifecycle boilerplate, and
        # esm-infra-legacy/xenial says the vulnerable code is not there.
        emitted = _run_clearance_cases(fresh_workspace, fixture_dir)
        assert _versions(emitted["ubuntu:16.04/cve-2022-4450"], "openssl") == ["0"]

    def test_a_fips_clearance_asserts_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # fips/focal and fips-updates/focal clear four kernel builds for
        # CVE-2023-2640. They are separate builds that map to no output
        # namespace, so they say nothing about the base release either way.
        emitted = _run_vex_cases(fresh_workspace, fixture_dir)
        named = {name for record in emitted.values() for name in _names(record)}
        for package in ("linux-fips", "linux-aws-fips", "linux-azure-fips", "linux-gcp-fips"):
            assert package not in named

    def test_a_pocket_component_not_present_asserts_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The other justification stays what it was: the pocket does not ship the
        # package, which is a fact about the pocket's own entry and not a
        # clearance to assert anywhere. Only seven such rows exist on
        # esm-infra/focal feed-wide and none of them is in the fixture trees, so
        # CVE-2023-2640's real document is taken and its esm-infra/focal statement
        # about linux-hwe-5.15 — the one package its OSV record carries there —
        # restated with that justification.
        document = _fixture_record(fixture_dir, "vex-cases/cve/2023/CVE-2023-2640.json")
        document["statements"].append(
            {
                "vulnerability": {"name": "CVE-2023-2640"},
                "status": "not_affected",
                "justification": "component_not_present",
                "products": [{"@id": "pkg:deb/ubuntu/linux-hwe-5.15@5.15.0-177.187~20.04.1?arch=source&distro=esm-infra/focal"}],
            },
        )
        _seed_osv(fresh_workspace, fixture_dir, "osv-vex-cases")
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases", extra=[document])
        emitted = _run(fresh_workspace)

        # the pocket's own entry is gone, so the +esm record is gone with it
        assert "ubuntu:20.04+esm/cve-2023-2640" not in emitted
        # and nothing is asserted in the base namespace in its place: the base
        # entry is the Pro-to-base inference's, which this statement does not
        # speak to either way
        base = emitted["ubuntu:20.04/cve-2023-2640"]
        assert _versions(base, "linux-hwe-5.15") == ["None"]


# ---------------------------------------------------------------------------
# The frozen tracker snapshot, read where neither current feed speaks
#
# The fixtures under test-fixtures/tracker-snapshot/ are two real files from
# `normalized-cve-data/`, copied whole. CVE-2014-3566 carries every status the
# emit path maps — `released`, `not-affected`, `needed`, `DNE` — and
# CVE-2006-2692 carries the `ignored` one.
# ---------------------------------------------------------------------------


def _seed_trusty_and_xenial(fresh_workspace, fixture_dir) -> None:
    """The `osv` tree serves 14.04 and 16.04, which is what makes the merge walk them."""
    _seed_osv(fresh_workspace, fixture_dir)


class TestTrackerSnapshot:
    """The third source: what the frozen snapshot still says and neither feed does."""

    def test_every_tracker_status_maps_as_the_legacy_path_mapped_it(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # Compare against parser_legacy.map_parsed, which still emits from these
        # same files for releases the feeds do not cover: `released` is a fix at
        # the version, `ignored` is won't-fix, `not-affected` is the "0" row,
        # `needed` is a finding with no fix, and `DNE` is nothing at all.
        _seed_trusty_and_xenial(fresh_workspace, fixture_dir)
        _seed_normalized(fresh_workspace, fixture_dir, "tracker-snapshot")
        emitted = _run(fresh_workspace)

        trusty = emitted["ubuntu:14.04/cve-2014-3566"]
        # released: the tracker's own version, and the fix date the run found for it
        assert _versions(trusty, "openssl") == ["1.0.1f-1ubuntu2.7"]
        assert _fixed_in_for(trusty, "openssl")[0]["Available"] == {"Date": "2024-01-01", "Kind": "first-observed"}
        # not-affected: the "0" row
        assert _versions(trusty, "nss") == ["0"]
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

    @pytest.mark.parametrize(
        "status",
        [*parser_legacy.patch_states, "in-progress", "needs-review", ""],
    )
    def test_no_status_yields_a_finding_the_legacy_path_would_drop(self, status):
        # The property, stated once rather than per status: this path may only
        # call a row vulnerable where `map_parsed` would too. Both run on the
        # releases they overlap on and the merge's record wins, so a status only
        # this side reads is a finding that exists or not depending on which
        # release it landed on. `in-progress` is the live example — Canonical
        # publishes it, `patch_states` has never held it.
        if tracker.disposition_of_status(status) == NO_FIX:
            assert parser_legacy.check_state(status), f"{status!r} is a finding here and dropped by map_parsed"

    def test_a_vex_fixed_statement_takes_the_trackers_version(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # VEX marks trusty/openjdk-6 and trusty/openjdk-7 fixed for CVE-2014-3566
        # and no OSV record carries them, so before the snapshot was read there
        # was a statement that a fix exists and no version to state.
        _seed_trusty_and_xenial(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        _seed_normalized(fresh_workspace, fixture_dir, "tracker-snapshot")
        trusty = _run(fresh_workspace)["ubuntu:14.04/cve-2014-3566"]
        assert _versions(trusty, "openjdk-6") == ["6b34-1.13.6-1ubuntu0.14.04.1"]
        assert _versions(trusty, "openjdk-7") == ["7u75-2.5.4-1~trusty1"]

    def test_a_vex_fixed_statement_with_no_tracker_row_states_nothing(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the same statements against a snapshot that does not carry the CVE at
        # all: a `fixed` statement has no version of its own, so there is still
        # nothing to say
        _seed_trusty_and_xenial(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        _seed_normalized(fresh_workspace, fixture_dir, "normalized-cve-data")
        trusty = _run(fresh_workspace)["ubuntu:14.04/cve-2014-3566"]
        assert _fixed_in_for(trusty, "openjdk-6") == []
        assert _fixed_in_for(trusty, "openjdk-7") == []

    def test_the_trackers_version_loses_to_osvs(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The feeds do not state this together either: Canonical's OSV generator
        # and its tracker agree on a fix version wherever both carry one, so no
        # record in the fixture trees disagrees with the snapshot. The entry
        # stated here is trusty/openssl on CVE-2014-3566, which the snapshot has
        # at 1.0.1f-1ubuntu2.7, given the version its own `trusty/esm` row
        # carries so the two are different strings.
        _seed_osv(fresh_workspace, fixture_dir, extra=[
            _osv_record("CVE-2014-3566", [_affected("Ubuntu:14.04:LTS", "openssl", "trusty", fixed="1.0.1f-1ubuntu9")]),
        ])
        _seed_normalized(fresh_workspace, fixture_dir, "tracker-snapshot")
        emitted = _run(fresh_workspace)
        assert _versions(emitted["ubuntu:14.04/cve-2014-3566"], "openssl") == ["1.0.1f-1ubuntu9"], (
            "the tracker's 1.0.1f-1ubuntu2.7 must not be added beside it"
        )

    def test_a_current_statement_outranks_the_snapshot(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # openssl098 is `needed` in the snapshot — vulnerable with no fix — and
        # the trusty statement carries the won't-fix prose, so the emitted finding
        # rules out an advisory the snapshot left open.
        _seed_trusty_and_xenial(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        _seed_normalized(fresh_workspace, fixture_dir, "tracker-snapshot")
        trusty = _run(fresh_workspace)["ubuntu:14.04/cve-2014-3566"]
        assert _fixed_in_for(trusty, "openssl098")[0]["Version"] == "None"
        assert _fixed_in_for(trusty, "openssl098")[0]["VendorAdvisory"] == {"NoAdvisory": True}

    def test_a_statement_of_absence_leaves_nothing_for_a_released_row(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The third thing the feeds never say together: the snapshot has
        # trusty/openjdk-6 `released` at a real version while a statement says the
        # release never shipped the package. Without asking, the row would put
        # back the package the vendor says was never there. CVE-2014-3566's real
        # document states exactly that about openjdk-6 at xenial; it is restated
        # here at trusty, where the snapshot has the row.
        document = _fixture_record(fixture_dir, "vex-cases/cve/2014/CVE-2014-3566.json")
        document["statements"].append(
            {
                "vulnerability": {"name": "CVE-2014-3566"},
                "status": "not_affected",
                "justification": "component_not_present",
                "products": [{"@id": "pkg:deb/ubuntu/openjdk-6@6b34-1.13.6-1ubuntu0.14.04.1?arch=source&distro=trusty"}],
            },
        )
        _seed_trusty_and_xenial(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases", extra=[document])
        _seed_normalized(fresh_workspace, fixture_dir, "tracker-snapshot")
        trusty = _run(fresh_workspace)["ubuntu:14.04/cve-2014-3566"]
        assert _fixed_in_for(trusty, "openjdk-6") == []
        # the sibling row, which nothing contradicts, still takes its version
        assert _versions(trusty, "openjdk-7") == ["7u75-2.5.4-1~trusty1"]

    def test_a_cve_only_the_snapshot_carries_still_emits(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the walk is the union of all three key sets, not the OSV feed's alone:
        # neither feed carries CVE-2006-2692 at all and the snapshot does
        _seed_trusty_and_xenial(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir, "vex-cases")
        emitted_without = _run(fresh_workspace)
        assert "ubuntu:14.04/cve-2006-2692" not in emitted_without

        _seed_normalized(fresh_workspace, fixture_dir, "tracker-snapshot")
        emitted = _run(fresh_workspace)
        assert _versions(emitted["ubuntu:14.04/cve-2006-2692"], "amule") == ["None"]

    def test_an_esm_clearance_carrying_a_fix_version_is_not_read_as_one(self, fixture_dir):
        # `parser_legacy`'s own test, on the real file: CVE-2014-3566's
        # `ignored_patches` holds `esm-infra/xenial openssl released
        # 1.0.1f-1ubuntu9` beside `fips/xenial openssl not-affected` at the same
        # version. The first is not a clearance because it is not `not-affected`,
        # the second because a version string is a fix and because FIPS speaks for
        # no namespace, and neither may clear xenial's openssl.
        cve_file = parser_legacy.CVEFile.from_dict(_fixture_record(fixture_dir, "tracker-snapshot/CVE-2014-3566"))
        assert tracker.esm_clearances(cve_file) == set()

    def test_an_esm_clearance_with_no_fix_version_is_read_as_one(self, fixture_dir):
        # CVE-2006-2692 holds `esm-apps/bionic amule not-affected` with no
        # version, which is the researched conclusion, beside
        # `esm-apps/xenial amule not-affected (2.4.0~...)`, which is a fix.
        cve_file = parser_legacy.CVEFile.from_dict(_fixture_record(fixture_dir, "tracker-snapshot/CVE-2006-2692"))
        assert tracker.esm_clearances(cve_file) == {("bionic", "amule")}


# ---------------------------------------------------------------------------
# Withdrawn records, and the one class of them that is a real retraction
# ---------------------------------------------------------------------------


class TestCVEProgramRejection:
    @pytest.mark.parametrize(
        "details",
        [
            "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.",
            "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.",
            "  ** reject ** leading whitespace and lower case",
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
            # A disputed record is published and live at the CVE program, not rejected,
            # in any case or whitespace form.
            {"details": "** DISPUTED ** wp-admin/setup-config.php in the installation component"},
            {"details": "\n\t** Disputed ** mixed case"},
        ],
    )
    def test_ordinary_records_are_not_rejections(self, payload):
        assert is_cve_program_rejection(payload) is False


class TestWithdrawnRecords:
    """Real feed records covering every published rejection prefix, and two that aren't.

    UBUNTU-CVE-2014-6422  withdrawn, ordinary description, carries a released fix
    UBUNTU-CVE-2014-0177  withdrawn, ordinary description, Pro-only (drives the inference)
    UBUNTU-CVE-2021-23334 withdrawn, `** REJECT **`
    UBUNTU-CVE-2011-4898  withdrawn, `** DISPUTED **`
    UBUNTU-CVE-2014-9297  NOT withdrawn, `Rejected reason:`, carries a released fix
    UBUNTU-CVE-2014-1850  withdrawn, `** REJECT **`, carries a released fix
    """

    def _run(self, fresh_workspace, fixture_dir):
        _seed_osv(fresh_workspace, fixture_dir, "osv-withdrawn")
        return _run_get(fresh_workspace)

    def test_withdrawn_record_with_a_fix_is_emitted(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2014-6422: withdrawn, wireshark on 14.04, fixed at
        # 1.12.1+g01b65bf-4+deb8u11ubuntu0.14.04.1. Real fix data that used to be dropped.
        emitted = self._run(fresh_workspace, fixture_dir)
        wireshark = _fixed_in_for(emitted["ubuntu:14.04/cve-2014-6422"], "wireshark")[0]
        assert wireshark["Version"] == "1.12.1+g01b65bf-4+deb8u11ubuntu0.14.04.1"
        assert wireshark["VendorAdvisory"]["NoAdvisory"] is False

    @pytest.mark.parametrize(
        ("cve", "marker"),
        [
            ("2021-23334", "** REJECT **"),
            ("2014-9297", "Rejected reason:"),
            ("2014-1850", "** REJECT ** with a released fix"),
        ],
    )
    def test_every_rejection_form_is_suppressed(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder, cve, marker):
        emitted = self._run(fresh_workspace, fixture_dir)
        assert not any(cve in identifier for identifier in emitted), f"{marker} was emitted"

    def test_a_disputed_record_with_no_upstream_alias_is_not_emitted(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # The real UBUNTU-CVE-2011-4898 record carries `** DISPUTED **` — a
        # published, live CVE the CVE program has not rejected — and no `upstream`
        # alias (`"aliases": []` in the feed). Every emitted record is named by
        # the upstream CVE, so it is dropped for having no name rather than for
        # being disputed.
        emitted = self._run(fresh_workspace, fixture_dir)
        assert not any("2011-4898" in identifier for identifier in emitted)

    def test_emitting_withdrawn_records_keeps_the_inference(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2014-0177 is withdrawn and Pro-only (nodejs on Pro:14.04/16.04/18.04).
        # Dropping withdrawn records lost the inference as well as the record.
        emitted = self._run(fresh_workspace, fixture_dir)
        assert _fixed_in_for(emitted["ubuntu:14.04/cve-2014-0177"], "nodejs")[0]["VendorAdvisory"] == {"NoAdvisory": True}

    def test_a_rejected_pro_record_infers_no_base_entry(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2021-23334 is `** REJECT **` and Pro-only (node-static-eval on
        # Pro:18.04/20.04). The rejection is a fact about the CVE and drops it
        # whole, inference included.
        emitted = self._run(fresh_workspace, fixture_dir)
        assert not any("2021-23334" in identifier for identifier in emitted)


# ---------------------------------------------------------------------------
# Pro-only-fix → base wont-fix inference
# ---------------------------------------------------------------------------


class TestProOnlyInference:
    """Canonical encodes "this will only be fixed on Pro" by omitting the base entry."""

    def test_a_pro_only_package_becomes_a_base_wont_fix(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2012-5855 has ONLY Ubuntu:Pro:14.04:LTS / vlc in its affected[].
        # The base Ubuntu:14.04:LTS record has no entry for vlc in any fixture, so
        # the base namespace's answer for vlc is the inference's alone.
        _seed_osv(fresh_workspace, fixture_dir, "osv-pro-inference")
        emitted = _run(fresh_workspace)
        chrony = _fixed_in_for(emitted["ubuntu:14.04/cve-2014-0021"], "chrony")[0]
        assert chrony["Version"] == "None"
        assert chrony["VendorAdvisory"] == {"NoAdvisory": True}
        # and the real Pro fix is the `+esm` channel's
        assert _versions(emitted["ubuntu:14.04+esm/cve-2014-0021"], "chrony") == ["1.29-1ubuntu0.1+esm1"]

    # The inference reads an omission and guesses. A statement is the vendor's
    # own word about that package on that release, so it replaces the guess
    # rather than being dropped for arriving second. Before `PackageState`
    # carried `inferred`, the steps after the inference could not tell a guess
    # from a fact and deferred to neither, which silently discarded the
    # statement — invisibly, while the guess happened to agree with it.
    _BASE_ECO = "Ubuntu:14.04:LTS"
    _PRO_ECO = "Ubuntu:Pro:14.04:LTS"

    def _inferred_then_stated(self, disposition):
        """Run the inference for a Pro-only package, then the statements step over it."""
        entries = {
            self._PRO_ECO: [
                OsvEntry(
                    ecosystem=self._PRO_ECO,
                    package="rustc",
                    purl="pkg:deb/ubuntu/rustc?distro=esm-infra/trusty",
                    fixed=(),
                ),
            ],
        }
        statements = {} if disposition is None else {"rustc": disposition}
        states = {}
        Parser._apply_inference(self._BASE_ECO, entries, statements, states)
        assert states["rustc"].inferred is True, "the inference should mark what it guesses"
        Parser._apply_statements(self._BASE_ECO, ["trusty"], {"trusty": statements}, states)
        return states["rustc"]

    def test_a_stated_wont_fix_keeps_the_label_on_an_inferred_entry(self):
        state = self._inferred_then_stated(WONT_FIX)
        assert state.wont_fix is True
        assert state.inferred is False, "a statement settles it, so a later token fills silence only"

    def test_a_stated_no_fix_overrides_the_inference_guess(self):
        # the vendor says the package is vulnerable with a fix still coming, which
        # contradicts the guess. This is the over-reach the seam exists to fix.
        state = self._inferred_then_stated(NO_FIX)
        assert state.wont_fix is False
        assert state.inferred is False

    def test_a_stated_clearance_still_wins_over_an_inferred_entry(self):
        state = self._inferred_then_stated(NOT_AFFECTED)
        assert state.cleared is True
        assert state.wont_fix is False

    def test_the_guess_stands_where_the_vendor_says_nothing(self):
        state = self._inferred_then_stated(None)
        assert state.wont_fix is True
        assert state.inferred is True, "nothing overrode it, so it is still only a guess"

    def test_inferred_packages_join_the_real_ones_in_one_record(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2015-20107 on 18.04 has real base entries for python2.7 and python3.6
        # and Pro-only ones for python3.7 and python3.8. One record holds all four:
        # a separate record would collide on the identifier and overwrite.
        _seed_osv(fresh_workspace, fixture_dir, "osv-pro-inference")
        record = _run(fresh_workspace)["ubuntu:18.04/cve-2015-20107"]
        assert _names(record) == {"python2.7", "python3.6", "python3.7", "python3.8"}
        # the real entries keep their fix versions
        assert _versions(record, "python2.7") == ["2.7.17-1~18.04ubuntu1.8"]
        assert _versions(record, "python3.6") == ["3.6.9-1~18.04ubuntu1.8"]
        # the inferred ones are vulnerable with no fix coming
        assert _fixed_in_for(record, "python3.7")[0]["VendorAdvisory"] == {"NoAdvisory": True}
        assert _fixed_in_for(record, "python3.8")[0]["VendorAdvisory"] == {"NoAdvisory": True}

    def test_a_base_entry_for_the_same_package_suppresses_the_inference(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2021-3782 has both Ubuntu:18.04:LTS / wayland (real, fixed)
        # and Ubuntu:Pro:16.04:LTS / wayland. The real base entry keeps its fix.
        _seed_osv(fresh_workspace, fixture_dir)
        record = _run(fresh_workspace)["ubuntu:18.04/cve-2021-3782"]
        assert _versions(record, "wayland") == ["1.16.0-1ubuntu1.1~18.04.4"]

    def test_sub_tier_slices_do_not_infer(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # FIPS rebuilds against FIPS 140-validated cryptographic modules, so a CVE
        # on the FIPS build says nothing about the mainline one. CVE-2022-4450
        # carries a real FIPS fix for openssl on 18.04 and 20.04 beside the
        # mainline entries; neither the fix nor the package may reach a base
        # record from there.
        _seed_osv(fresh_workspace, fixture_dir, "osv-clearance-cases")
        emitted = _run(fresh_workspace)
        assert "1.1.1-1ubuntu2.fips.2.1~18.04.21" not in orjson.dumps(emitted).decode()
        assert "1.1.1f-1ubuntu2.fips.17" not in orjson.dumps(emitted).decode()
        # the mainline fix for the same CVE and package is emitted
        assert _versions(emitted["ubuntu:18.04/cve-2022-4450"], "openssl") == ["1.1.1-1ubuntu2.1~18.04.21"]


# ---------------------------------------------------------------------------
# The `+esm` channel
# ---------------------------------------------------------------------------


class TestESMChannel:
    def test_plain_pro_emits_the_channel_with_the_verbatim_fix_version(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # UBUNTU-CVE-2026-41293 (tomcat) fans out across five releases with real
        # `+esm` fix versions on four of them.
        _seed_osv(fresh_workspace, fixture_dir, "osv-canonical-identity")
        emitted = _run(fresh_workspace)
        assert _versions(emitted["ubuntu:18.04+esm/cve-2026-41293"], "tomcat9") == ["9.0.16-3ubuntu0.18.04.2+esm8"]
        assert _versions(emitted["ubuntu:26.04+esm/cve-2026-41293"], "tomcat11") == ["11.0.18-1ubuntu0.1~esm1"]

    def test_two_packages_of_one_release_share_a_channel_record(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2026-41293 fixes tomcat9 and tomcat10 on Ubuntu:Pro:24.04:LTS; both
        # are the same channel and the same CVE, so both are FixedIn entries of
        # one record.
        _seed_osv(fresh_workspace, fixture_dir, "osv-canonical-identity")
        record = _run(fresh_workspace)["ubuntu:24.04+esm/cve-2026-41293"]
        assert _names(record) == {"tomcat9", "tomcat10"}

    def test_a_pro_slice_with_no_fix_emits_no_channel_record(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2022-24823 fixes netty on four Pro releases and carries an unfixed
        # Ubuntu:Pro:14.04:LTS slice. The base wont-fix already disclosed that one;
        # a `Version: "None"` +esm record would only duplicate it.
        _seed_osv(fresh_workspace, fixture_dir, "osv-esm-cases")
        emitted = _run(fresh_workspace)
        assert "ubuntu:14.04+esm/cve-2022-24823" not in emitted
        assert _versions(emitted["ubuntu:14.04/cve-2022-24823"], "netty") == ["None"]
        assert _versions(emitted["ubuntu:16.04+esm/cve-2022-24823"], "netty") == ["1:4.0.34-1ubuntu0.1~esm2"]

    def test_the_flag_off_drops_every_channel_record(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir, "osv-esm-cases")
        with_esm = _run(fresh_workspace, emit_esm=True)
        without = _run(fresh_workspace, emit_esm=False)
        assert any("+esm" in identifier for identifier in with_esm)
        assert not any("+esm" in identifier for identifier in without)
        # and the base namespaces are untouched
        assert {i for i in with_esm if "+esm" not in i} == set(without)

    def test_the_provider_config_wires_the_flag_through(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.downconvert_emit_esm = False
        p = Provider(root=str(ws.root), config=c)
        assert p.parser.downconvert_emit_esm is False

        input_path = os.path.join(str(ws.root), "ubuntu", "input")
        os.makedirs(input_path, exist_ok=True)
        _write_archive(os.path.join(input_path, "osv-all.tar.xz"), fixture_dir, "osv-esm-cases", "osv")
        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)
        assert not any("+esm" in os.path.basename(f) for f in ws.result_files())


# ---------------------------------------------------------------------------
# The two releases the feed carries only post-sweep residue for
# ---------------------------------------------------------------------------


class TestKnownHuskReleases:
    """Oracular (24.10) and plucky (25.04) are served from the frozen snapshot.

    Canonical's end-of-life removal was a regeneration sweep that left a husk of
    never-regenerated withdrawn records still naming the release, so the feed
    goes on carrying them every day and nothing in the data separates that
    residue from a healthy release's records. The two are named in code and
    refused; every other release the archive names is read whatever its support
    status.
    """

    def test_no_record_is_emitted_for_a_husk_release_from_the_feed(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # osv-husk carries real withdrawn 24.10 and 25.04 records plus one of
        # plucky's three live stragglers, beside a live release's record
        _seed_osv(fresh_workspace, fixture_dir, "osv-husk")
        emitted = _run(fresh_workspace)
        assert not any(i.startswith(("ubuntu:24.10/", "ubuntu:25.04/")) for i in emitted)
        # a live release in the same archive is emitted normally
        assert "ubuntu:24.04/cve-2022-21695" in emitted

    def test_a_husk_release_is_served_from_the_snapshot_instead(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir, "osv-husk")
        _seed_normalized(fresh_workspace, fixture_dir, "normalized-cve-data-husk")
        emitted = _run_get(fresh_workspace)
        assert "ubuntu:24.10/cve-2019-1010305" in emitted
        assert "ubuntu:25.04/cve-2019-1010305" in emitted

    def test_a_husk_release_is_refused_wherever_the_feed_names_it(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # CVE-2020-21685 names Ubuntu:25.04 beside four live releases, and
        # CVE-2025-46336 names it beside six. Neither puts anything in plucky's
        # namespace, and the live releases beside it are unaffected.
        _seed_osv(fresh_workspace, fixture_dir, "osv-clearance-cases")
        emitted = _run(fresh_workspace)
        assert not any(i.startswith("ubuntu:25.04") for i in emitted)
        assert _versions(emitted["ubuntu:22.04/cve-2020-21685"], "nasm") == ["None"]

    def test_a_past_eol_release_that_is_not_a_husk_is_read_like_any_other(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # questing (Ubuntu:25.10) has a published EOL in the past, and nothing
        # here asks: there is no calendar, no clock and no `now` in this path.
        _seed_osv(fresh_workspace, fixture_dir, "osv-canonical-identity")
        assert "ubuntu:25.10/cve-2026-7246" in _run(fresh_workspace)

    def test_the_tracker_not_affected_package_emits_one_zero_version_fixedin(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # grype reads a package group whose every FixedIn is exactly "0" as an
        # unaffected package that suppresses and never matches. The sentinel is an
        # exact string compare, so a second FixedIn for the same package on the
        # same namespace would drop the group back onto the affected path.
        _seed_normalized(fresh_workspace, fixture_dir, "normalized-cve-data-husk")
        p = Parser(workspace=fresh_workspace)
        by_id = {t[0]: t[2] for t in p._iter_normalized_cve_data()}

        plucky = by_id["ubuntu:25.04/cve-2019-1010305"]
        assert _versions(plucky, "clamav") == ["0"]
        # and a released package on the same record still carries its real version
        assert _versions(plucky, "libmspack") == ["0.10.1-1"]


# ---------------------------------------------------------------------------
# The frozen snapshot passthrough, for releases the feeds do not serve
# ---------------------------------------------------------------------------


class TestSnapshotPassthrough:
    # Real normalized-cve-data fixtures:
    #   CVE-2012-5124   chromium-browser, released on precise + quantal
    #   CVE-2013-6627   chromium-browser, released on precise + quantal + raring
    #   CVE-2022-31258  check-mk, not-affected on bionic (used for the coverage filter)

    def test_emits_os_schema_envelopes_for_unserved_namespaces(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_normalized(fresh_workspace, fixture_dir)
        # nothing read from the feed → no release is served → every legacy ns emits
        p = Parser(workspace=fresh_workspace)
        records = list(p._iter_normalized_cve_data())

        assert sorted(r[0] for r in records) == [
            "ubuntu:12.04/cve-2012-5124",
            "ubuntu:12.04/cve-2013-6627",
            "ubuntu:12.10/cve-2012-5124",
            "ubuntu:12.10/cve-2013-6627",
            "ubuntu:13.04/cve-2013-6627",
            "ubuntu:18.04/cve-2022-31258",
        ]
        for _id, sch, _payload in records:
            assert "/os/" in sch.url

    def test_skips_records_for_namespaces_the_feed_serves(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_normalized(fresh_workspace, fixture_dir)
        # the `osv` tree names Ubuntu:18.04:LTS, so bionic is served from the feed
        _seed_osv(fresh_workspace, fixture_dir)
        p = Parser(workspace=fresh_workspace)
        p._read_osv_archive()
        identifiers = sorted(r[0] for r in p._iter_normalized_cve_data())
        p._osv_rows.close()

        assert "ubuntu:18.04/cve-2022-31258" not in identifiers
        assert identifiers == [
            "ubuntu:12.04/cve-2012-5124",
            "ubuntu:12.04/cve-2013-6627",
            "ubuntu:12.10/cve-2012-5124",
            "ubuntu:12.10/cve-2013-6627",
            "ubuntu:13.04/cve-2013-6627",
        ]

    def test_a_release_the_feed_carries_only_an_esm_build_of_still_passes_through(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # the osv-withdrawn tree names Ubuntu:Pro:18.04:LTS and no base 18.04
        # record at all. The Pro-to-base inference still puts records in bionic's
        # namespace, but the base release's own data is gone from the feed and the
        # snapshot is what holds it, so both sources speak for it.
        _seed_normalized(fresh_workspace, fixture_dir)
        _seed_osv(fresh_workspace, fixture_dir, "osv-withdrawn")
        emitted = _run_get(fresh_workspace)
        assert "ubuntu:18.04/cve-2022-31258" in emitted
        assert _versions(emitted["ubuntu:18.04/cve-2014-0177"], "nodejs") == ["None"]

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
        assert "3.0.1271.97-0ubuntu0.12.04.1" in _versions(precise, "chromium-browser")

    def test_fixdater_not_queried_for_namespaces_the_feed_serves(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Count fixdater queries via a callable response. With 18.04 served from
        # the feed, the bionic legacy record (CVE-2022-31258) should never reach
        # map_parsed — so fixdater should be called zero times for it.
        calls = []

        def counting_responses(vuln_id, cpe_or_package, fix_version, ecosystem):
            calls.append((vuln_id, cpe_or_package, ecosystem))
            return []

        fake_fixdate_finder(responses=counting_responses)
        _seed_normalized(fresh_workspace, fixture_dir)
        _seed_osv(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        p._read_osv_archive()
        list(p._iter_normalized_cve_data())
        p._osv_rows.close()

        bionic_filtered_calls = [c for c in calls if c[0] == "CVE-2022-31258"]
        assert bionic_filtered_calls == [], f"expected zero fixdater calls for the served CVE-2022-31258, got {bionic_filtered_calls}"
        # And calls for the unserved namespaces DO happen
        assert any(c[0] == "CVE-2012-5124" for c in calls)
        assert any(c[0] == "CVE-2013-6627" for c in calls)


class TestParserEmissionOrder:
    """Policy: the snapshot passthrough first, the merge last.

    The two only collide for a release the feed carries an extended-support
    build of and no base data — both speak for its base namespace — and the
    merge's record is the one that has seen every source, so it is written last.
    """

    def test_passthrough_yielded_before_the_merge(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        _seed_osv(fresh_workspace, fixture_dir)
        _seed_vex(fresh_workspace, fixture_dir)
        _seed_normalized(fresh_workspace, fixture_dir)

        p = Parser(workspace=fresh_workspace)
        with patch.object(p, "_download_archive"), patch.object(p, "_download_vex_archive"):
            identifiers = [t[0] for t in p.get()]

        passthrough = {"ubuntu:12.04", "ubuntu:12.10", "ubuntu:13.04"}
        last_passthrough = max(i for i, x in enumerate(identifiers) if x.split("/")[0] in passthrough)
        first_merged = min(i for i, x in enumerate(identifiers) if x.startswith("ubuntu:24.04/"))
        assert last_passthrough < first_merged


# ---------------------------------------------------------------------------
# The clean-up of the stores this shape replaced
# ---------------------------------------------------------------------------


class TestCleanInput:
    def test_the_replaced_stores_are_removed_once(self, fresh_workspace, auto_fake_fixdate_finder):
        # input/ is kept between runs, so 12 GB of per-release SQLite would stay
        # for good if nothing removed it
        for name in ("fragments", "vex-fragments", "tracker-index", "ubuntu-cve-tracker", "distro-info"):
            directory = os.path.join(fresh_workspace.input_path, name)
            os.makedirs(directory, exist_ok=True)
            with open(os.path.join(directory, "something.db"), "wb") as fh:
                fh.write(b"x")
        keep = os.path.join(fresh_workspace.input_path, "normalized-cve-data")
        os.makedirs(keep, exist_ok=True)

        Parser(workspace=fresh_workspace)._clean_input()

        for name in ("fragments", "vex-fragments", "tracker-index", "ubuntu-cve-tracker", "distro-info"):
            assert not os.path.exists(os.path.join(fresh_workspace.input_path, name))
        assert os.path.isdir(keep)

    def test_a_partial_download_left_by_a_killed_run_is_swept(self, fresh_workspace, auto_fake_fixdate_finder):
        # download_to_file only removes its own staging file when its own retry
        # loop exhausts; a hard kill skips that, and input/ is kept between runs
        orphan = os.path.join(fresh_workspace.input_path, "osv-all.tar.xz" + http.PARTIAL_SUFFIX)
        with open(orphan, "wb") as fh:
            fh.write(b"half an archive")
        keep = os.path.join(fresh_workspace.input_path, "osv-all.tar.xz")
        with open(keep, "wb") as fh:
            fh.write(b"a whole one")

        Parser(workspace=fresh_workspace)._clean_input()

        assert not os.path.exists(orphan)
        assert os.path.isfile(keep)

    def test_it_is_idempotent_on_a_workspace_with_nothing_to_remove(self, fresh_workspace, auto_fake_fixdate_finder):
        p = Parser(workspace=fresh_workspace)
        p._clean_input()
        p._clean_input()
        assert os.path.isdir(fresh_workspace.input_path)


# ---------------------------------------------------------------------------
# USN fix-date overlay — authoritative fix-ship dates from USN.published
# ---------------------------------------------------------------------------


def _usn_overlay_from_fixture(fixture_dir: str, *names: str) -> USNFixDateOverlay:
    overlay = USNFixDateOverlay()
    for name in names:
        with open(os.path.join(fixture_dir, "osv", "usn", name), "rb") as fh:
            overlay.ingest_record(orjson.loads(fh.read()))
    return overlay


class TestUSNFixDateOverlay:
    """Pure tests for the overlay class + ISO-date parsing."""

    def test_lookup_returns_usn_publish_date(self, fixture_dir):
        overlay = _usn_overlay_from_fixture(fixture_dir, "USN-5614-1.json")
        # USN-5614-1 fixture covers wayland on 18.04/20.04/22.04, published 2022-09-15.
        assert overlay.lookup("Ubuntu:18.04:LTS", "wayland", "1.16.0-1ubuntu1.1~18.04.4") == datetime.date(2022, 9, 15)
        assert overlay.lookup("Ubuntu:20.04:LTS", "wayland", "1.18.0-1ubuntu0.1") == datetime.date(2022, 9, 15)
        assert overlay.lookup("Ubuntu:22.04:LTS", "wayland", "1.20.0-1ubuntu0.1") == datetime.date(2022, 9, 15)

    def test_lookup_misses_return_none(self, fixture_dir):
        overlay = _usn_overlay_from_fixture(fixture_dir, "USN-5614-1.json")
        assert overlay.lookup("Ubuntu:18.04:LTS", "wayland", "9.9.9-bogus") is None
        assert overlay.lookup("Ubuntu:18.04:LTS", "nonexistent", "1.0") is None
        assert overlay.lookup("Ubuntu:99.99:LTS", "wayland", "1.16.0-1ubuntu1.1~18.04.4") is None

    def test_empty_overlay_lookups_return_none(self):
        overlay = USNFixDateOverlay()
        assert overlay.lookup("any", "any", "any") is None
        assert len(overlay) == 0

    def test_iso_date_parsing(self):
        from vunnel.providers.ubuntu.usn_fixdate_overlay import _parse_iso_date

        # Real USN timestamp shapes we observed in the live feed
        assert _parse_iso_date("2023-10-11T11:34:51Z") == datetime.date(2023, 10, 11)
        assert _parse_iso_date("2023-10-17T11:22:48.353678Z") == datetime.date(2023, 10, 17)
        assert _parse_iso_date("2014-12-24T18:59:00Z") == datetime.date(2014, 12, 24)
        # Date-only form (defensive — not observed in real data, but parses correctly)
        assert _parse_iso_date("2023-10-11") == datetime.date(2023, 10, 11)
        # Garbage returns None — caller treats as "no USN date" and falls through
        assert _parse_iso_date("not a date") is None
        assert _parse_iso_date("") is None


class TestUSNOverlayIntegration:
    """End-to-end: the USN's authoritative date beats other fixdater sources."""

    def test_usn_date_overrides_first_observed(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # A first-observed finder that would return 2024-01-01 for everything —
        # the "wrong day, we just turned on Pro and grype-db is recording today"
        # failure mode the overlay was built to prevent.
        fake_fixdate_finder(responses=[Result(date=datetime.date(2024, 1, 1), kind="first-observed", accurate=True)])
        _seed_osv(fresh_workspace, fixture_dir)
        # CVE-2021-3782 / wayland on 18.04 has a real USN (USN-5614-1) published 2022-09-15
        record = _run(fresh_workspace)["ubuntu:18.04/cve-2021-3782"]
        assert _fixed_in_for(record, "wayland")[0]["Available"] == {"Date": "2022-09-15", "Kind": "advisory"}

    def test_falls_back_to_first_observed_when_usn_missing(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # First-observed mock with a date EARLIER than CVE.published (2013-10-28) so it
        # beats the CVE.published fallback candidate in fixdater.best()'s ranking.
        fake_fixdate_finder(responses=[Result(date=datetime.date(2013, 7, 15), kind="first-observed", accurate=True)])
        _seed_osv(fresh_workspace, fixture_dir)
        # CVE-2013-2208 fixes tpp@1.3.1-3 on Ubuntu:14.04:LTS; no USN in the
        # fixture ships that tuple, so the overlay lookup misses.
        record = _run(fresh_workspace)["ubuntu:14.04/cve-2013-2208"]
        assert _fixed_in_for(record, "tpp")[0]["Available"] == {"Date": "2013-07-15", "Kind": "first-observed"}

    def test_missing_archive_disables_the_overlay_gracefully(self, fresh_workspace, auto_fake_fixdate_finder):
        p = Parser(workspace=fresh_workspace)
        p._read_osv_archive()
        assert p._usn_overlay is None
        assert p._served_versions == set()


# ---------------------------------------------------------------------------
# Full Provider.update integration
# ---------------------------------------------------------------------------


def _stage_workspace_for_update(ws_root: str, fixture_dir: str, subdir: str = "osv") -> str:
    input_path = os.path.join(ws_root, "ubuntu", "input")
    os.makedirs(input_path, exist_ok=True)
    _write_archive(os.path.join(input_path, "osv-all.tar.xz"), fixture_dir, subdir, "osv")
    return input_path


class TestProviderUpdate:
    def test_writes_one_record_per_namespace_cve_pair(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        # 12 base records plus the one `+esm` record the fixture's only Pro fix
        # produces (Pro:16.04 / wayland on CVE-2021-3782). See
        # TestMergeEnumeration::test_one_record_per_namespace_the_feed_speaks_for
        # for the full list.
        assert ws.num_result_entries() == 13

    def test_writes_the_os_schema_for_every_record(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        schemas = set()
        for f in ws.result_files():
            with open(f, "rb") as fh:
                schemas.add(orjson.loads(fh.read())["schema"])
        assert schemas and all("/os/schema-" in s for s in schemas), schemas

    def test_writes_the_merge_and_the_passthrough_together(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        input_path = _stage_workspace_for_update(str(ws.root), fixture_dir)
        shutil.copytree(os.path.join(fixture_dir, "normalized-cve-data"), os.path.join(input_path, "normalized-cve-data"))

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        # the 13 from the merge, plus 6 from the snapshot: 2012-5124 on precise
        # and quantal, 2013-6627 on those two and raring, and 2022-31258 on
        # bionic, which the feed does not speak for in this fixture because no
        # record in it names Ubuntu:18.04:LTS at all — only the Pro build.
        assert ws.num_result_entries() == 19

    def test_via_snapshot(self, helpers, fixture_dir, fake_fixdate_finder):
        fake_fixdate_finder(responses=[Result(date=datetime.date(2024, 1, 1), kind="first-observed")])

        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        input_path = _stage_workspace_for_update(str(ws.root), fixture_dir)
        # the snapshot passthrough's own fixture
        shutil.copytree(os.path.join(fixture_dir, "normalized-cve-data"), os.path.join(input_path, "normalized-cve-data"))
        # and the statements, so the won't-fix labels and clearances are in the golden files
        _write_archive(os.path.join(input_path, "vex-all.tar.xz"), fixture_dir, "vex", "vex")

        with patch.object(p.parser, "_download_archive"), patch.object(p.parser, "_download_vex_archive"):
            p.update(None)

        ws.assert_result_snapshots()

