from __future__ import annotations

import datetime
import os
import shutil
from unittest.mock import patch

import pytest

from vunnel import provider, result, schema, workspace
from vunnel.providers.ubuntu import Config, Provider
from vunnel.providers.ubuntu.parser import Parser
from vunnel.tool.fixdate.finder import Result


@pytest.fixture
def fixture_dir(helpers):
    return helpers.local_dir("test-fixtures")


@pytest.fixture
def fresh_workspace(tmpdir):
    return workspace.Workspace(tmpdir, "ubuntu", create=True)


class TestProvider:
    def test_static_attrs(self):
        assert Provider.name() == "ubuntu"
        assert Provider.tags() == ["vulnerability", "os"]
        assert "/osv/" in Provider.__schema__.url
        # We deliberately do NOT bump __distribution_version__. The framework would
        # otherwise call workspace.clear() on the first run with the new code, wiping
        # the operationally-critical input/legacy/ cache. Downstream dispatches on the
        # per-envelope schema URL instead.
        assert Provider.__distribution_version__ == 1

    def test_compatible_schema_not_overridden(self):
        # parser yields Schema objects directly; we don't gate on compatible_schema
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


class TestParserOSVIteration:
    def test_iterates_osv_records_from_extracted_dir(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        shutil.copytree(os.path.join(fixture_dir, "osv"), os.path.join(fresh_workspace.input_path, "osv"))

        p = Parser(workspace=fresh_workspace)
        records = list(p._iter_osv_records())

        identifiers = sorted(r[0] for r in records)
        assert identifiers == [
            "ubuntu-cve-2011-0221",
            "ubuntu-cve-2021-3782",
            "ubuntu-cve-2023-99999",
        ]

    def test_yields_schema_per_record_version(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        shutil.copytree(os.path.join(fixture_dir, "osv"), os.path.join(fresh_workspace.input_path, "osv"))
        p = Parser(workspace=fresh_workspace)
        by_id = {r[0]: r[1] for r in p._iter_osv_records()}

        # the older-schema fixture record gets a 1.6.1 schema; the rest get 1.7.0
        assert by_id["ubuntu-cve-2023-99999"].version == "1.6.1"
        assert by_id["ubuntu-cve-2023-99999"].url.endswith("/osv/schema-1.6.1.json")
        assert by_id["ubuntu-cve-2021-3782"].version == "1.7.0"
        assert by_id["ubuntu-cve-2021-3782"].url.endswith("/osv/schema-1.7.0.json")

    def test_payload_passed_through_verbatim(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        shutil.copytree(os.path.join(fixture_dir, "osv"), os.path.join(fresh_workspace.input_path, "osv"))
        p = Parser(workspace=fresh_workspace)
        by_id = {r[0]: r[2] for r in p._iter_osv_records()}

        rec = by_id["ubuntu-cve-2021-3782"]
        ecosystems = sorted({a["package"]["ecosystem"] for a in rec["affected"]})
        assert ecosystems == ["Ubuntu:18.04:LTS", "Ubuntu:20.04:LTS"]


class TestParserFixDatePatching:
    def test_patches_records_with_fixed_events(self, fresh_workspace, fixture_dir, fake_fixdate_finder):
        # Use a mock date *earlier* than the record's published date AND mark it accurate so it
        # becomes the upper bound — that way Finder.best() filters out the higher-confidence
        # "published" candidate (which is later than the upper bound) and falls back to the mock.
        finder = fake_fixdate_finder(
            responses=[Result(date=datetime.date(2020, 1, 1), kind="first-observed", accurate=True)],
        )
        shutil.copytree(os.path.join(fixture_dir, "osv"), os.path.join(fresh_workspace.input_path, "osv"))

        p = Parser(workspace=fresh_workspace, fixdater=finder)
        by_id = {r[0]: r[2] for r in p._iter_osv_records()}

        rec = by_id["ubuntu-cve-2021-3782"]
        bionic = next(a for a in rec["affected"] if a["package"]["ecosystem"] == "Ubuntu:18.04:LTS")
        fixes = bionic["ranges"][0]["database_specific"]["anchore"]["fixes"]
        assert any(f["date"] == "2020-01-01" for f in fixes)

    def test_no_fixed_events_means_no_anchore_field(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        shutil.copytree(os.path.join(fixture_dir, "osv"), os.path.join(fresh_workspace.input_path, "osv"))
        p = Parser(workspace=fresh_workspace)
        by_id = {r[0]: r[2] for r in p._iter_osv_records()}

        # CVE-2011-0221 has only {introduced: 0} -> patch_fix_date is a no-op
        rec = by_id["ubuntu-cve-2011-0221"]
        for aff in rec["affected"]:
            for r in aff["ranges"]:
                assert "anchore" not in r.get("database_specific", {})


class TestParserLegacyPassthrough:
    def test_iterates_legacy_envelopes(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        legacy_src = os.path.join(fixture_dir, "input", "legacy")
        shutil.copytree(legacy_src, os.path.join(fresh_workspace.input_path, "legacy"))

        p = Parser(workspace=fresh_workspace)
        records = list(p._iter_legacy_records())

        identifiers = sorted(r[0] for r in records)
        assert identifiers == ["ubuntu:12.04/cve-2012-1111", "ubuntu:13.04/cve-2013-2222"]

    def test_legacy_envelopes_preserve_os_schema_url(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        legacy_src = os.path.join(fixture_dir, "input", "legacy")
        shutil.copytree(legacy_src, os.path.join(fresh_workspace.input_path, "legacy"))

        p = Parser(workspace=fresh_workspace)
        for _id, sch, _payload in p._iter_legacy_records():
            assert "/os/schema-" in sch.url
            assert sch.version == "1.1.0"

    def test_legacy_dir_missing_yields_nothing(self, fresh_workspace, auto_fake_fixdate_finder):
        p = Parser(workspace=fresh_workspace)
        assert list(p._iter_legacy_records()) == []


class TestParserDownloadAndExtract:
    def test_download_streams_archive_to_input(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
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

        with patch("vunnel.providers.ubuntu.parser.http.get", return_value=FakeResp(payload)) as mock_get:
            p = Parser(workspace=fresh_workspace)
            p._download()

        archive = os.path.join(fresh_workspace.input_path, "osv-all.tar.xz")
        assert os.path.isfile(archive)
        assert os.path.getsize(archive) == len(payload)
        mock_get.assert_called_once()

    def test_extract_wipes_existing_osv_dir(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        # seed a stale file under input/osv/ that should be removed by extract
        stale = os.path.join(fresh_workspace.input_path, "osv", "stale.json")
        os.makedirs(os.path.dirname(stale))
        with open(stale, "w") as f:
            f.write("{}")

        shutil.copy(
            os.path.join(fixture_dir, "sample-osv-all.tar.xz"),
            os.path.join(fresh_workspace.input_path, "osv-all.tar.xz"),
        )

        p = Parser(workspace=fresh_workspace)
        p._extract()

        assert not os.path.exists(stale), "stale file should be wiped before extraction"
        assert os.path.isfile(
            os.path.join(fresh_workspace.input_path, "osv", "cve", "2021", "UBUNTU-CVE-2021-3782.json"),
        )


class TestParserEmissionOrder:
    def test_legacy_yielded_before_osv(self, fresh_workspace, fixture_dir, auto_fake_fixdate_finder):
        shutil.copytree(os.path.join(fixture_dir, "osv"), os.path.join(fresh_workspace.input_path, "osv"))
        shutil.copytree(
            os.path.join(fixture_dir, "input", "legacy"),
            os.path.join(fresh_workspace.input_path, "legacy"),
        )

        p = Parser(workspace=fresh_workspace)

        with patch.object(p, "_download"), patch.object(p, "_extract"):
            ids = [t[0] for t in p.get()]

        first_osv = next(i for i, x in enumerate(ids) if x.startswith("ubuntu-cve-"))
        last_legacy = max(i for i, x in enumerate(ids) if x.startswith("ubuntu:"))
        assert last_legacy < first_osv


def _stage_workspace_for_update(ws_root: str, fixture_dir: str) -> None:
    """Copy fixture archive + legacy db into the workspace's input dir."""
    input_path = os.path.join(ws_root, "ubuntu", "input")
    shutil.copy(
        os.path.join(fixture_dir, "sample-osv-all.tar.xz"),
        os.path.join(input_path, "osv-all.tar.xz"),
    )
    shutil.copytree(
        os.path.join(fixture_dir, "input", "legacy"),
        os.path.join(input_path, "legacy"),
    )


class TestProviderUpdate:
    def test_writes_mixed_schema_results(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download"):
            p.update(None)

        # 3 OSV records + 2 legacy records = 5 entries
        assert ws.num_result_entries() == 5
        # NOTE: we deliberately do NOT call result_schemas_valid() here. Canonical's records
        # declare schema_version=1.7.0 but use the "Ubuntu" severity.type, which the upstream
        # OSV 1.7.0 schema rejects (it permits only CVSS_V{2,3,4}). The provider is per spec
        # a verbatim pass-through; reconciling this is grype-db's OSV transformer's job.

    def test_writes_expected_envelope_schemas(self, helpers, fixture_dir, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download"):
            p.update(None)

        # confirm the mixed-schema envelope: OSV records carry per-record OSV schema URLs,
        # legacy records carry the original OS schema URL
        import json
        schemas = []
        for f in ws.result_files():
            with open(f) as fh:
                schemas.append(json.load(fh)["schema"])
        assert any("/osv/schema-1.7.0.json" in s for s in schemas), schemas
        assert any("/osv/schema-1.6.1.json" in s for s in schemas), schemas
        assert any("/os/schema-1.1.0.json" in s for s in schemas), schemas

    def test_via_snapshot(self, helpers, fixture_dir, fake_fixdate_finder):
        fake_fixdate_finder(responses=[Result(date=datetime.date(2024, 1, 1), kind="first-observed")])

        ws = helpers.provider_workspace_helper(name=Provider.name())
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE

        p = Provider(root=str(ws.root), config=c)
        _stage_workspace_for_update(str(ws.root), fixture_dir)

        with patch.object(p.parser, "_download"):
            p.update(None)

        ws.assert_result_snapshots()
