"""Behavior tests for Parser.get() and Provider schema handling."""
import io
import json
import os
import tarfile
from unittest.mock import Mock, patch

import pytest

from vunnel import workspace
from vunnel.providers.bellsoft import Provider
from vunnel.providers.bellsoft.parser import Parser


def _write_archive(ws, records, extra_members=None, top_dir="osv-database-master"):
    """Build the input tarball the way a github archive download lays it out:
    content nested under a "<repo>-<branch>/" top-level directory."""
    prefix = f"{top_dir}/" if top_dir else ""
    members = {f"{prefix}BELL-CVE/{r['id']}.json": json.dumps(r).encode() for r in records}
    members.update(extra_members or {})

    os.makedirs(ws.input_path, exist_ok=True)
    with tarfile.open(os.path.join(ws.input_path, "osv-database.tar.gz"), mode="w:gz") as tar:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


V3 = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
V2_BARE = {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}


@pytest.fixture()
def ws(tmp_path):
    return workspace.Workspace(str(tmp_path), "bellsoft", create=True)


@pytest.fixture()
def parser(ws, auto_fake_fixdate_finder):
    with patch.object(Parser, "_download"):
        yield Parser(ws=ws)


def test_get_yields_each_record_once(parser, ws):
    _write_archive(ws, [{"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4", "severity": [V3]}])
    results = list(parser.get())
    assert len(results) == 1


def test_get_tolerates_empty_severity_list(parser, ws):
    _write_archive(ws, [{"id": "BELL-CVE-2020-0002", "schema_version": "1.7.4", "severity": []}])
    results = list(parser.get())
    assert {r[0] for r in results} == {"BELL-CVE-2020-0002"}


def test_record_with_v2_and_v3_severity_is_not_dropped(parser, ws):
    # 3 real upstream records (e.g. BELL-CVE-2010-4478) have [CVSS_V2, CVSS_V3]
    _write_archive(ws, [{"id": "BELL-CVE-2020-0003", "schema_version": "1.7.4", "severity": [V2_BARE, V3]}])
    results = list(parser.get())
    assert len(results) == 1
    scores = [s["score"] for s in results[0][2]["severity"]]
    assert scores == ["CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", V3["score"]]


def test_v2_only_record_is_kept_and_prefixed(parser, ws):
    # ~727 upstream records carry only a bare CVSS_V2 score; grype-db requires
    # the "CVSS:2.0/" prefix to parse them
    _write_archive(ws, [{"id": "BELL-CVE-2020-0004", "schema_version": "1.7.4", "severity": [V2_BARE]}])
    results = list(parser.get())
    assert len(results) == 1
    assert results[0][2]["severity"][0]["score"] == "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"


def test_get_handles_flat_archive_layout(parser, ws):
    # tolerate an archive without the github "<repo>-<branch>/" nesting
    _write_archive(ws, [{"id": "BELL-CVE-2020-0008", "schema_version": "1.7.4"}], top_dir=None)
    results = list(parser.get())
    assert {r[0] for r in results} == {"BELL-CVE-2020-0008"}


def test_download_writes_archive(ws, auto_fake_fixdate_finder):
    # serve a github-shaped tarball via a mocked http.get and verify the
    # download lands where _load expects it
    payload = json.dumps({"id": "BELL-CVE-2020-0009", "schema_version": "1.7.4"}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("osv-database-master/BELL-CVE/BELL-CVE-2020-0009.json")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    response = Mock()
    response.iter_content = lambda chunk_size: iter([buf.getvalue()])
    with patch("vunnel.providers.bellsoft.parser.http.get", return_value=response) as mock_get:
        parser = Parser(ws=ws)
        parser._download()

    assert mock_get.call_args.kwargs["timeout"] == 125
    assert os.path.exists(os.path.join(ws.input_path, "osv-database.tar.gz"))
    # and the downloaded archive is loadable end to end
    assert next(parser._load())["id"] == "BELL-CVE-2020-0009"


def test_fix_dates_are_patched_onto_ranges(parser, ws):
    # osv.patch_fix_date annotates database_specific.anchore.fixes with
    # first-observed dates (faked to 2024-01-01 by auto_fake_fixdate_finder),
    # which grype-db surfaces as fix availability
    _write_archive(ws, [{
        "id": "BELL-CVE-2020-0007",
        "schema_version": "1.7.4",
        "affected": [{
            "package": {"ecosystem": "Alpaquita:stream", "name": "expat"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.7.2-r0"}]}],
        }],
    }])
    results = list(parser.get())
    assert len(results) == 1
    rng = results[0][2]["affected"][0]["ranges"][0]
    fixes = rng["database_specific"]["anchore"]["fixes"]
    assert fixes[0]["version"] == "2.7.2-r0"
    assert fixes[0]["date"] == "2024-01-01"
    assert fixes[0]["kind"] == "first-observed"


def test_withdrawn_record_is_skipped(parser, ws):
    _write_archive(ws, [{"id": "BELL-CVE-2020-0005", "schema_version": "1.7.4", "withdrawn": "2024-01-01T00:00:00Z"}])
    assert list(parser.get()) == []


def test_malformed_members_are_skipped_not_fatal(parser, ws):
    _write_archive(
        ws,
        [{"id": "BELL-CVE-2020-0006", "schema_version": "1.7.4"}],
        extra_members={
            "osv-database-master/BELL-CVE/README.md": b"# not an advisory",
            "osv-database-master/BELL-CVE/broken.json": b"{not json",
            "osv-database-master/BELL-CVE/no-id.json": json.dumps({"schema_version": "1.7.4"}).encode(),
            "osv-database-master/LICENSE": b"outside the advisory dir",
        },
    )
    results = list(parser.get())
    assert {r[0] for r in results} == {"BELL-CVE-2020-0006"}


def test_load_with_no_archive_yields_nothing(parser):
    assert list(parser._load()) == []


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
