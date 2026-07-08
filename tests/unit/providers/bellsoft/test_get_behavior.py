"""Behavior tests for Parser.get() and Provider schema handling."""
import json
import os
from unittest.mock import patch

import pytest

from vunnel import workspace
from vunnel.providers.bellsoft import Provider
from vunnel.providers.bellsoft.parser import Parser


def _write_record(ws, record, filename=None):
    d = os.path.join(ws.input_path, "osv-database", "BELL-CVE")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, filename or f"{record['id']}.json"), "w") as f:
        json.dump(record, f)


V3 = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
V2_BARE = {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}


@pytest.fixture()
def ws(tmp_path):
    return workspace.Workspace(str(tmp_path), "bellsoft", create=True)


@pytest.fixture()
def parser(ws):
    with (
        patch("vunnel.providers.bellsoft.parser.GitWrapper.clone_repo"),
        patch("vunnel.providers.bellsoft.parser.GitWrapper.delete_repo"),
    ):
        yield Parser(ws=ws)


def test_get_yields_each_record_once(parser, ws):
    _write_record(ws, {"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4", "severity": [V3]})
    results = list(parser.get())
    assert len(results) == 1


def test_get_tolerates_empty_severity_list(parser, ws):
    _write_record(ws, {"id": "BELL-CVE-2020-0002", "schema_version": "1.7.4", "severity": []})
    results = list(parser.get())
    assert {r[0] for r in results} == {"BELL-CVE-2020-0002"}


def test_record_with_v2_and_v3_severity_is_not_dropped(parser, ws):
    # 3 real upstream records (e.g. BELL-CVE-2010-4478) have [CVSS_V2, CVSS_V3]
    _write_record(ws, {"id": "BELL-CVE-2020-0003", "schema_version": "1.7.4", "severity": [V2_BARE, V3]})
    results = list(parser.get())
    assert len(results) == 1
    scores = [s["score"] for s in results[0][2]["severity"]]
    assert scores == ["CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", V3["score"]]


def test_v2_only_record_is_kept_and_prefixed(parser, ws):
    # ~727 upstream records carry only a bare CVSS_V2 score; grype-db requires
    # the "CVSS:2.0/" prefix to parse them
    _write_record(ws, {"id": "BELL-CVE-2020-0004", "schema_version": "1.7.4", "severity": [V2_BARE]})
    results = list(parser.get())
    assert len(results) == 1
    assert results[0][2]["severity"][0]["score"] == "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"


def test_withdrawn_record_is_skipped(parser, ws):
    _write_record(ws, {"id": "BELL-CVE-2020-0005", "schema_version": "1.7.4", "withdrawn": "2024-01-01T00:00:00Z"})
    assert list(parser.get()) == []


def test_malformed_files_are_skipped_not_fatal(parser, ws):
    _write_record(ws, {"id": "BELL-CVE-2020-0006", "schema_version": "1.7.4"})
    d = os.path.join(ws.input_path, "osv-database", "BELL-CVE")
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write("# not an advisory")
    with open(os.path.join(d, "broken.json"), "w") as f:
        f.write("{not json")
    with open(os.path.join(d, "no-id.json"), "w") as f:
        json.dump({"schema_version": "1.7.4"}, f)
    results = list(parser.get())
    assert {r[0] for r in results} == {"BELL-CVE-2020-0006"}


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
