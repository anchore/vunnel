"""Parser-level tests. End-to-end behavior lives in test_bellsoft.py."""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
from unittest.mock import Mock, patch

import jsonschema
import pytest
import requests

from vunnel import workspace
from vunnel.providers.bellsoft.parser import PINNED_OSV_SCHEMA_VERSION, Parser

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
PINNED_SCHEMA_PATH = os.path.join(
    REPO_ROOT, "schema", "vulnerability", "osv", f"schema-{PINNED_OSV_SCHEMA_VERSION}.json",
)

V2_BARE = {"type": "CVSS_V2", "score": "AV:L/AC:H/Au:N/C:C/I:C/A:C"}
V3 = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _write_members(input_path: str, members: dict[str, bytes]) -> None:
    os.makedirs(input_path, exist_ok=True)
    with open(os.path.join(input_path, Parser._archive_name_), "wb") as fh:
        fh.write(_tar_bytes(members))


def _advisories(input_path: str, records: list[dict], top_dir: str = "osv-database-master", sub_dir: str = "BELL-CVE") -> None:
    prefix = f"{top_dir}/" if top_dir else ""
    _write_members(
        input_path,
        {f"{prefix}{sub_dir}/{r['id']}.json": json.dumps(r).encode() for r in records},
    )


@pytest.fixture()
def ws(tmp_path):
    return workspace.Workspace(str(tmp_path), "bellsoft", create=True)


@pytest.fixture()
def parser(ws, auto_fake_fixdate_finder):
    with patch.object(Parser, "_download"):
        yield Parser(ws=ws)


@pytest.fixture(scope="module")
def osv_validator():
    with open(PINNED_SCHEMA_PATH) as fh:
        return jsonschema.Draft7Validator(json.load(fh))


# ---------------------------------------------------------------------------
# _download()
# ---------------------------------------------------------------------------


def test_download_writes_archive(ws, auto_fake_fixdate_finder):
    payload = json.dumps({"id": "BELL-CVE-2020-0009", "schema_version": "1.7.4"}).encode()
    blob = _tar_bytes({"osv-database-master/BELL-CVE/BELL-CVE-2020-0009.json": payload})

    response = Mock()
    response.iter_content = lambda chunk_size: iter([blob])
    with patch("vunnel.providers.bellsoft.parser.http.get", return_value=response) as mock_get:
        parser = Parser(ws=ws)
        parser._download()

    assert mock_get.call_args.kwargs["timeout"] == 125
    assert os.path.exists(os.path.join(ws.input_path, Parser._archive_name_))
    assert next(parser._load())["id"] == "BELL-CVE-2020-0009"


def test_download_propagates_a_mid_stream_failure(ws, auto_fake_fixdate_finder):
    def iter_content(chunk_size):
        yield b"partial"
        raise requests.exceptions.ChunkedEncodingError("connection broken")

    response = Mock()
    response.iter_content = iter_content
    with patch("vunnel.providers.bellsoft.parser.http.get", return_value=response):
        with pytest.raises(requests.exceptions.ChunkedEncodingError):
            Parser(ws=ws)._download()


def test_download_propagates_a_request_failure(ws, auto_fake_fixdate_finder):
    with patch(
        "vunnel.providers.bellsoft.parser.http.get",
        side_effect=requests.exceptions.ConnectionError("unreachable"),
    ):
        with pytest.raises(requests.exceptions.ConnectionError):
            Parser(ws=ws)._download()


# ---------------------------------------------------------------------------
# _load()
# ---------------------------------------------------------------------------


class TestLoad:
    def test_no_archive_raises(self, parser):
        with pytest.raises(FileNotFoundError):
            list(parser._load())

    def test_handles_flat_archive_layout(self, parser, ws):
        _advisories(str(ws.input_path), [{"id": "BELL-CVE-2020-0008", "schema_version": "1.7.4"}], top_dir="")
        assert [r["id"] for r in parser._load()] == ["BELL-CVE-2020-0008"]

    def test_non_advisory_members_are_skipped(self, parser, ws):
        _write_members(
            str(ws.input_path),
            {
                "osv-database-master/BELL-CVE/README.md": b"# not an advisory",
                "osv-database-master/LICENSE": b"outside the advisory dir",
                "osv-database-master/BELL-CVE/BELL-CVE-2020-0006.json": json.dumps(
                    {"id": "BELL-CVE-2020-0006", "schema_version": "1.7.4"},
                ).encode(),
            },
        )
        assert [r["id"] for r in parser._load()] == ["BELL-CVE-2020-0006"]

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(b"{not json", id="syntax-error"),
            pytest.param(b"", id="empty-file"),
            pytest.param(b"\xff\xfe\x00\x00", id="invalid-utf8"),
            pytest.param(b'{"id": "\xed\xa0\x80"}', id="surrogate"),
        ],
    )
    def test_all_decode_failures_are_caught(self, parser, ws, payload):
        """orjson raises JSONDecodeError for every malformed-input shape, including invalid UTF-8."""
        _write_members(
            str(ws.input_path),
            {
                "osv-database-master/BELL-CVE/bad.json": payload,
                "osv-database-master/BELL-CVE/BELL-CVE-2020-0001.json": json.dumps(
                    {"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4"},
                ).encode(),
            },
        )
        assert [r["id"] for r in parser._load()] == ["BELL-CVE-2020-0001"]

    def test_streams_many_members_without_corruption(self, parser, ws):
        """extractfile() during iteration stays correct because "r:gz" opens a seekable archive."""
        count = 500
        members = {
            f"osv-database-master/BELL-CVE/BELL-CVE-2020-{i:05d}.json": json.dumps(
                {"id": f"BELL-CVE-2020-{i:05d}", "schema_version": "1.7.4", "summary": "x" * (i % 97)},
            ).encode()
            for i in range(count)
        }
        members["osv-database-master/LICENSE"] = b"license"
        members["osv-database-master/README.md"] = b"readme"
        _write_members(str(ws.input_path), members)

        loaded = list(parser._load())
        assert len(loaded) == count
        assert {r["id"] for r in loaded} == {f"BELL-CVE-2020-{i:05d}" for i in range(count)}
        assert all(len(r["summary"]) == int(r["id"].split("-")[-1]) % 97 for r in loaded)

    def test_truncated_archive_raises_rather_than_yielding_a_silent_subset(self, parser, ws):
        members = {
            f"osv-database-master/BELL-CVE/BELL-CVE-2020-{i:05d}.json": json.dumps(
                {"id": f"BELL-CVE-2020-{i:05d}", "schema_version": "1.7.4", "summary": "x" * 500},
            ).encode()
            for i in range(400)
        }
        blob = _tar_bytes(members)
        os.makedirs(ws.input_path, exist_ok=True)
        with open(os.path.join(ws.input_path, Parser._archive_name_), "wb") as fh:
            fh.write(blob[: len(blob) // 2])

        with pytest.raises((EOFError, tarfile.TarError, OSError)):
            list(parser._load())

    def test_nested_bell_cve_path_component_is_matched(self, parser, ws):
        _advisories(
            str(ws.input_path),
            [{"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4"}],
            top_dir="osv-database-master/some/deep",
        )
        assert [r["id"] for r in parser._load()] == ["BELL-CVE-2020-0001"]

    def test_unrelated_file_under_a_bell_cve_component_is_loaded(self, parser, ws):
        """The filter matches a path component at any depth. It is not anchored to the repo root."""
        _write_members(
            str(ws.input_path),
            {"osv-database-master/tools/BELL-CVE/testdata/fixture.json": json.dumps({"id": "NOT-AN-ADVISORY"}).encode()},
        )
        assert [r["id"] for r in parser._load()] == ["NOT-AN-ADVISORY"]


# ---------------------------------------------------------------------------
# _normalize_severities()
# ---------------------------------------------------------------------------


class TestNormalizeSeverities:
    def test_leaves_bare_cvss_v2_untouched(self, parser):
        entry = {"id": "BELL-CVE-2000-0344", "severity": [{"score": "AV:N/AC:L/Au:N/C:N/I:N/A:P", "type": "CVSS_V2"}]}

        result = parser._normalize_severities(entry)

        assert result["severity"][0]["score"] == "AV:N/AC:L/Au:N/C:N/I:N/A:P"
        assert result["severity"][0]["type"] == "CVSS_V2"

    def test_normalizes_cvss_v3_without_prefix(self, parser):
        entry = {"id": "X", "severity": [{"score": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "type": "CVSS_V3"}]}

        result = parser._normalize_severities(entry)

        assert result["severity"][0]["score"] == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_preserves_cvss_v3_with_version(self, parser):
        entry = {"id": "X", "severity": [{"score": V3["score"], "type": "CVSS_V3"}]}

        assert parser._normalize_severities(entry)["severity"][0]["score"] == V3["score"]

    def test_normalizes_cvss_v4_without_prefix(self, parser):
        bare = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"
        entry = {"id": "X", "severity": [{"score": bare, "type": "CVSS_V4"}]}

        assert parser._normalize_severities(entry)["severity"][0]["score"] == f"CVSS:4.0/{bare}"

    def test_handles_multiple_severities(self, parser):
        entry = {
            "id": "X",
            "severity": [
                {"score": "AV:N/AC:L/Au:N/C:N/I:N/A:P", "type": "CVSS_V2"},
                {"score": V3["score"], "type": "CVSS_V3"},
            ],
        }

        result = parser._normalize_severities(entry)

        assert [s["score"] for s in result["severity"]] == ["AV:N/AC:L/Au:N/C:N/I:N/A:P", V3["score"]]

    def test_handles_empty_severity_list(self, parser):
        assert parser._normalize_severities({"id": "X", "severity": []})["severity"] == []

    def test_handles_missing_severity_key(self, parser):
        assert "severity" not in parser._normalize_severities({"id": "X"})

    def test_handles_empty_score(self, parser):
        entry = {"id": "X", "severity": [{"score": "", "type": "CVSS_V2"}]}

        assert parser._normalize_severities(entry)["severity"][0]["score"] == ""

    def test_preserves_other_fields(self, parser):
        entry = {
            "id": "BELL-CVE-2020-1234",
            "summary": "Test vulnerability",
            "references": [{"url": "https://example.com"}],
            "severity": [{"score": "AV:N/AC:L/Au:N/C:N/I:N/A:P", "type": "CVSS_V2"}],
        }

        result = parser._normalize_severities(entry)

        assert result["id"] == "BELL-CVE-2020-1234"
        assert result["summary"] == "Test vulnerability"
        assert result["references"] == [{"url": "https://example.com"}]

    def test_does_not_mutate_original(self, parser):
        original = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        entry = {"id": "X", "severity": [{"score": original, "type": "CVSS_V3"}]}

        parser._normalize_severities(entry)

        assert entry["severity"][0]["score"] == original

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            pytest.param([{"type": "CVSS_V3"}], [{"type": "CVSS_V3"}], id="missing-score"),
            pytest.param([{"type": "CVSS_V3", "score": None}], [{"type": "CVSS_V3", "score": None}], id="null-score"),
            pytest.param([{"score": "AV:N/AC:L"}], [{"score": "AV:N/AC:L"}], id="missing-type-left-unprefixed"),
            pytest.param([{"type": "Ubuntu", "score": "low"}], [{"type": "Ubuntu", "score": "low"}], id="unknown-type"),
            pytest.param([{"type": "CVSS_V3.1", "score": "AV:N"}], [{"type": "CVSS_V3.1", "score": "AV:N"}], id="unmapped-type"),
            pytest.param({"type": "CVSS_V2", "score": "AV:N"}, {"type": "CVSS_V2", "score": "AV:N"}, id="severity-is-a-dict-not-a-list"),
            pytest.param(["CVSS_V2"], ["CVSS_V2"], id="severity-is-a-list-of-strings"),
            pytest.param([{"type": "CVSS_V3", "score": 7.5}], [{"type": "CVSS_V3", "score": 7.5}], id="score-is-a-number"),
        ],
    )
    def test_structurally_odd_severity_is_left_as_found(self, parser, severity, expected):
        assert parser._normalize_severities({"id": "X", "severity": severity})["severity"] == expected

    @pytest.mark.parametrize(
        "score",
        [
            pytest.param("cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="lowercase-prefix"),
            pytest.param(" CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="leading-space"),
        ],
    )
    def test_odd_prefix_is_canonicalized_not_double_prefixed(self, parser, score):
        entry = {"id": "X", "severity": [{"type": "CVSS_V3", "score": score}]}

        assert parser._normalize_severities(entry)["severity"][0]["score"] == V3["score"]


# ---------------------------------------------------------------------------
# _normalize()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "expected_version"),
    [
        pytest.param({"id": "X"}, PINNED_OSV_SCHEMA_VERSION, id="missing-key-uses-pinned-version"),
        pytest.param({"id": "X", "schema_version": "1.7.4"}, "1.7.4", id="present"),
        pytest.param({"id": "X", "schema_version": ""}, "", id="empty-string-passes-through"),
    ],
)
def test_normalize_schema_version(parser, entry, expected_version):
    _, version, _ = parser._normalize(entry)
    assert version == expected_version


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


class TestGet:
    def test_yields_each_record_once(self, parser, ws):
        _advisories(str(ws.input_path), [{"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4", "severity": [V3]}])
        assert len(list(parser.get())) == 1

    def test_withdrawn_record_is_skipped(self, parser, ws):
        _advisories(
            str(ws.input_path),
            [{"id": "BELL-CVE-2020-0005", "schema_version": "1.7.4", "withdrawn": "2024-01-01T00:00:00Z"}],
        )
        assert list(parser.get()) == []

    def test_withdrawn_entries_are_summarized_not_logged_per_record(self, parser, ws, caplog):
        _advisories(
            str(ws.input_path),
            [
                {"id": f"BELL-CVE-2020-{i:04d}", "schema_version": "1.7.4", "withdrawn": "2024-01-01T00:00:00Z"}
                for i in range(5)
            ]
            + [{"id": "BELL-CVE-2020-9999", "schema_version": "1.7.4"}],
        )
        with caplog.at_level(logging.DEBUG):
            assert [r[0] for r in parser.get()] == ["BELL-CVE-2020-9999"]

        assert not [m for m in caplog.messages if "BELL-CVE-2020-0000" in m]
        assert "skipped 5 withdrawn advisories" in caplog.messages

    def test_no_withdrawn_summary_when_there_are_none(self, parser, ws, caplog):
        _advisories(str(ws.input_path), [{"id": "BELL-CVE-2020-9999", "schema_version": "1.7.4"}])
        with caplog.at_level(logging.DEBUG):
            list(parser.get())

        assert not [m for m in caplog.messages if "withdrawn" in m]

    def test_record_without_an_id_is_skipped(self, parser, ws):
        _write_members(
            str(ws.input_path),
            {
                "osv-database-master/BELL-CVE/no-id.json": json.dumps({"schema_version": "1.7.4"}).encode(),
                "osv-database-master/BELL-CVE/BELL-CVE-2020-0006.json": json.dumps(
                    {"id": "BELL-CVE-2020-0006", "schema_version": "1.7.4"},
                ).encode(),
            },
        )
        assert [r[0] for r in parser.get()] == ["BELL-CVE-2020-0006"]

    def test_top_level_list_is_skipped_not_fatal(self, parser, ws):
        _write_members(
            str(ws.input_path),
            {
                "osv-database-master/BELL-CVE/list.json": b'[{"id": "BELL-CVE-2020-9999"}]',
                "osv-database-master/BELL-CVE/scalar.json": b'"a string"',
                "osv-database-master/BELL-CVE/null.json": b"null",
                "osv-database-master/BELL-CVE/BELL-CVE-2020-0001.json": json.dumps(
                    {"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4"},
                ).encode(),
            },
        )
        assert [r[0] for r in parser.get()] == ["BELL-CVE-2020-0001"]

    @pytest.mark.parametrize(
        "vuln_id",
        [
            pytest.param(123, id="number"),
            pytest.param("", id="empty"),
            pytest.param("CVE-2020-0001", id="not-a-bell-id"),
            pytest.param("BELL-CVE-2020-0001/../../x", id="path-separator"),
        ],
    )
    def test_record_with_an_invalid_id_is_skipped(self, parser, ws, vuln_id):
        _write_members(
            str(ws.input_path),
            {
                "osv-database-master/BELL-CVE/bad.json": json.dumps({"id": vuln_id, "schema_version": "1.7.4"}).encode(),
                "osv-database-master/BELL-CVE/BELL-CVE-2020-0006.json": json.dumps(
                    {"id": "BELL-CVE-2020-0006", "schema_version": "1.7.4"},
                ).encode(),
            },
        )
        assert [r[0] for r in parser.get()] == ["BELL-CVE-2020-0006"]

    def test_ids_that_collide_when_lowercased_yield_only_the_first(self, parser, ws):
        # update() lowercases ids into result identifiers.
        _advisories(
            str(ws.input_path),
            [
                {"id": "BELL-CVE-2020-0001", "schema_version": "1.7.4"},
                {"id": "BELL-cve-2020-0001", "schema_version": "1.7.4"},
            ],
        )
        assert [r[0] for r in parser.get()] == ["BELL-CVE-2020-0001"]

    @pytest.mark.parametrize(
        "affected",
        [
            pytest.param(None, id="affected-null"),
            pytest.param([{"package": None}], id="package-null"),
            pytest.param([{"package": {"name": "glibc", "ecosystem": "Alpaquita:23"}, "ranges": None}], id="ranges-null"),
        ],
    )
    def test_odd_affected_shape_is_skipped_not_fatal(self, parser, ws, caplog, affected):
        _advisories(
            str(ws.input_path),
            [
                {"id": "BELL-CVE-2020-0002", "schema_version": "1.7.4", "affected": affected},
                {"id": "BELL-CVE-2020-0003", "schema_version": "1.7.4"},
            ],
        )
        with caplog.at_level(logging.WARNING):
            assert [r[0] for r in parser.get()] == ["BELL-CVE-2020-0003"]

        assert any("skipping malformed advisory BELL-CVE-2020-0002" in m for m in caplog.messages)

    def test_fix_dates_are_patched_onto_ranges(self, parser, ws):
        # auto_fake_fixdate_finder reports 2024-01-01 for every fix.
        _advisories(
            str(ws.input_path),
            [{
                "id": "BELL-CVE-2020-0007",
                "schema_version": "1.7.4",
                "affected": [{
                    "package": {"ecosystem": "Alpaquita:stream", "name": "expat"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.7.2-r0"}]}],
                }],
            }],
        )
        results = list(parser.get())

        assert len(results) == 1
        fixes = results[0][2]["affected"][0]["ranges"][0]["database_specific"]["anchore"]["fixes"]
        assert fixes[0]["version"] == "2.7.2-r0"
        assert fixes[0]["date"] == "2024-01-01"
        assert fixes[0]["kind"] == "first-observed"


class TestYieldedRecordsAreSchemaValid:
    def _only(self, parser, record):
        _advisories(str(parser.workspace.input_path), [record])
        return next(iter(parser.get()))[2]

    def test_minimal_record(self, parser, osv_validator):
        record = self._only(parser, {"id": "BELL-CVE-2010-4478", "modified": "2024-01-01T00:00:00Z"})
        assert list(osv_validator.iter_errors(record)) == []

    def test_alpaquita_ecosystem_requires_the_pinned_schema(self, parser, osv_validator):
        """The Alpaquita ecosystem value does not exist in the schema 1.7.0 enum."""
        record = self._only(parser, {
            "id": "BELL-CVE-2010-4478",
            "modified": "2024-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": "Alpaquita", "name": "expat"}}],
        })
        assert list(osv_validator.iter_errors(record)) == []

        older = os.path.join(REPO_ROOT, "schema", "vulnerability", "osv", "schema-1.7.0.json")
        with open(older) as fh:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.Draft7Validator(json.load(fh)).validate(record)

    def test_cvss_v3_is_prefixed_and_stays_valid(self, parser, osv_validator):
        record = self._only(parser, {
            "id": "BELL-CVE-2010-4478",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        })
        assert record["severity"][0]["score"].startswith("CVSS:3.0/")
        assert list(osv_validator.iter_errors(record)) == []

    def test_cvss_v2_is_left_bare_and_stays_valid(self, parser, osv_validator):
        """Upstream ships live records with bare V2 scores, such as BELL-CVE-2008-5135."""
        record = self._only(parser, {
            "id": "BELL-CVE-2008-5135",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [V2_BARE],
        })
        assert record["severity"][0]["score"] == V2_BARE["score"]
        assert list(osv_validator.iter_errors(record)) == []

    def test_v2_and_v3_together(self, parser, osv_validator):
        """Some upstream records carry both a CVSS_V2 and a CVSS_V3 score."""
        record = self._only(parser, {
            "id": "BELL-CVE-2010-4478",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [V2_BARE, V3],
        })
        assert [s["score"] for s in record["severity"]] == [V2_BARE["score"], V3["score"]]
        assert list(osv_validator.iter_errors(record)) == []
