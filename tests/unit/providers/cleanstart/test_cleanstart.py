from __future__ import annotations

import json
import os

import pytest
from vunnel import schema, workspace
from vunnel.providers.cleanstart import SCHEMA, Config, Provider
from vunnel.providers.cleanstart.parser import (
    ADVISORIES_REPO,
    Parser,
    normalize_ecosystem,
    normalize_identifier,
    normalize_record,
)


def test_schema_covers_the_upstream_field():
    # CleanStart advisories declare 1.7.3 and carry their identifiers in
    # `upstream`, which OSV added in 1.7. The 1.6.1 default that OSVSchema()
    # returns predates that field and would misdeclare every record.
    assert SCHEMA.version == "1.7.3"
    assert SCHEMA.version != schema.OSVSchema().version


class TestNormalizeEcosystem:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("CleanStart", "CleanStart"),
            ("clnstrt", "CleanStart"),
            ("CLNSTRT", "CleanStart"),
            ("cleanstart", "CleanStart"),
            # a version suffix rides along untouched
            ("clnstrt:3.20", "CleanStart:3.20"),
            ("CleanStart:3.20", "CleanStart:3.20"),
            # other distros are left completely alone
            ("Alpine:3.20", "Alpine:3.20"),
            ("npm", "npm"),
            ("", ""),
        ],
    )
    def test_spellings(self, given, expected):
        assert normalize_ecosystem(given) == expected


class TestNormalizeIdentifier:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            # only the prefix is case-folded: a GHSA suffix is lower-case by
            # construction, so upper-casing the whole id would corrupt it
            ("ghsa-hr2v-4r36-88hr", "GHSA-hr2v-4r36-88hr"),
            ("GHSA-hr2v-4r36-88hr", "GHSA-hr2v-4r36-88hr"),
            ("cve-2026-1111", "CVE-2026-1111"),
            ("CVE-2026-1111", "CVE-2026-1111"),
            ("pysec-2024-48", "PYSEC-2024-48"),
            # unknown prefixes are not guessed at
            ("SOMETHING-else-1", "SOMETHING-else-1"),
            ("", ""),
        ],
    )
    def test_prefixes(self, given, expected):
        assert normalize_identifier(given) == expected


class TestNormalizeRecord:
    def test_real_advisory_shape(self):
        record = {
            "schema_version": "1.7.3",
            "id": "CLEANSTART-2026-AA09584",
            "affected": [
                {
                    "package": {"ecosystem": "CleanStart", "name": "linkerd2"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "26.1.4-r0"}]}],
                },
                {
                    "package": {"ecosystem": "clnstrt", "name": "linkerd2"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "26.4.2"}]}],
                },
            ],
            "upstream": ["ghsa-hr2v-4r36-88hr", "CVE-2026-1111"],
            "related": [],
        }

        got = normalize_record(record)

        assert [a["package"]["ecosystem"] for a in got["affected"]] == ["CleanStart", "CleanStart"]
        assert got["upstream"] == ["GHSA-hr2v-4r36-88hr", "CVE-2026-1111"]
        # ranges and everything else are untouched
        assert got["affected"][1]["ranges"][0]["events"][1]["fixed"] == "26.4.2"
        assert got["id"] == "CLEANSTART-2026-AA09584"

    def test_missing_and_odd_fields_are_tolerated(self):
        # the feed emits empty `related`/`credits` and occasionally omits keys;
        # normalization must not raise on any of it
        assert normalize_record({}) == {}
        assert normalize_record({"affected": None}) == {"affected": None}
        assert normalize_record({"affected": ["not-a-dict"]})["affected"] == ["not-a-dict"]
        assert normalize_record({"affected": [{}]})["affected"] == [{}]
        assert normalize_record({"upstream": "not-a-list"})["upstream"] == "not-a-list"
        assert normalize_record({"upstream": [None]})["upstream"] == [None]


class TestParser:
    def test_walks_nested_year_directories(self, tmp_path, monkeypatch):
        ws = workspace.Workspace(root=str(tmp_path), name="cleanstart", create=True)
        advisories = os.path.join(ws.input_path, "cleanstart-security-advisories", "advisories")

        for year, ident, eco in (("2025", "CLEANSTART-2025-AA00001", "clnstrt"), ("2026", "CLEANSTART-2026-BB00002", "CleanStart")):
            os.makedirs(os.path.join(advisories, year), exist_ok=True)
            with open(os.path.join(advisories, year, f"{ident}.json"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "id": ident,
                        "upstream": ["ghsa-hr2v-4r36-88hr"],
                        "affected": [{"package": {"ecosystem": eco, "name": "pkg"}}],
                    },
                    f,
                )

        # a malformed file must be skipped, not abort the run
        with open(os.path.join(advisories, "2026", "broken.json"), "w", encoding="utf-8") as f:
            f.write("{not json")

        parser = Parser(ws=ws)
        monkeypatch.setattr("subprocess.run", lambda *a, **kw: None)

        got = dict(parser.get())

        assert sorted(got) == ["CLEANSTART-2025-AA00001", "CLEANSTART-2026-BB00002"]
        for record in got.values():
            assert record["upstream"] == ["GHSA-hr2v-4r36-88hr"]
            assert record["affected"][0]["package"]["ecosystem"] == "CleanStart"


def test_provider_update_emits_each_record_under_the_pinned_schema(tmp_path, monkeypatch):
    provider = Provider(root=str(tmp_path), config=Config())

    records = [
        ("CLEANSTART-2026-AA09584", {"id": "CLEANSTART-2026-AA09584", "upstream": ["GHSA-hr2v-4r36-88hr"]}),
        ("CLEANSTART-2025-AA00001", {"id": "CLEANSTART-2025-AA00001", "upstream": ["CVE-2026-1111"]}),
    ]
    monkeypatch.setattr(provider.parser, "get", lambda: iter(records))

    written = []

    class RecordingWriter:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def write(self, identifier, schema, payload):
            written.append((identifier, schema, payload))

        def __len__(self):
            return len(written)

    monkeypatch.setattr(provider, "results_writer", RecordingWriter)

    urls, count = provider.update(None)

    assert count == 2
    assert urls == [ADVISORIES_REPO]
    assert [identifier for identifier, _, _ in written] == [r[0] for r in records]
    # every record must be declared under the version the feed declares
    assert {s.version for _, s, _ in written} == {"1.7.3"}
    assert [payload for _, _, payload in written] == [r[1] for r in records]
