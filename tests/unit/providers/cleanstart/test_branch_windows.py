from __future__ import annotations

import pytest
from vunnel.providers.cleanstart.parser import (
    _has_gap,
    collect_branches,
    derive_branch_windows,
    normalize_record,
)


def affected(name: str, fixed: str, ecosystem: str = "CleanStart") -> dict:
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


def record(ident: str, *entries: dict) -> dict:
    return {"id": ident, "upstream": ["CVE-2025-46818"], "affected": list(entries)}


def events_for(rec: dict, name: str) -> list[list[dict]]:
    return [a["ranges"][0]["events"] for a in rec["affected"] if a["package"]["name"] == name]


class TestDeriveBranchWindows:
    def test_one_branch_per_fix(self):
        # the real redis shape: one CVE backported to four maintenance branches
        got = derive_branch_windows(["7.2.11-r0", "7.4.6-r0", "8.0.4-r0", "8.2.2-r0"])
        assert got == {
            # the lowest branch keeps "0" so anything below it still matches
            "7.2.11-r0": "0",
            "7.4.6-r0": "7.4.0",
            "8.0.4-r0": "8.0.0",
            "8.2.2-r0": "8.2.0",
        }

    def test_earliest_fix_wins_within_a_branch(self):
        # 8.0.5-r0 is redundant: 8.0.4-r0 already carries the patch on that branch
        got = derive_branch_windows(["7.4.6-r0", "8.0.4-r0", "8.0.5-r0"])
        assert got == {"7.4.6-r0": "0", "8.0.4-r0": "8.0.0"}
        assert "8.0.5-r0" not in got

    def test_revision_ordering_picks_r0_over_r1(self):
        got = derive_branch_windows(["1.2.3-r1", "1.2.3-r0", "2.0.0-r0"])
        assert got == {"1.2.3-r0": "0", "2.0.0-r0": "2.0.0"}

    def test_non_r_revision_does_not_crash(self):
        # the feed contains "2.5.4-1" (no "r"), which once mixed ints and strs
        # in the sort key and aborted the whole record
        got = derive_branch_windows(["2.5.4-1", "2.6.0-r0"])
        assert got == {"2.5.4-1": "0", "2.6.0-r0": "2.6.0"}

    @pytest.mark.parametrize("fixes", [["latest", "1.0.0-r0"], ["v1.2-r0"], ["", "1.0.0-r0"]])
    def test_unparseable_returns_none(self, fixes):
        # caller must leave the record exactly as the feed produced it
        assert derive_branch_windows(fixes) is None


class TestCollectBranches:
    def test_unions_branches_across_the_whole_feed(self):
        # no single advisory names every branch a package ships
        records = [
            record("A", affected("harbor-fips", "2.10.3-r0"), affected("harbor-fips", "2.13.2-r1")),
            record("B", affected("harbor-fips", "2.11.9-r0")),
            record("C", affected("redis", "8.0.4-r0")),
        ]
        got = collect_branches(records)
        assert got["harbor-fips"] == {(2, 10), (2, 11), (2, 13)}
        assert got["redis"] == {(8, 0)}

    def test_tolerates_junk(self):
        assert collect_branches([{}, {"affected": None}, {"affected": ["nope"]}]) == {}


class TestHasGap:
    def test_no_gap_when_every_branch_in_span_is_fixed(self):
        fixed = {(7, 2), (7, 4), (8, 0), (8, 2)}
        shipped = {(5, 0), (6, 2), (7, 0), (7, 2), (7, 4), (8, 0), (8, 2), (8, 10)}
        assert _has_gap(fixed, shipped) is False

    def test_gap_when_a_shipped_branch_inside_the_span_has_no_fix(self):
        # harbor-fips ships 2.11 but this advisory only fixes 2.10/2.12/2.13
        assert _has_gap({(2, 10), (2, 12), (2, 13)}, {(2, 10), (2, 11), (2, 12), (2, 13)}) is True

    def test_branch_below_the_span_is_not_a_gap(self):
        # covered by the lowest window, which keeps introduced "0"
        assert _has_gap({(7, 2), (7, 4)}, {(5, 0), (6, 2), (7, 2), (7, 4)}) is False

    def test_branch_above_the_span_is_not_a_gap(self):
        # 8.10 is newer than the highest fix; it was already unreported before
        assert _has_gap({(7, 2), (8, 2)}, {(7, 2), (8, 2), (8, 10)}) is False

    def test_nothing_known_means_no_gap(self):
        assert _has_gap({(1, 0), (2, 0)}, set()) is False


class TestNormalizeRecordBounding:
    def test_applies_when_the_branch_picture_is_complete(self):
        rec = record(
            "CLEANSTART-2026-CD34884",
            affected("redis", "7.2.11-r0"),
            affected("redis", "7.4.6-r0"),
            affected("redis", "8.0.4-r0"),
            affected("redis", "8.2.2-r0"),
        )
        known = {"redis": {(7, 2), (7, 4), (8, 0), (8, 2)}}

        got = normalize_record(rec, known)

        assert events_for(got, "redis") == [
            [{"introduced": "0"}, {"fixed": "7.2.11-r0"}],
            [{"introduced": "7.4.0"}, {"fixed": "7.4.6-r0"}],
            [{"introduced": "8.0.0"}, {"fixed": "8.0.4-r0"}],
            [{"introduced": "8.2.0"}, {"fixed": "8.2.2-r0"}],
        ]

    def test_skips_the_package_entirely_when_a_branch_is_unaccounted_for(self):
        rec = record(
            "CLEANSTART-2025-TT45966",
            affected("harbor-fips", "2.10.3-r0"),
            affected("harbor-fips", "2.12.4-r1"),
            affected("harbor-fips", "2.13.2-r1"),
        )
        # 2.11 is shipped but unfixed here, so 2.11.x must keep matching
        known = {"harbor-fips": {(2, 10), (2, 11), (2, 12), (2, 13)}}

        got = normalize_record(rec, known)

        assert events_for(got, "harbor-fips") == [
            [{"introduced": "0"}, {"fixed": "2.10.3-r0"}],
            [{"introduced": "0"}, {"fixed": "2.12.4-r1"}],
            [{"introduced": "0"}, {"fixed": "2.13.2-r1"}],
        ]

    def test_single_fix_is_left_alone(self):
        # "< fix" is already unambiguous with nothing to disambiguate against
        rec = record("CLEANSTART-2026-TM59792", affected("redis", "8.10.1-r0"))
        got = normalize_record(rec, {"redis": {(8, 10)}})
        assert events_for(got, "redis") == [[{"introduced": "0"}, {"fixed": "8.10.1-r0"}]]

    def test_superseded_entry_within_a_branch_is_dropped(self):
        rec = record(
            "CLEANSTART-2026-XX",
            affected("foo", "1.0.0-r0"),
            affected("foo", "2.0.0-r0"),
            affected("foo", "2.0.1-r0"),
        )
        got = normalize_record(rec, {"foo": {(1, 0), (2, 0)}})
        assert events_for(got, "foo") == [
            [{"introduced": "0"}, {"fixed": "1.0.0-r0"}],
            [{"introduced": "2.0.0"}, {"fixed": "2.0.0-r0"}],
        ]

    def test_each_package_is_judged_on_its_own(self):
        rec = record(
            "CLEANSTART-2026-YY",
            affected("safe", "1.0.0-r0"),
            affected("safe", "2.0.0-r0"),
            affected("gappy", "1.0.0-r0"),
            affected("gappy", "3.0.0-r0"),
        )
        known = {"safe": {(1, 0), (2, 0)}, "gappy": {(1, 0), (2, 0), (3, 0)}}

        got = normalize_record(rec, known)

        assert events_for(got, "safe") == [
            [{"introduced": "0"}, {"fixed": "1.0.0-r0"}],
            [{"introduced": "2.0.0"}, {"fixed": "2.0.0-r0"}],
        ]
        assert events_for(got, "gappy") == [
            [{"introduced": "0"}, {"fixed": "1.0.0-r0"}],
            [{"introduced": "0"}, {"fixed": "3.0.0-r0"}],
        ]

    def test_without_known_branches_nothing_is_rewritten(self):
        # the gap check cannot run, so the safe default is to change nothing
        rec = record("CLEANSTART-2026-ZZ", affected("redis", "7.4.6-r0"), affected("redis", "8.0.4-r0"))
        got = normalize_record(rec)
        assert events_for(got, "redis") == [
            [{"introduced": "0"}, {"fixed": "7.4.6-r0"}],
            [{"introduced": "0"}, {"fixed": "8.0.4-r0"}],
        ]

    def test_ecosystem_and_ids_are_still_normalized(self):
        rec = {
            "id": "CLEANSTART-2026-AA",
            "upstream": ["ghsa-hr2v-4r36-88hr"],
            "affected": [affected("redis", "8.0.4-r0", ecosystem="clnstrt")],
        }
        got = normalize_record(rec, {"redis": {(8, 0)}})
        assert got["upstream"] == ["GHSA-hr2v-4r36-88hr"]
        assert got["affected"][0]["package"]["ecosystem"] == "CleanStart"
