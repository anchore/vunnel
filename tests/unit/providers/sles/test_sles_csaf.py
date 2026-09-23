from __future__ import annotations

import logging
import os
import tarfile

import pytest

from vunnel import result
from vunnel.providers.sles import Config, Provider
from vunnel.providers.sles.csaf_advisory_client import AdvisoryDates
from vunnel.providers.sles.csaf_parser import FixDates, _ProductBuilds, _resolve_orphan_binaries, downconvert
from vunnel.tool.fixdate.finder import Finder
from vunnel.utils.csaf_types import from_path
from vunnel.utils.vulnerability import FixedIn, VendorAdvisory


class _NoFirstObserved:
    """A first-observed store that knows nothing, so a FixDates built for these tests
    resolves dates only from the advisory index it was handed."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def download(self):
        return None

    def find(self, *args, **kwargs):
        return []

# Real SUSE CSAF VEX documents, subsetted down to plain + LTSS SLES 15.x via
# subset_for_sles() (never hand-authored) -- see the inline comment on each entry
# for what it demonstrates.
FIXTURE_CVES = [
    "cve-2010-1323",  # many packages, one fixed version, on sles:15 (also covered by the OVAL-path snapshot)
    "cve-2004-2771",  # single package fixed, on sles:15.1
    "cve-2004-0657",  # known_not_affected -> "fixed at version 0" convention
    "cve-2019-8608",  # plain fixed, LTSS never fixed -- proves the plain/+ltss split
    "cve-2023-47627",  # explicit no_fix_planned won't-fix disposition
    # withdrawn CVEs -- both of MITRE's rejection wordings. Deliberately part of the
    # snapshot pipeline: they carry real affected/fixed SLES data, so the assertion
    # worth making end to end is that the archive contains them and the output has no
    # snapshot file for either.
    "cve-2023-45918",
    "cve-2022-46283",
]

# Real, subsetted CVEs used only in standalone TestDownconvert cases below, not in the
# provider-level snapshot pipeline: most are SLES 11/12 data, which the snapshot tests'
# allow_versions=["15"] scope excludes anyway, and the 15.x ones carry enough platforms
# and advisory references that snapshotting them would bury the behavior these cases
# assert directly.
_LTSS_ONLY_FIX_CVE = "cve-2022-1271"  # liblzma5 fixed ONLY under -LTSS -- proves the LTSS->plain fix-borrowing rule
_LTSS_SPACE_SPELLING_CVE = "cve-2018-16881"  # platform spelled "...11 SP1 LTSS" (space, no hyphen)
_UNASSESSED_WONT_FIX_CVE = "cve-2002-20001"  # no_fix_planned swept onto packages never asserted known_affected
_AFFECTED_NO_FIX_CVE = "cve-2022-24735"  # redis known_affected with no fix on 15.2, really fixed on 15.3/15.4/15.5
_SOURCE_NAMED_AFFECTED_CVE = "cve-2015-3217"  # source `pcre` known_affected alongside a real fix for its binaries
_MANGLED_PURL_SOURCE_CVE = "cve-2018-4197"  # same, but the source entry's own purl carries no upstream= qualifier
# SLES 15 SP1's fix list covers 9 of the 11 openldap2 binaries known_affected there; SP2's
# covers all 11 at the identical build. Both orphan-binary remedies in one document.
_ORPHAN_BINARY_CVE = "cve-2019-13057"
_LTSS_FIX_VS_PLAIN_AFFECTED_CVE = "cve-2017-6004"  # plain known_affected for libpcre1, fixed only on -LTSS/-ESPOS
_LTSS_FIX_VS_PLAIN_NOT_AFFECTED_CVE = "cve-2019-19966"  # plain known_not_affected for the kernel, real fix on -LTSS
_REJECTED_CANDIDATE_CVE = "cve-2023-45918"  # withdrawn: MITRE's "DO NOT USE THIS CANDIDATE NUMBER" wording
_REJECTED_CNA_WORDING_CVE = "cve-2022-46283"  # withdrawn: the modern "rejected or withdrawn by its CNA" wording
_MULTI_RECOMMENDED_CVE = "cve-2018-4197"  # `recommended` names one package twice, at different versions
# `recommended` (a pre-fix GA build) disagrees with `first_fixed`, and no advisory ever
# shipped the `recommended` build for this CVE -- the attestation fallback's own case.
_UNATTESTED_RECOMMENDED_CVE = "cve-2025-38250"


def _build_test_advisory_archive(fixture_dir: str, archive_path: str) -> None:
    """Build a csaf.tar.bz2-shaped advisory archive from the committed, subsetted
    fixtures, so SLESCSAFAdvisoryClient's real streaming/indexing path runs too.

    Only CVE-2023-47627 has a matching advisory here, which is representative: real
    coverage is ~58%, so most fixes fall back to the finder's first-observed date.
    """
    with tarfile.open(archive_path, mode="w:bz2") as tar:
        for name in sorted(os.listdir(fixture_dir)):
            if name.endswith(".json"):
                tar.add(os.path.join(fixture_dir, name), arcname=f"csaf/{name}")


def _build_test_archive(fixture_dir: str, archive_path: str) -> None:
    """Build a csaf-vex.tar.bz2-shaped archive from the committed, subsetted JSON
    fixtures, so SLESCSAFClient's real streaming tarfile-reading code path is
    exercised end to end rather than bypassed."""
    with tarfile.open(archive_path, mode="w:bz2") as tar:
        for cve in FIXTURE_CVES:
            src = os.path.join(fixture_dir, f"{cve}.json")
            tar.add(src, arcname=f"csaf-vex/{cve}.json")


@pytest.fixture
def fixture_dir(helpers):
    return helpers.local_dir("test-fixtures/csaf")


class TestDownconvert:
    """Direct assertions against the downconvert transform, using real (subsetted)
    CSAF VEX documents -- covers the behaviors that can't be exercised by the OVAL
    feed at all: the plain/+ltss split and the won't-fix disposition."""

    def test_fixed_package(self, fixture_dir):
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}
        fixed = {f.Name: f.Version for f in results["sles:15.1"].FixedIn}
        assert fixed == {"mailx": "0:12.5-1.87"}

    def test_not_affected_package(self, fixture_dir):
        doc = from_path(os.path.join(fixture_dir, "cve-2004-0657.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}
        fixed_in = results["sles:15.1"].FixedIn[0]
        assert fixed_in.Name == "ntp"
        assert fixed_in.Version == "0"
        # VendorAdvisory=None passed in becomes the "no advisory data" default via
        # FixedIn.__post_init__, matching the OVAL-path not-affected convention.
        assert fixed_in.VendorAdvisory == VendorAdvisory(NoAdvisory=False, AdvisorySummary=[])

    def test_plain_and_ltss_tracked_separately(self, fixture_dir):
        """libwebkit2gtk-4_0-37 was fixed on plain SLES 15 SP1, while SP1-LTSS is listed
        known_affected with no fix -- real, confirmed data (see the LTSS exploration
        notes). Each track must carry its own answer: plain the real fix, LTSS the
        "vulnerable, no fix" record, rather than one being folded into the other.

        LTSS specifically must NOT be silently dropped: SUSE names nine affected
        packages there, and emitting nothing for them would leave a scanner reporting
        no findings for a package the vendor confirmed as vulnerable."""
        doc = from_path(os.path.join(fixture_dir, "cve-2019-8608.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        assert "sles:15.1" in results
        plain_fixed = {f.Name: f.Version for f in results["sles:15.1"].FixedIn}
        assert plain_fixed["libwebkit2gtk-4_0-37"] == "0:2.24.2-3.27.1"

        ltss_fixed = {f.Name: f for f in results["sles:15.1+ltss"].FixedIn}
        assert ltss_fixed["libwebkit2gtk-4_0-37"].Version == "None"
        assert ltss_fixed["libwebkit2gtk-4_0-37"].VendorAdvisory.NoAdvisory is False
        # the LTSS "None" must not leak into plain, which has a real fix for it
        assert plain_fixed["libwebkit2gtk-4_0-37"] != "None"

    def test_wont_fix_disposition(self, fixture_dir):
        """CSAF's explicit no_fix_planned remediation has no OVAL equivalent; honor it
        with vunnel's existing won't-fix convention (Version="None", NoAdvisory=True)."""
        doc = from_path(os.path.join(fixture_dir, "cve-2023-47627.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        fixed = {f.Name: f for f in results["sles:15.4"].FixedIn}
        assert fixed["python-aiohttp"].Version == "None"
        assert fixed["python-aiohttp"].VendorAdvisory.NoAdvisory is True

        # a real fix elsewhere in the same CVE/doc is unaffected by the won't-fix
        # entries for other packages.
        fixed_15_6 = {f.Name: f.Version for f in results["sles:15.6"].FixedIn}
        assert fixed_15_6 == {"python311-aiohttp": "0:3.9.3-150400.10.14.1"}

        # python3-aiohttp is swept into the same no_fix_planned remediation block as
        # python-aiohttp/python311-aiohttp, but (unlike them) was never independently
        # asserted known_affected in product_status for sles:15.4 -- so no won't-fix
        # record should be emitted for it at all (see test_wont_fix_requires_known_affected
        # below for the CVE that made this distinction matter).
        assert "python3-aiohttp" not in fixed

    def test_known_affected_with_no_fix_is_reported(self, fixture_dir):
        """known_affected means SUSE says the package IS vulnerable. With no fix
        published, that is vunnel's Version="None" case ("vulnerable, no fix available
        yet" -- see FixedIn's docstring), exactly as ubuntu/os_downconvert.py maps
        "no fixed event, no wont-fix". Dropping it means a scanner silently reports
        nothing for a package the vendor has confirmed as affected.

        CVE-2022-24735's real data says redis is known_affected on SLES 15 SP2 (plain
        and LTSS) with no fix anywhere for that SP, while 15.3/15.4/15.5 have real
        recommended fixes -- so one document covers both the emit and the rule that a
        real fix still outranks it.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_AFFECTED_NO_FIX_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        for ns in ("sles:15.2", "sles:15.2+ltss"):
            fixed = {f.Name: f for f in results[ns].FixedIn}
            assert fixed["redis"].Version == "None", f"{ns}: known_affected must be reported as vulnerable"
            # no no_fix_planned remediation covers these, so this is "no fix yet",
            # not a declared won't-fix
            assert fixed["redis"].VendorAdvisory.NoAdvisory is False

        # a real fix outranks the affected-with-no-fix assertion for the same package
        assert {f.Name: f.Version for f in results["sles:15.3"].FixedIn} == {"redis": "0:6.0.14-150200.6.11.1"}
        assert {f.Name: f.Version for f in results["sles:15.4"].FixedIn} == {"redis": "0:6.2.6-150400.3.3.7"}

    def test_source_named_affected_is_dropped_when_its_binaries_are_fixed(self, fixture_dir):
        """SUSE names the *source* package in known_affected alongside the binaries it
        builds, and keeps doing so even after publishing a fix for those binaries.

        CVE-2015-3217 on plain SLES 12 SP4 is the real case: `recommended` lists
        libpcre1-8.39-8.3.1 and eight sibling binaries, while known_affected lists
        `pcre` -- the source RPM all nine are built from -- plus most of those same
        binaries. The per-binary contradictions are already masked by the fix-first
        precedence rule, but `pcre` has no same-named fix to mask it, so it survived as
        Version="None".

        That record is a false positive with a wide blast radius: `pcre` is not a
        shipped binary on SLES 12 at all (no version-bearing `...12*:pcre-<version>`
        product exists anywhere in the 64k-document corpus), so nothing can match it
        directly -- but grype resolves an installed binary to its source RPM and
        searches under that name too. An installed libpcre1-8.45-8.7.1, comfortably
        above the 8.39-8.3.1 fix, matched `pcre` -> "None" and got reported NOT-FIXED.
        A "None" record under a source name over-matches *every* binary that source
        builds, at *every* version, because "None" carries no version to compare.

        SUSE's own page shows the same contradiction -- the patch table says
        "libpcre1 >= 8.39-8.3.1" for 12 SP4 while the state table (rendered at source
        granularity) says "pcre | Affected" -- and `recommended` is the authoritative
        half. So when a fix exists for a source package's binaries in a namespace, a
        bare known_affected entry naming that source package is stale, and asserting
        "vulnerable at every version" from it is wrong.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_SOURCE_NAMED_AFFECTED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        plain = {f.Name: f.Version for f in results["sles:12.4"].FixedIn}

        # the source package's binaries keep their real fix...
        assert plain["libpcre1"] == "0:8.39-8.3.1"
        assert plain["libpcre16-0"] == "0:8.39-8.3.1"
        assert plain["pcre-devel"] == "0:8.39-8.3.1"
        # ...and the stale source-named record is gone entirely, rather than being
        # emitted as "vulnerable at every version".
        assert "pcre" not in plain

    def test_source_named_affected_dropped_when_its_own_purl_lacks_upstream(self, fixture_dir):
        """The rule has to read the source name off the *fixed* products, not off the
        affected record's own purl.

        SUSE's generator mangles version-less purls (README: "Version-less IDs take
        their package name from product_reference, not the purl"), and for
        CVE-2018-4197 it drops the qualifier altogether: the version-less `webkit2gtk3`
        branch is `pkg:rpm/suse/webkit2gtk3@` -- no version, no `upstream=`. There is
        nothing on that record saying it is a source package.

        The fixed products spell it out instead: libwebkit2gtk-4_0-37-2.22.4-2.29.3
        carries `upstream=webkit2gtk3-2.22.4-2.29.3.src.rpm`. Keying the rule off that
        side is what makes it fire here -- and webkit2gtk3 is the single largest
        contributor to this false-positive class corpus-wide, so a purl-derived
        implementation would miss most of the problem.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_MANGLED_PURL_SOURCE_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        plain = {f.Name: f.Version for f in results["sles:12.4"].FixedIn}
        assert plain["libwebkit2gtk-4_0-37"] == "0:2.22.4-2.29.3"
        assert plain["webkit2gtk-4_0-injected-bundles"] == "0:2.22.4-2.29.3"
        assert "webkit2gtk3" not in plain

    def test_declared_wont_fix_survives_a_fix_for_its_siblings(self, fixture_dir):
        """The other boundary of the source-named drop: a *declared* won't-fix is never
        retired by it.

        The drop rests on the claim that SUSE left a stale line standing. A
        `no_fix_planned` remediation naming the exact product is the opposite -- a
        deliberate statement -- and it is how SUSE says "this flavor stays vulnerable,
        use the other one".

        CVE-2023-47627 is that case: on SLES 15 SP4 `python-aiohttp` is declared
        won't-fix while `python311-aiohttp`, built from the same `python-aiohttp` source
        RPM, is fixed at 3.9.3-150400.10.14.1. Retiring the won't-fix record because a
        sibling binary got fixed would drop a real, vendor-confirmed exposure -- so the
        drop only ever applies to the passive known_affected case (`NoAdvisory=False`),
        never to `NoAdvisory=True`.
        """
        doc = from_path(os.path.join(fixture_dir, "cve-2023-47627.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        fixed = {f.Name: f for f in results["sles:15.4"].FixedIn}
        # a sibling binary from the same source RPM really is fixed here...
        assert fixed["python311-aiohttp"].Version == "0:3.9.3-150400.10.14.1"
        # ...and that must not retire the declared won't-fix for python-aiohttp
        assert fixed["python-aiohttp"].Version == "None"
        assert fixed["python-aiohttp"].VendorAdvisory.NoAdvisory is True

    def test_source_named_affected_is_kept_when_that_namespace_has_no_fix(self, fixture_dir):
        """The rule is scoped to one namespace and one CVE: it only drops a source-named
        record where SUSE actually contradicts itself by publishing a fix. Where SUSE
        says affected and means it, the record must survive.

        Same document, the LTSS track: SLES 12 SP4-LTSS lists the identical twelve
        packages known_affected but has no `recommended` entry at all, so `pcre` there
        is a genuine "vulnerable, no fix available" claim and must still be reported.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_SOURCE_NAMED_AFFECTED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        ltss = {f.Name: f.Version for f in results["sles:12.4+ltss"].FixedIn}
        assert ltss["pcre"] == "None"
        assert ltss["libpcre1"] == "None"

    def test_unrelated_source_package_affected_records_survive(self, fixture_dir):
        """Narrowness in the other direction: the fix has to come from the *same* source
        package. CVE-2015-3217's plain 12 SP4 data fixes the `pcre` binaries but says
        nothing about `pcre2`, a separate source package whose own binaries SUSE lists
        known_affected in the same namespace. Those records are untouched -- a fix for
        pcre is not evidence about pcre2.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_SOURCE_NAMED_AFFECTED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        plain = {f.Name: f.Version for f in results["sles:12.4"].FixedIn}
        assert plain["pcre2"] == "None"
        for binary in ("libpcre2-8-0", "libpcre2-16-0", "libpcre2-32-0", "libpcre2-posix2"):
            assert plain[binary] == "None"

    def test_orphan_binary_inherits_the_build_that_fixed_its_siblings(self, fixture_dir):
        """One level down from the source-named drop: a *binary* SUSE lists
        known_affected whose fix list, in the same namespace, covers its siblings but
        not it.

        CVE-2019-13057 on plain SLES 15 SP1 is the real case. `known_affected` names 11
        openldap2 binaries; `vendor_fix` names 9 of them at 2.4.46-9.19.2, omitting
        libldap-data and openldap2-ppolicy-check-password. SUSE's *own* SP2 fix list for
        the same CVE carries all 11 at the identical 2.4.46-9.19.2 build, and the purl
        proves it is one build: libldap-data-2.4.46-9.19.2 is
        `upstream=openldap2-2.4.46-9.19.2.src.rpm`, same source NVR as the SP1 fix.

        So "None" here asserts "vulnerable at every version" about a binary that same
        build patched. The SLE 15 SP1 base image ships libldap-data-2.4.46-9.53.1 and
        libldap-2_4-2-2.4.46-9.53.1 from one source RPM: the latter is suppressed by its
        fix entry, the former was reported NOT-FIXED with no version to compare.

        The boundary comes from SUSE's own build rather than being inferred -- the rule
        only fires when the document publishes that package at the sibling's source NVR.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_ORPHAN_BINARY_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        plain = {f.Name: f.Version for f in results["sles:15.1"].FixedIn}
        # the siblings SUSE did list keep their own fix...
        assert plain["libldap-2_4-2"] == "0:2.4.46-9.19.2"
        assert plain["openldap2"] == "0:2.4.46-9.19.2"
        # ...and the omitted binary gets the boundary from the same source build,
        # epoch-prefixed like every other SLES version, rather than "None".
        assert plain["libldap-data"] == "0:2.4.46-9.19.2"

    def test_orphan_binary_is_retired_when_only_the_source_record_can_answer(self, fixture_dir):
        """The other remedy, in the same document. openldap2-ppolicy-check-password is
        orphaned on SLES 15 SP1 exactly as libldap-data is, but it is built on its own
        version stream (SP2 fixes it at 1.2-9.19.2, not 2.4.46-9.19.2), so no build of
        it carries the source NVR the SP1 siblings were fixed at. There is no honest
        boundary to inherit -- pasting the siblings' 2.4.46-9.19.2 onto a 1.2-x install
        would compare across streams and stay wrong.

        It is dropped instead, and only because `openldap2` -- the source RPM's own name
        -- is a fixed record in this namespace. grype resolves an installed binary to
        its source RPM and searches under that name too, so an unpatched
        openldap2-ppolicy-check-password still matches via `openldap2`
        (exact-indirect-match), and a patched one still produces the "Distro Not
        Vulnerable" ignore. Without that record the drop would be a false negative,
        which is why the rule requires it.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_ORPHAN_BINARY_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        plain = {f.Name: f.Version for f in results["sles:15.1"].FixedIn}
        assert "openldap2-ppolicy-check-password" not in plain
        # the record that answers the source-indirect search is still there
        assert plain["openldap2"] == "0:2.4.46-9.19.2"

    def test_orphan_rule_is_silent_where_the_namespace_fixes_nothing(self, fixture_dir):
        """Same scoping as the source-named drop: the rule needs SUSE to contradict
        itself *in this namespace*. SLES 15 SP1-LTSS lists the same 11 openldap2
        binaries known_affected and publishes no fix for any of them, so every one is a
        genuine "vulnerable, no fix available" claim -- including the two the plain
        track resolves.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_ORPHAN_BINARY_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        ltss = {f.Name: f.Version for f in results["sles:15.1+ltss"].FixedIn}
        assert ltss["libldap-data"] == "None"
        assert ltss["openldap2-ppolicy-check-password"] == "None"
        assert ltss["openldap2"] == "None"

    def test_wont_fix_requires_known_affected(self, fixture_dir):
        """no_fix_planned alone isn't enough to justify emitting a won't-fix record.
        CVE-2002-20001's real CSAF data sweeps a "no fix planned" remediation across
        several openssl sub-packages (libopenssl1_0_0, openssl-1_0_0, compat-openssl098,
        libopenssl1_1, openssl-1_1, ...) on SLES 12 SP4 -- but SUSE's product_status
        for this CVE never asserts any of them known_affected (product_status only has
        known_not_affected/recommended categories populated at all in this doc, and none
        of those categories mention these packages either). SUSE's own per-CVE web page
        renders this same sweep as "Ignore" -- i.e. these sub-packages were never
        independently assessed, not confirmed affected-but-wontfix.

        Only the source package `openssl` got an explicit, independent
        known_not_affected determination. Emitting Version="None" (vunnel's "every
        version is vulnerable, no fix exists" convention) for the unassessed
        sub-packages is a false positive: it asserts a stronger claim (affected) than
        the source data ever made.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_UNASSESSED_WONT_FIX_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        fixed = {f.Name: f for f in results["sles:12.4"].FixedIn}

        # openssl itself has a real, independent known_not_affected determination --
        # must still come through as "fixed at version 0".
        assert fixed["openssl"].Version == "0"

        # none of these were ever asserted known_affected -- despite each one also
        # appearing in the doc's no_fix_planned remediation, no won't-fix record (or
        # any record at all) should be emitted for them.
        for unassessed_package in (
            "libopenssl1_0_0",
            "openssl-1_0_0",
            "compat-openssl098",
            "libopenssl0_9_8",
            "libopenssl1_1",
            "openssl-1_1",
        ):
            assert unassessed_package not in fixed, (
                f"{unassessed_package} was never known_affected; no_fix_planned alone must not produce a record"
            )

    def test_ltss_fix_borrowed_into_plain_when_plain_has_nothing(self, fixture_dir):
        """liblzma5's real CSAF data for CVE-2022-1271 only lists a fix under
        "SUSE Linux Enterprise Server 12 SP4-LTSS" -- there's no bare "12 SP4" entry
        for it at all. Since SLES's LTSS track is the same package lineage continued
        longer (not a fork) and a container image can never be "on LTSS" in the first
        place (its marker package isn't available as a container image), the fix must
        be borrowed into the plain sles:12.4 namespace too, or it's unreachable by any
        real scan. Confirmed against the actual quality-gate regression this fixed."""
        doc = from_path(os.path.join(fixture_dir, f"{_LTSS_ONLY_FIX_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        plain_fixed = {f.Name: f.Version for f in results["sles:12.4"].FixedIn}
        ltss_fixed = {f.Name: f.Version for f in results["sles:12.4+ltss"].FixedIn}
        assert plain_fixed["liblzma5"] == "0:5.0.5-6.7.1"
        assert plain_fixed == ltss_fixed

    def test_ltss_fix_outranks_a_plain_affected_with_no_fix(self, fixture_dir):
        """A plain-track known_affected entry must not block an LTSS fix from being
        borrowed. This is the same inference as borrowing into an empty plain track,
        extended one step: SUSE stops publishing plain-track fixes once a SP leaves
        general support but leaves the "affected" line standing, so a plain "None" there
        is a statement about which channel ships the RPM, not about whether the code is
        fixed.

        CVE-2017-6004 is the real case, and it lands on the image the quality gate
        actually scans. SUSE lists libpcre1 known_affected on plain 12 SP4 and publishes
        the fix only under 12 SP4-LTSS and 12 SP4-ESPOS, at 8.45-8.7.1 --
        and 8.45-8.7.1 is exactly the libpcre1 build installed in
        registry.suse.com/suse/sles12sp4, whose SBOM reports the plain
        `cpe:/o:suse:sles:12:sp4`. So SUSE's own plain-CPE container image ships the
        LTSS-track RPM; no version-bearing `...Server 12 SP4:libpcre1-8.45-8.7.1`
        product exists anywhere in the corpus, only the -LTSS and -ESPOS ones.

        Emitting Version="None" here does not mean "your subscription can't get the
        fix" -- vunnel's "None" means *no version fixes this, every version matches*,
        which would report the installed 8.45-8.7.1 as vulnerable when it is the fix.
        Erring toward the borrowed version costs a fix a plain-subscription VM may not
        be entitled to install; erring the other way flags already-patched images.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_LTSS_FIX_VS_PLAIN_AFFECTED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        plain = {f.Name: f.Version for f in results["sles:12.4"].FixedIn}
        ltss = {f.Name: f.Version for f in results["sles:12.4+ltss"].FixedIn}

        # known_affected on plain, real fix on LTSS -> the fix wins
        for package in ("libpcre1", "libpcre1-32bit", "libpcre16-0"):
            assert ltss[package] == "0:8.45-8.7.1"
            assert plain[package] == "0:8.45-8.7.1", f"{package}: plain 'None' must not shadow the LTSS fix"

        # packages plain said nothing about are borrowed exactly as before
        assert plain["libpcrecpp0"] == "0:8.45-8.7.1"

    def test_borrowed_fix_also_retires_a_stale_source_named_record(self, fixture_dir):
        """The source-named drop has to see borrowed fixes too, not just fixes the plain
        track published itself.

        In CVE-2017-6004 plain 12 SP4 has no `recommended` entry at all -- every fix it
        ends up with is borrowed from -LTSS. Its known_affected list still names the
        source package `pcre` alongside the binaries. Once the libpcre1 fix is borrowed
        in, that source-named record is exactly as stale as the one in CVE-2015-3217,
        and just as reachable by grype's source-RPM indirect match, so it must go too.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_LTSS_FIX_VS_PLAIN_AFFECTED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        plain = {f.Name: f.Version for f in results["sles:12.4"].FixedIn}
        assert plain["libpcre1"] == "0:8.45-8.7.1"
        assert "pcre" not in plain

    def test_ltss_borrowing_does_not_override_real_plain_data(self, fixture_dir):
        """The borrowing rule only fills in packages plain has NOTHING for -- it must
        never clobber a real (and possibly different) plain-track answer, matching the
        version-disagreement pairs found in the corpus (plain and LTSS sometimes fix
        the same package at genuinely different versions)."""
        doc = from_path(os.path.join(fixture_dir, "cve-2019-8608.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        # sles:15.1 already has its own real fix for libwebkit2gtk-4_0-37 (asserted in
        # test_plain_and_ltss_tracked_separately above); borrowing must be a no-op here.
        plain_fixed = {f.Name: f.Version for f in results["sles:15.1"].FixedIn}
        assert plain_fixed["libwebkit2gtk-4_0-37"] == "0:2.24.2-3.27.1"

    def test_ltss_borrowing_does_not_override_not_affected(self, fixture_dir):
        """The boundary of the rule above. Borrowing now outranks a plain "None", but it
        must still never outrank a plain "0".

        "None" and "0" are not symmetric. A plain "None" is SUSE declining to ship on
        that channel; a plain "0" is an explicit known_not_affected determination -- SUSE
        looked at the plain track and said this package was never vulnerable there.
        Overwriting that with the LTSS fix version would invert the intent and *create*
        false positives, since every plain version below the borrowed version would then
        match. This is not hypothetical: a 3,000-document sample found 442 real
        (plain "0", LTSS fixed) pairs.

        CVE-2019-19966: the kernel packages are known_not_affected on plain SLES 15
        while 15-LTSS carries a real fix at 4.12.14-150.52.1.
        """
        doc = from_path(os.path.join(fixture_dir, f"{_LTSS_FIX_VS_PLAIN_NOT_AFFECTED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        plain = {f.Name: f.Version for f in results["sles:15"].FixedIn}
        ltss = {f.Name: f.Version for f in results["sles:15+ltss"].FixedIn}

        for package in ("kernel-default", "kernel-default-devel"):
            assert ltss[package] == "0:4.12.14-150.52.1"
            assert plain[package] == "0", f"{package}: known_not_affected must survive an LTSS fix"

    def test_ltss_platform_name_spelling_variant_still_resolves(self, fixture_dir):
        """SUSE's own generator isn't consistent about how it spells the LTSS platform
        name -- this document uses "SUSE Linux Enterprise Server 11 SP1 LTSS" (space,
        no hyphen) rather than the usual "...11 SP1-LTSS". Matching is CPE-driven
        specifically so this doesn't silently vanish."""
        doc = from_path(os.path.join(fixture_dir, f"{_LTSS_SPACE_SPELLING_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["11"])}

        assert "sles:11.1+ltss" in results
        fixed = {f.Name: f.Version for f in results["sles:11.1+ltss"].FixedIn}
        assert fixed == {"rsyslog": "0"}

    def test_allow_versions_filters_out_of_scope_namespaces(self, fixture_dir):
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        results = downconvert(doc, allow_versions=["12"])
        assert all(v.NamespaceName.startswith("sles:12") for v in results)
        assert not any(v.NamespaceName.startswith("sles:15") for v in results)

    def test_out_of_scope_ids_are_silent(self, fixture_dir, caplog):
        """Out-of-scope ids are skipped on scope, before anything tries to resolve them,
        so they never produce a "could not resolve" line. This matters most for the ids
        that have no product_tree relationship at all and so *cannot* resolve: across
        the full 64k-document corpus they number ~816k, and every one belongs to a
        product line we don't cover -- cloud host images (~549k, "chost:...") and the
        Open Buildservice Development Tools module (~267k). Committed fixtures can't
        cover this on their own, since subset_for_sles() strips exactly these ids, so
        the ids below are pasted verbatim from real corpus documents.
        """
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        doc.vulnerabilities[0].product_status.recommended += [
            "chost:microsoft/suse-sles-15-sp3-chost-byos-v20210729",
            "chost:amazon/suse-sles-15-sp1-chost-byos-v20210304-hvm-ssd-x86_64",
            "SUSE Linux Enterprise Module for Open Buildservice Development Tools 15 SP2:python-azure-agent-test-2.2.45-3.3.1",
        ]

        with caplog.at_level(logging.DEBUG):
            results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}

        assert not [r for r in caplog.records if "could not resolve" in r.message]
        # the real, in-scope data in the same document still comes through
        assert {f.Name: f.Version for f in results["sles:15.1"].FixedIn} == {"mailx": "0:12.5-1.87"}

    def test_unresolvable_in_scope_id_still_logs(self, fixture_dir, caplog):
        """The flip side of test_out_of_scope_ids_are_silent: an id naming a platform we
        DO cover, that still fails to resolve, is a genuine anomaly worth a line. (This
        never happens in the current corpus -- zero occurrences across 64k documents --
        but it's the case the debug log exists for.)"""
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        doc.vulnerabilities[0].product_status.recommended.append("SUSE Linux Enterprise Server 15 SP1:no-such-package-1.0")

        with caplog.at_level(logging.DEBUG):
            downconvert(doc, allow_versions=["15"])

        assert [r for r in caplog.records if "no-such-package-1.0" in r.message]

    def test_lowest_version_wins_among_competing_recommended_entries(self, fixture_dir):
        """`recommended` alone can name one package twice at different versions -- 2,072
        (cve, namespace, package) triples corpus-wide. `FixedIn.Version` is a boundary
        ("installed below this is vulnerable"), so among versions all claimed to fix the
        CVE the *lowest* is the true boundary; a higher one reports already-patched
        installs as vulnerable.

        This used to fall out of `product_status` list order, which picked a non-lowest
        version in 306 of those triples. CVE-2018-4197 lists
        `typelib-1_0-WebKit2WebExtension-4_0` on SLES 12 SP5 at both 2.22.4-2.29.3 and
        2.24.4-2.47.1."""
        doc = from_path(os.path.join(fixture_dir, f"{_MULTI_RECOMMENDED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"])}

        fixed = {f.Name: f.Version for f in results["sles:12.5"].FixedIn}
        assert fixed["typelib-1_0-WebKit2WebExtension-4_0"] == "0:2.22.4-2.29.3"

    def test_selection_does_not_depend_on_product_status_order(self, fixture_dir):
        """The corollary: shuffling `product_status` must not change any emitted version.
        Fold order deciding a fix version was the actual defect behind the test above."""
        doc = from_path(os.path.join(fixture_dir, f"{_MULTI_RECOMMENDED_CVE}.json"))
        before = {(v.NamespaceName, f.Name): f.Version for v in downconvert(doc, allow_versions=["12"]) for f in v.FixedIn}

        for vuln in doc.vulnerabilities:
            vuln.product_status.recommended.reverse()
        after = {(v.NamespaceName, f.Name): f.Version for v in downconvert(doc, allow_versions=["12"]) for f in v.FixedIn}

        assert before == after

    def test_recommended_wins_over_a_higher_first_fixed(self, fixture_dir):
        """SUSE's `first_fixed` does not mean what the spec says. Across 2,326,075
        triples the two categories collide on 905, disagree on 666, and `recommended` is
        the lower version in **all 666** -- never once higher. So lowest-wins keeps
        `recommended`, and SUSE's own advisories back that: where both builds are
        attested, `recommended` shipped earlier in 523 of 666 cases and `first_fixed`
        earlier in none.

        Reordering to prefer `first_fixed` would push 613 records above the build that
        demonstrably shipped the fix -- a median 64 extra days of false positives.

        With no advisory index (`fix_dates=None`) there is no attestation to consult, so
        this is the pure lowest-wins path."""
        doc = from_path(os.path.join(fixture_dir, f"{_UNATTESTED_RECOMMENDED_CVE}.json"))
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["16"])}

        fixed = {f.Name: f.Version for f in results["sles:16.0"].FixedIn}
        # recommended 6.12.0-160000.5.1 vs first_fixed 6.12.0-160000.37.1
        assert fixed["kernel-default"] == "0:6.12.0-160000.5.1"

    def test_unattested_recommended_yields_to_an_attested_first_fixed(self, fixture_dir):
        """The one exception to lowest-wins. A `recommended` build that no SUSE advisory
        ever shipped for this CVE, sitting beside a `first_fixed` build that was shipped,
        is not a fix at all -- it's a pre-fix GA build SUSE listed anyway -- so it drops
        out before the version comparison.

        This is the residue lowest-wins alone can't reach: 47 of 2,696,427 fixed records
        corpus-wide (0.0017%), confined to two CVEs on sles:16.0. They are false
        negatives without this rule -- the emitted boundary sits below the real fix, so
        an unpatched install compares as fixed."""
        doc = from_path(os.path.join(fixture_dir, f"{_UNATTESTED_RECOMMENDED_CVE}.json"))
        # only the first_fixed build is attested; the recommended GA build never shipped
        # for this CVE.
        fix_dates = FixDates(
            Finder(strategies=[], first_observed=_NoFirstObserved()),
            AdvisoryDates(by_cve_nevr={("CVE-2025-38250", "kernel-default-6.12.0-160000.37.1"): "2026-08-25"}),
        )
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["16"], fix_dates=fix_dates)}

        fixed = {f.Name: f for f in results["sles:16.0"].FixedIn}
        assert fixed["kernel-default"].Version == "0:6.12.0-160000.37.1"
        assert fixed["kernel-default"].Available.Date == "2026-08-25"
        # siblings with no attestation either way are untouched: all-or-nothing
        # attestation is no evidence, so they keep the lowest version.
        assert fixed["kernel-64kb"].Version == "0:6.12.0-160000.5.1"

    def test_attestation_never_overrides_within_one_category(self, fixture_dir):
        """The attestation rule is scoped to disagreements *across* categories. Within
        `recommended` alone, competing versions are parallel maintenance streams rather
        than a spec disagreement, and advisory coverage is only ~58% -- so letting an
        index gap raise a version there would manufacture false positives."""
        doc = from_path(os.path.join(fixture_dir, f"{_MULTI_RECOMMENDED_CVE}.json"))
        fix_dates = FixDates(
            Finder(strategies=[], first_observed=_NoFirstObserved()),
            # attest only the *higher* of the two competing recommended builds
            AdvisoryDates(by_cve_nevr={("CVE-2018-4197", "typelib-1_0-WebKit2WebExtension-4_0-2.24.4-2.47.1"): "2019-06-01"}),
        )
        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["12"], fix_dates=fix_dates)}

        fixed = {f.Name: f.Version for f in results["sles:12.5"].FixedIn}
        assert fixed["typelib-1_0-WebKit2WebExtension-4_0"] == "0:2.22.4-2.29.3"

    def test_description_comes_from_the_document_note(self, fixture_dir):
        """SUSE spells the CVE description as a document-level note (category
        "description"); the per-vulnerability copy, where it exists, is category
        "general". Reading vuln.notes for category "description" -- the obvious-looking
        place -- matches nothing in any real document, so this asserts against the note
        that actually carries the text."""
        doc = from_path(os.path.join(fixture_dir, "cve-2023-47627.json"))
        results = downconvert(doc, allow_versions=["15"])

        assert results
        for v in results:
            assert v.Description.startswith("aiohttp is an asynchronous HTTP client/server framework")

    @pytest.mark.parametrize(
        ("cve", "marker"),
        [
            (_REJECTED_CANDIDATE_CVE, "DO NOT USE THIS CANDIDATE NUMBER"),
            (_REJECTED_CNA_WORDING_CVE, "has been rejected or withdrawn"),
        ],
    )
    def test_withdrawn_cve_emits_nothing(self, fixture_dir, caplog, cve, marker):
        """A CVE ID MITRE has rejected is not a vulnerability, so reporting it is a
        false positive no matter what SUSE's product_status says -- and SUSE keeps
        publishing affected/fixed data for these regardless (CVE-2023-45918 lists 616
        affected products and three shipped SUSE-SUs).

        Both of MITRE's rejection wordings are covered because they barely overlap in
        the real corpus: of the 789 withdrawn documents, 447 use the "CANDIDATE NUMBER"
        wording and 311 use the CNA wording, with one document in both.
        """
        doc = from_path(os.path.join(fixture_dir, f"{cve}.json"))
        assert any(n.category == "description" and marker in n.text for n in doc.document.notes)

        with caplog.at_level(logging.DEBUG):
            assert downconvert(doc, allow_versions=["15"]) == []

        assert [r for r in caplog.records if "withdrawn (rejected) CVE" in r.message]

    def test_withdrawn_check_reads_the_description_not_the_whole_document(self, fixture_dir):
        """The marker only counts in the description note. A document that merely
        mentions the phrase elsewhere -- a reference summary, say -- is a live CVE and
        must still be reported; anchoring to the description is what keeps prose
        matching from over-reaching."""
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        doc.document.references[0].summary = "DO NOT USE THIS CANDIDATE NUMBER"

        results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}
        assert {f.Name: f.Version for f in results["sles:15.1"].FixedIn} == {"mailx": "0:12.5-1.87"}

    def test_disputed_and_unsupported_are_not_withdrawn(self, fixture_dir):
        """MITRE's other bracketed markers are not rejections and must not be skipped:
        `** DISPUTED **` is a contested but live record, and
        `** UNSUPPORTED WHEN ASSIGNED **` is a real vulnerability in software that was
        already end-of-life. Both are rare in the corpus (4 and 8 documents), and both
        would be real findings to drop."""
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        description = next(n for n in doc.document.notes if n.category == "description")

        for marker in ("** DISPUTED **", "** UNSUPPORTED WHEN ASSIGNED **"):
            description.text = f"{marker} some real vulnerability"
            results = {v.NamespaceName: v for v in downconvert(doc, allow_versions=["15"])}
            assert {f.Name: f.Version for f in results["sles:15.1"].FixedIn} == {"mailx": "0:12.5-1.87"}, marker


class TestOrphanBinaryGuards:
    """The two conditions that stop the orphan-binary rule, built by hand rather than
    from a fixture: neither shape occurs in the 1,200-document corpus sample this rule
    was measured on (zero declared won't-fix records sit beside a same-source fix), so
    there is no real document to subset for them -- but both are load-bearing, and a
    regression in either is a false negative rather than a visible failure.
    """

    @staticmethod
    def _record(name, version, *, no_advisory=False):
        return FixedIn(
            Name=name,
            NamespaceName="sles:15.1",
            VersionFormat="rpm",
            Version=version,
            Module=None,
            VendorAdvisory=VendorAdvisory(NoAdvisory=no_advisory, AdvisorySummary=[]),
        )

    def _builds(self):
        # foo builds two binaries; neither is published at the source NVR of the other's
        # fix, so only the retire branch can apply
        return _ProductBuilds(
            source_by_package={"libfoo": "foo", "libfoo-data": "foo", "foo": "foo"},
            source_nvr_by_build={("libfoo", "0:1.0-1.1"): "foo-1.0-1.1", ("foo", "0:1.0-1.1"): "foo-1.0-1.1"},
            build_from_source={},
        )

    def test_declared_wont_fix_is_never_retired(self):
        """A `no_fix_planned` remediation naming the exact product is SUSE stating a
        position -- how they say one flavor stays vulnerable while its sibling is fixed
        (CVE-2023-47627 declares python-aiohttp won't-fix on SLES 15 SP4 while the
        same-source python311-aiohttp is fixed). Retiring that drops a real,
        vendor-confirmed exposure. Same carve-out as _drop_stale_source_records.
        """
        bucket = {
            "foo": self._record("foo", "0:1.0-1.1"),
            "libfoo-data": self._record("libfoo-data", "None", no_advisory=True),
        }
        _resolve_orphan_binaries({"sles:15.1": bucket}, self._builds(), "CVE-2024-0001", None, logging.getLogger(__name__))

        assert bucket["libfoo-data"].Version == "None"

    def test_record_stands_when_no_source_named_record_can_answer(self):
        """Without a record named for the source RPM, dropping is a false negative:
        grype's source-indirect search would find nothing under `foo` either, so an
        unpatched libfoo-data becomes invisible to both match paths. Corpus-wide this is
        the common case -- 326 of 363 orphans -- so the rule leaves them alone and the
        false positive stays SUSE's to fix.
        """
        bucket = {
            "libfoo": self._record("libfoo", "0:1.0-1.1"),
            "libfoo-data": self._record("libfoo-data", "None"),
        }
        _resolve_orphan_binaries({"sles:15.1": bucket}, self._builds(), "CVE-2024-0001", None, logging.getLogger(__name__))

        assert bucket["libfoo-data"].Version == "None"

    def test_record_is_retired_once_the_source_named_record_exists(self):
        """The pair to the case above: same bucket plus a fixed `foo`, which is what
        makes the drop safe. Proves the guard is what holds the record, not some other
        condition."""
        bucket = {
            "libfoo": self._record("libfoo", "0:1.0-1.1"),
            "foo": self._record("foo", "0:1.0-1.1"),
            "libfoo-data": self._record("libfoo-data", "None"),
        }
        _resolve_orphan_binaries({"sles:15.1": bucket}, self._builds(), "CVE-2024-0001", None, logging.getLogger(__name__))

        assert "libfoo-data" not in bucket


def test_provider_via_snapshot_csaf(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    """Runs the CSAF path end to -- through the real streaming SLESCSAFClient/tarfile code, not just the
    downconvert function directly -- against real, subsetted CSAF VEX fixtures, and
    snapshot-tests the resulting OS-schema records. This is the CSAF-path counterpart
    to test_provider_via_snapshot_oval: proves the new ingestion path produces valid,
    stable OS-schema output for real fixed / not-affected / won't-fix / plain-vs-LTSS
    data. It intentionally does not reuse the OVAL path's existing snapshot files --
    CSAF legitimately enriches VendorAdvisory (populated from document.references,
    where OVAL leaves it empty) and doesn't have OVAL's `Available` fixdate, so a
    byte-for-byte match against the old snapshots isn't the right bar; this asserts
    the CSAF path's own output is what we expect and stays that way.
    """
    # a sibling directory to test-fixtures/snapshots, not nested inside it -- the OVAL
    # path's own snapshot test walks its whole snapshot_dir tree looking for
    # unasserted files, so nesting here would make it see (and fail on) our files too.
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    workspace.snapshot.snapshot_dir = helpers.local_dir("test-fixtures/snapshots-csaf")

    c = Config(use_csaf=True, allow_versions=["15"])
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    c.runtime.skip_download = True
    p = Provider(root=workspace.root, config=c)

    assert p.csaf_client is not None
    _build_test_archive(helpers.local_dir("test-fixtures/csaf"), p.csaf_client.archive_path)
    assert p.csaf_advisory_client is not None
    _build_test_advisory_archive(helpers.local_dir("test-fixtures/csaf-advisory"), p.csaf_advisory_client.archive_path)

    p.update(None)

    assert workspace.result_schemas_valid(require_entries=True)
    workspace.assert_result_snapshots()
