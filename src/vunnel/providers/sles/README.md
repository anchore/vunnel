# SLES provider

## Overview

The SLES provider can consume either OVAL XML or CSAF JSON from
SUSE, controlled by the `use_csaf` config, which defaults to true.
Both providers emit OS schema `Vulnerability` + `FixedIn` records,
so no Grype change is required to consume this information.

This README documents the CSAF behavior. The OVAL behavior in
is considered deprecated.

## Why CSAF over OVAL

Prefer CSAF over OVAL mode because it produces more complete and correct
data, in the following ways, order by importance:

1. It includes unfixed disclosures. That is, scanners consuming the output of the CSAF mode can detect vulnerabilities that are disclosed but not fixed.
2. Consumers will no longer find false positives when an RPM is fixed in LTSS and non-LTSS builds.
3. Consumers can tell when SUSE has marked a vulnerability as "will not fix"
4. Matching on vulnerabilities that are fixed in LTSS and non-LTSS is more accurate.
5. Parsing JSON is nicer than parsing XML.

## Data downloaded

This provider downloads two files:

- CVE-oriented CSAF, from https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2
- Advisory-oriented CSAF https://ftp.suse.com/pub/projects/security/csaf.tar.bz2

As of this writing, the `changes.csv` mechanism used by the RHEL CSAF and Hummingbird providers
is not needed here; the `.tar.bz2` archives are newer than `changes.csv` and seem complete.

## How a document is read

`csaf_parser.py` reads each document, extracting JSON documents from the `r|bz` stream,
and takes them through the following steps.

1. **Dropping withdrawn records** by detecting strings like "do not use this candidate number"
2. **Filtering to relevant platforms** by examining the platform CPEs in the document.
3. **Detecting relevant packages** by computing the children of the relevant platforms.
4. **Raising assertions** by examining `product_status` and `remediations` sets.
5. **Emitting FixedIns** by folding up the assertions as follows:

======= change below here ======

Yield order is precedence — for a given (namespace, package), the first assertion wins:

| Order | Source | `Version` | `VendorAdvisory` |
|---|---|---|---|
| 1 | `recommended`, `first_fixed` and `fixed` together, one version chosen — see "Choosing among the fix categories" | the fixed version | the CVE's advisories, `NoAdvisory=False` |
| 2 | `known_not_affected` | `"0"` | absent (`None`) |
| 3 | `known_affected`, covered by a `no_fix_planned` remediation | `"None"` | the CVE's advisories, `NoAdvisory=True` |
| 4 | `known_affected`, not covered by one | `"None"` | the CVE's advisories, `NoAdvisory=False` |

so a weaker later statement never downgrades a real fix. Precedence only decides
*between* those three rows: row 1 is not itself a precedence list, because
`_fix_assertions` yields **one** assertion per (namespace, package), so fold order never
picks a version. Row 3 has one exclusion — a
`known_affected` entry naming a *source* package whose binaries this namespace already
fixes emits nothing (see "Source-named `known_affected` entries" below).
`_borrow_ltss_fixes_into_plain()` runs over the completed fold, so it can tell a plain
namespace has *nothing* to say about a package.

`"None"` is vunnel's "vulnerable, no fix available yet" convention — exactly what
`known_affected` claims. Both row-3 cases come from one pass over it
(`_affected_assertions`); the `no_fix_planned` remediation only sets `NoAdvisory`,
marking a *declared* won't-fix apart from a fix maybe still coming, and emits nothing
alone — see "Won't-fix requires `known_affected`" below. Same mapping as
`ubuntu/os_downconvert.py`; OVAL encodes only fixed and not-affected, so
affected-but-unfixed is data CSAF recovers.

Two consequences:

- **Out-of-scope products are never visited.** Uncovered lines — cloud host images
  (`chost:...`), the Open Buildservice Development Tools module, ~816k IDs corpus-wide —
  have no relationship under an in-scope platform, so nothing resolves them or reports
  them unresolvable.
- **Version-less IDs take their package name from `product_reference`, not the purl**,
  which mistakes part of the RPM name for a version (`libjavascriptcoregtk-4_0-18` →
  `pkg:rpm/suse/libjavascriptcoregtk@4_0-18`). Version-bearing branches spell it
  correctly and do use the purl, the source of fixed versions.

## Choosing among the fix categories

Three `product_status` categories carry a fixed version — `recommended`, `first_fixed`,
`fixed` — and they can name the same (namespace, package) at *different* versions.
`_choose_fix` picks one: **the lowest version wins**, with one exception.

Lowest, because `FixedIn.Version` is a boundary — "installed below this is vulnerable".
Among versions all claimed to fix the CVE the earliest is the true boundary; a higher one
reports already-patched installs as vulnerable. 2,738 triples need a version chosen at
all — see "Known limitation" for how many a single boundary cannot serve.

Don't prefer `first_fixed` on the strength of the spec ("the first version containing the
fix"): SUSE's data does not honour that. Where both keys name a build and disagree (666
triples) `recommended` is never the higher of the two, and where both builds are attested
by an advisory `recommended` shipped earlier in **523** and `first_fixed` in **none**.
SUSE's `first_fixed` behaves like "a recent build known to contain the fix". `fixed` is
effectively dead — one (document, vulnerability) in 64,231 populates it and it never
survives scoping — but costs nothing to keep in the tuple.

**The exception: a version no advisory attests is not a fix.** In 47 of those 666
disagreements only `first_fixed` is attested, `recommended` naming a pre-fix GA build no
advisory ever shipped for that CVE, so lowest-wins would put the boundary *below* the real
fix and call an unpatched install fixed. So a candidate no advisory attests, standing
beside one that is, drops out before the version comparison; `FixDates.attests()` reads
the `(CVE, NEVR)` index from "Fix dates" below as evidence rather than as a date. Advisory
coverage is only ~58%, so two guards keep an index gap from raising a version: attestation
is consulted only *across* categories (competing versions inside `recommended` are
parallel streams, not a spec disagreement), and only when it discriminates.

### Known limitation

A single `FixedIn` cannot express two parallel version streams, so where a SLES release
carries two, one boundary is wrong for one of them. **This affects 1,681 of 2,326,075
(cve, namespace, package) tuples — 0.072%, about 1 in 1,400.**

A tuple is at risk when its candidate versions span more than one **upstream** version,
because release order then says nothing across the boundary: `2.11.1-6.40.1` being lower
than `2.24.0-8.20.1` does not make it a fix for anything in the `2.24.0` line.
`python-requests` on `sles:12.5` is the shape — SP5 carries `2.11.1-6.x` and `2.24.0-8.x`
side by side, so the boundary lands on the lower stream and an installed `2.24.0-8.14.1`
reports fixed while sitting below its own stream's fix. The other 1,057 of the 2,738
chosen tuples are rebuilds within one upstream version, where the lowest is simply right.

Taking the highest instead inverts this into false positives for every install patched on
the lower stream — a larger set, and the direction this provider consistently avoids.
Fixing it properly needs several `FixedIn` records per package, which the OS schema has no
room for. The number counts tuples where the emitted boundary *cannot* be right for both
streams, not scans that will actually miss something.

## Scope: SLES only, for now

Only the plain and LTSS tracks of **SUSE Linux Enterprise Server**; everything else
sharing that name prefix in SUSE's product catalog is deliberately excluded:

| Variant | Example | Why excluded |
|---|---|---|
| SAP | `... for SAP Applications 15` | Different product line, out of scope by design |
| HPC | `... High Performance Computing 15 SP1` | Different product line |
| Desktop / Workstation | `... Desktop 15 SP1` | Different product line |
| Modules | `... Module for Basesystem 15 SP1` | Different product line (SLE Modules aren't RHEL-style optional modularity — they're separate add-on repos) |
| BCL (Basic Component Lifecycle) | `... 15 SP1-BCL` | Different product line |
| Teradata | `... 11 SP1-TERADATA` / `... 11 SP1 for Teradata` | Vendor-specific rebuild; confirmed to sometimes share plain SLES's CPE product component, so excluded by name, not CPE |
| Raspberry Pi | `... for Raspberry Pi 12 SP2` | Confirmed to share a CPE **byte-for-byte identical** to plain SLES of the same version in at least one case — excluded by name, since CPE alone can't distinguish it |
| `-SECURITY` | `... 11-SECURITY` | Unrecognized variant, excluded by name shape |
| ESPOS | `... 15-ESPOS` | Different product line |

Two **LTSS sub-tiers** are out too, though genuinely LTSS-adjacent:
`SUSE Linux Enterprise Server 11 SP4 LTSS EXTREME CORE` and
`SUSE Linux Enterprise Server 12 SP5-LTSS Extended Security`, confirmed distinct by
their own CPE product components
(`suse_sles_ltss-extreme-core`/`sles-ltss-extended-security`). Two SPs so far, each a
longer-tail paid tier beyond regular LTSS; deliberate, not an oversight — revisit on
demand.

## Platform matching is CPE-driven, not name-string-driven

SUSE's CSAF generator spells display names inconsistently: one product (same CPE,
`cpe:/o:suse:suse_sles_ltss:11:sp1`) appears as both
`"SUSE Linux Enterprise Server 11 SP1-LTSS"` and `"...11 SP1 LTSS"` (space, no hyphen).
Verbatim name matching silently drops whichever spelling a document uses — a real bug,
since found and fixed.

So `namespace_and_channel_for_platform()` classifies by CPE
(`cpe:/o:suse:{product}:{major}[:sp{n}]`, plus a newer
`cpe:/o:suse:{product}:{major}:{major}.{minor}:server` form for SLES 16+'s dotted
versioning), matching the `product` component against plain aliases (`sles`,
`suse_sles`) and LTSS aliases (`sles-ltss`, `suse_sles_ltss`) — both exist because SLES
11-era and 12+-era documents spell it differently for the same distinction. The platform
**name** is still checked, but only as a cheap defensive backstop for the two cases
(Teradata, Raspberry Pi) where CPE alone can't separate an excluded variant from
plain/LTSS SLES — see the table above.

## Plain vs LTSS: two distinct namespaces, not one

Plain and LTSS are separate namespaces (`sles:X.Y` vs `sles:X.Y+ltss`), mirroring
`rhel:X.Y+eus` / `ubuntu:X.YY+esm` elsewhere in this repo, not folded together under a
preference rule as the OVAL parser does. A corpus-wide survey backs that:

- Plain against its LTSS variant, same major.SP: **8,157 (cve, package, major.SP)
  triples** have a real fix on *both* tracks at *different* versions — LTSS sometimes a
  later cumulative build of the same upstream version, sometimes a different upstream
  version or numbering scheme entirely. Picking a "winner" (as OVAL does) discards one
  side's true answer.
- **364,705 (cve, package) pairs** have a real fix on LTSS and *zero* data on plain, not
  even `known_affected` — see "LTSS→plain fix-borrowing" below.
- A smaller reverse set (plain fixed, LTSS absent), concentrated in SPs still within
  general support: real module/package-scope differences, not a time lag.

## LTSS→plain fix-borrowing

`_borrow_ltss_fixes_into_plain()`: **if a package has a real fix on the LTSS track for a
CVE, and the plain track has nothing better to say about that exact (CVE, package) — no
data, or a bare `known_affected` with no fix — copy the fix into the plain namespace.**

**This is the opposite of what this repo does for Ubuntu Pro/ESM, deliberately.** Ubuntu's
analogous rule (`ubuntu/README.md`, "Pro-only-fix → base wont-fix inference") synthesizes
a base **wont-fix** instead of copying Pro's version down, because Canonical *omits* the
base ecosystem from `affected[]`, making base's absence itself a signal. In SUSE's VEX a
missing plain entry is just missing. The data differs, so the inference does.

What justifies it:

1. **LTSS continues the same lineage longer; it isn't a fork.** SUSE's lifecycle page
   calls LTSS "the identical codebase", patches "backports to the original service pack
   version, not forward ports to newer versions" — so a version fixing a CVE on LTSS is
   evidence about that package's *code*, whichever channel ships it.
2. **Plain-CPE artifacts demonstrably carry LTSS-track builds.**
   `registry.suse.com/suse/sles12sp4` reports `cpe:/o:suse:sles:12:sp4` and ships
   `libpcre1-8.45-8.7.1`, which the corpus publishes *only* under `12 SP4-LTSS` and
   `12 SP4-ESPOS`; that artifact selects `sles:12.4`, where without borrowing the fix is
   unreachable. SUSE stops plain-track fixes once a SP passes general support, and 100% of
   the 364,705-pair set above is past-general-support SPs, so this is the common shape.

The rule stands on those two points — code lineage, and an observed plain-CPE artifact
carrying an LTSS-only build — not on `+ltss` being unreachable. We have never examined a
paid-LTSS image, and syft reads `/etc/os-release`'s `CPE_NAME`, so an LTSS-entitled
artifact reporting an LTSS CPE would be detected and the namespace selected normally.
Don't claim `+ltss` is unreachable, or that a container image can never be "on LTSS":
neither is established. (The OVAL parser's `_release_resolver` docstring says
`sles-ltss-release` "is not available as a container image" — an inherited assertion, not
a measurement.)

`CVE-2022-1271` (`liblzma5`) is the measured quality-gate regression this fixed: fixed
only under `...Server 12 SP4-LTSS`, so `sles:12.4` could never reach a labeled true
positive.

Deliberately narrow:

- **One-directional (LTSS → plain).** No reverse borrow: no demonstrated false positive
  drives it, and the plain-fixed/LTSS-absent set is real module- and package-scope
  difference (see "Plain vs LTSS" above).
- **Only real fixed versions cross** — never `known_not_affected` ("0") or won't-fix
  ("None").
- **Never overrides a real plain answer**: a plain fixed version or `"0"` wins, even where
  the versions disagree.

**A plain `"None"` it does override.** Once a SP leaves general support SUSE stops
plain-track fixes but leaves the `known_affected` line standing, so a plain `"None"` there
describes *which channel ships the RPM*, not whether the code is fixed — and `"None"` is
stronger than "unavailable to you": no version fixes this, every version matches, no
comparison performed. `CVE-2017-6004` gave `libpcre1 → "None"` on `sles:12.4` with the fix
on `-LTSS` at 8.45-8.7.1, flagging an installed 8.45-8.7.1 that *is* the fix.

The alternative — leaving the fix on `+ltss` only — says nothing to a plain scan:
`sles:12.4` would carry no record, so an unpatched plain install comes back clean. **We
would rather sometimes advertise a fix that turns out to be paywalled than emit that false
negative;** a paywalled fix is a wrong remediation hint on an otherwise correct finding.
Nor is it a regression: OVAL folded the two tracks into one namespace per version, so
where only LTSS data existed it already published under the plain namespace, with none of
these guards. Over a random 6,000-document sample the rule converts **986 plain `"None"`
records across 117 CVEs**.

The `"0"` boundary is asymmetric on purpose: a plain `"0"` is an explicit
`known_not_affected` determination, so borrowing over it would invert SUSE's own "never
vulnerable there" and match every plain version *below* the borrowed one — and a
3,000-document sample found 442 real (plain `"0"`, LTSS fixed) pairs.

**Known limitation.** Some "LTSS fixed, plain absent" pairs are LTSS-only content never
meant to infer about plain — kernel live-patches (`kgraft-patch-*`), old LTSS-specific
repackagings — ~4.3% of qualifying pairs. Filtering precisely needs cross-document
knowledge (does this package exist *anywhere* on plain SLES) unavailable one document at a
time: a conscious tradeoff, revisit if it proves to matter.

## Won't-fix requires `known_affected`

A `no_fix_planned` remediation alone doesn't mean SUSE assessed a package as affected.
SUSE sweeps it across sub-packages `product_status` never mentions in any category: for
`CVE-2002-20001`, `libopenssl1_0_0`, `openssl-1_0_0`, `compat-openssl098` and others
appear *only* in the remediation, alongside the source `openssl` package's own
independent `known_not_affected` determination — and SUSE's per-CVE page renders that
sweep as "Ignore", not a considered affected-but-won't-fix call. `Version: "None"` for
them would assert "vulnerable" about packages SUSE never claimed were affected. So
`known_affected` puts a package into that state; the remediation only sets `NoAdvisory`
on a package already there.

Note the direction: the rule gates on `known_affected` because `no_fix_planned` is the
untrustworthy signal, not the reverse. Requiring *both* would drop every package SUSE
has confirmed affected but simply hasn't fixed yet — the common case: 16,889 records
across a 1,500-document sample, and 2% of documents would report nothing at all for SLES
despite SUSE naming affected packages.

## Source-named `known_affected` entries

`known_affected` mixes granularities: alongside the binary RPMs it names their
**source** package, and keeps that claim standing after the binaries are fixed.

`CVE-2015-3217`, plain SLES 12 SP4: `recommended` lists `libpcre1-8.39-8.3.1` plus eight
sibling binaries, `known_affected` lists `pcre` — the source RPM all nine build from —
plus most of those binaries. Fix-first precedence masks the per-binary contradictions;
`pcre` has no same-named fix to mask it, so it survived as `Version: "None"`, a false
positive with an unusually wide blast radius:

- `pcre` is **not a shipped binary on SLES 12 at all**: no version-bearing
  `...Server 12*:pcre-<version>` product exists in the 64k-document corpus.
- grype also searches an installed binary's source RPM name (`exact-indirect-match`), so
  `libpcre1-8.45-8.7.1`, well above the `8.39-8.3.1` fix, matched `pcre` → `"None"`:
  NOT-FIXED.
- `"None"` carries no version to compare, so one source-named record over-matches
  *every* binary that source builds, at *every* version.

SUSE's own page carries both halves — patch table `libpcre1 >= 8.39-8.3.1` for 12 SP4,
state table (source granularity) `pcre | Affected` — and `recommended` is authoritative.

So `_affected_assertions` drops a `known_affected` entry whose name is the source RPM of
a fix in the **same namespace and same CVE**. Both scope halves matter: this document's
LTSS track has no `recommended`, so its `pcre` is a genuine "vulnerable, no fix" claim
and still reported; `pcre2`, a separate source package with no fix here, is untouched.

**The source name comes off the *fixed* products, never the affected entry's own purl**,
which often carries no `upstream=` qualifier at all (`pkg:rpm/suse/webkit2gtk3@`) while
the fixed products spell it out (`upstream=webkit2gtk3-2.22.4-2.29.3.src.rpm`). Same
purl mangling as under "How a document is read" above, and no corner case: `webkit2gtk3`
leads this class, so a purl-derived implementation would miss most of the problem.

Two boundaries. It runs **after** LTSS fix-borrowing, so a borrowed fix retires a stale
source record just as a plain-track fix would (`CVE-2017-6004` reaches plain 12 SP4
purely by borrowing). And a **declared won't-fix is never retired**: where a
`no_fix_planned` remediation names the exact product (`NoAdvisory=True`) SUSE is stating
a position — how it says "this flavor stays vulnerable, use the other one".
`CVE-2023-47627` declares `python-aiohttp` won't-fix on SLES 15 SP4 while its sibling
`python311-aiohttp`, same source RPM, is fixed; retiring that drops a real,
vendor-confirmed exposure.

Narrow by measurement: over a random 6,000-document sample (9.3% of the corpus) it
suppresses **180 records across 114 CVEs — 0.22% of the 80,724 records `known_affected`
would otherwise produce** — led by `webkit2gtk3` (43), `exiv2` (12), `jasper` (10) and
`LibVNCServer` (8). Only 12 of the 180 also ship as a binary in that namespace
(`php5`/`php7`/`php72`, `mariadb`, `librest`), where SUSE fixed a sibling from the same
source RPM but not the same-named binary — rebuilt at the same NVR anyway, so making no
claim beats asserting "vulnerable at every version".

Rejected alternative: dropping any entry whose name matches its own source RPM. Roughly
half of all SUSE source RPM names are also real binary RPM names (`kernel-default`'s
purl is
`pkg:rpm/suse/kernel-default@4.12.14-122.237.1?upstream=kernel-default-4.12.14-122.237.1.src.rpm`),
so it drops 17,191 records in the same sample — 21.3% of all `"None"` records, 84%
naming genuine binaries, including every unfixed kernel record — while catching only 166
of its targets.

## Withdrawn (rejected) CVEs

A document whose description says MITRE has rejected the CVE ID emits nothing at all;
`downconvert()` checks that before any scope work, since one VEX document is one CVE.

SUSE keeps publishing affected/fixed data for these: `CVE-2023-45918`'s description reads
`"DO NOT USE THIS CANDIDATE NUMBER. ... This candidate was withdrawn by its CNA."` while
the document still lists 616 `known_affected` products and 425 fixed. **CSAF 2.0 has
nowhere to encode the rejection** — `tracking.status` is only draft/final/interim, and
`flags[].label` justifies *not affected*, never *not a vulnerability* — so SUSE mirrors
MITRE's `cveMetadata.state: "REJECTED"` as prose, which is all this feed has.

**Matching prose is the wrong layer; this is deliberately a stopgap.** The principled
version reads `state: "REJECTED"` off the CVE List / NVD data once, for every provider; a
rule inside one provider reaches only vendors who mirror MITRE's sentences, hence
SLES-only. No central filter exists today — the `nvd` provider carries `vulnStatus`
without branching on it, and the nearest precedents are vendor-sourced
(`ubuntu/os_downconvert.py`, `alpine/rejections.py`). **If a central filter ever lands,
delete this rule rather than maintaining it.** Tolerable meanwhile: MITRE-generated
boilerplate, stable 20+ years, anchored to `document.notes[category="description"]` so a
phrase in a reference summary can't trip it; 40 documents sampled against `cvelistV5` came
back 40/40 at `state: "REJECTED"`.

MITRE has several rejection wordings and SUSE mirrors all of them, so the best-known
phrase alone catches only a bit over half. `_REJECTED_CVE_MARKERS` holds four, matched
case-insensitively: `DO NOT USE THIS CANDIDATE NUMBER`, `has been rejected or withdrawn`
(the modern CNA wording), `DO NOT USE THIS CVE RECORD` and the legacy `** REJECT **` —
**789 of 64,231 documents, 1.23%**, whose in-scope surface is **287 CVEs / 24,499
records**. That includes the 238 documents where SUSE shipped a fix anyway, whose
fixed-version data goes too: a rejected CVE ID is not a vulnerability.
`** DISPUTED **` and `** UNSUPPORTED WHEN ASSIGNED **` stay out — both are live
`PUBLISHED` records upstream, contested or end-of-life rather than withdrawn.

The marker lives in a note the provider was silently failing to read: SUSE puts the CVE
description in `document.notes` with `category: "description"`, not under the
vulnerability (where only some documents repeat it, as `category: "general"` titled
`"CVE description"`). `_description_for()` reads the document note, which is what enables
this check and what stops every record on this path shipping `Description: ""`.

## Fix dates

`FixedIn.Available` comes from `fixdate.Finder`, the same machinery the OVAL path uses, so
switching feeds doesn't drop the field; dates attach only to real fixed versions, since
the finder returns nothing for `"0"` and `"None"`.

**Neither SUSE feed dates a fix directly.** `remediations[].date` is empty in both
archives, and VEX's document-level date is unusable too: `tracking.initial_release_date`
is when SUSE's CVE page was created, and 52% of documents share one bulk-generation day.
OVAL is no better — 77% of its `<issued>` dates are the day SUSE regenerated the file.

The advisory archive (`csaf.tar.bz2`, one document per SUSE-SU) is the one place a real
date exists: there the document *is* one advisory, so `initial_release_date` is the day
those packages shipped. `csaf_advisory_client.py` indexes it two ways —
`(CVE, arch-stripped NEVR)` and NEVR alone — feeding hits to the finder as `advisory`
candidates; unmatched records fall back to first-observed. Always fetched: a fix date is
output, not an option. Costs a 188 MB download and a ~70s index build (~1.5M entries,
~0.9 GB peak). 185 documents are not valid UTF-8 and are decoded leniently rather than
skipped; every field the index reads is ASCII.

**58.48% of emitted fixed tuples get a real advisory date** — 50.70% from the precise
`(CVE, NEVR)` key, 7.78% from the NEVR-alone fallback.

**Two keys, because availability is a property of the build.** `(CVE, NEVR)` leaves 49%
unresolved, since SUSE routinely ships a build without listing every CVE it fixes; NEVR
alone asks when this build shipped at all, which is still exact, because a NEVR names one
build. Where both resolve they agree for **99.97%** of tuples, and in every disagreement
the NEVR date is *earlier*, never later — so the precise key stays primary and the
fallback only fills gaps, because letting it win would pull an attributed date backwards.
Looser keys are out: `(CVE, package name)` and CVE-alone measured 60% and 29% exactness.
Both keys omit the product deliberately, since advisories ship to
`...Module for Basesystem 15 SP6` where VEX records the base OS.

`attests()` reads **only** the CVE-keyed index, never the fallback — see "Choosing among
the fix categories" above. A build that shipped under some other CVE is exactly the
pre-fix GA build that rule exists to catch.

The remaining 41.5% is missing data, not a failed lookup: the cited NEVR appears nowhere
in the archive under any CVE. Two fifths of that bucket is SLES 16 GA builds that shipped
*as the base OS release* and so have no advisory; most of the rest is kernel subpackage
fan-out, where `recommended` names a current rebuild that postdates every advisory naming
the CVE. Keep the `"SUSE Linux Enterprise"` platform filter: the 0.15% of tuples it costs
come from openSUSE Tumbleweed and Leap, whose ship dates should never date a SLES fix.

Don't clamp the date to the CVE's own year. A clamp fires on 1,451 dated tuples (0.107%),
1,261 of them from the precise key, so it mostly second-guesses correct attributions — and
a CVE ID's year is its *assignment* year, not a lower bound on the fix: `CVE-2013-0160` on
`sles:11.1+ltss` is dated 2012-04-24 because SUSE's advisory really did ship
`kernel-pae-2.6.32.59-0.15.2` in April 2012.

## Vendor advisory attribution

CSAF's `remediations[]` doesn't attribute a fix to a specific advisory the way RHEL's
CSAF does: SUSE flattens every advisory that ever touched a CVE into one `vendor_fix`
entry, so nothing says which advisory shipped which package version. The parser instead
builds `VendorAdvisory.AdvisorySummary` from every `document.references` entry titled
`"Advisory link for <notice id>"`, attached uniformly to every `FixedIn` record for that
CVE — coarser than RHEL's per-advisory attribution, better than OVAL, which leaves
`VendorAdvisory` empty (`None`).

`advisory-map.csv.bz2` (SUSE's patchid → notice-id → URL mapping) proved unnecessary:
its `patchid` key appears in neither OVAL nor CSAF, its URLs are either derivable by
formula from the notice ID or already in `document.references`, and it doesn't solve the
per-advisory attribution problem either. `package2cpe.csv` too — CSAF already gives
explicit CPEs per product branch.
