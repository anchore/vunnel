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

Three `product_status` categories carry a fixed version, and they can name the same
(namespace, package) at *different* versions. `_choose_fix` picks one: **the lowest
version wins**, with one exception for a version no advisory ever shipped.

**Lowest, because `FixedIn.Version` is a boundary** — "installed below this is
vulnerable". Among versions all claimed to fix the CVE, the earliest is the true
boundary; a higher one reports already-patched installs as vulnerable. This replaced
`product_status` list order, which was arbitrary: `recommended` alone names one package
twice in **2,072** triples (`java-*`, `typelib-*`, `wireshark` and friends), and list
order picked a non-lowest version in **306** of them. All 306 now move down. Adding the
666 cross-category disagreements below gives 2,738 triples where a version has to be
chosen — see "Known limitation" for how many of those a single boundary cannot serve.

**Do not "fix" this by preferring `first_fixed`.** Per CSAF 2.0 `first_fixed` is the
first version containing the fix, which is exactly what a boundary wants — but SUSE's
data does not honour that, and the spec reading is a trap here. Corpus-wide, over
**2,326,075** (cve, namespace, package) triples:

| | triples |
|---|---|
| `recommended` only | 2,296,275 (98.72%) |
| `first_fixed` only | 28,895 (1.24%) |
| both, same triple | 905 (0.039%) |
| → versions agree | 239 |
| → versions disagree | 666 |
| disagreements where `recommended` is **higher** | **0** |

`recommended` is never above `first_fixed` anywhere in the corpus, so lowest-wins keeps
`recommended` in all 666 — the reorder changes nothing there. Cross-checking all 666
against SUSE's own advisory archive shows why that is right: where both builds are
attested, `recommended` shipped **earlier in 523**, `first_fixed` earlier in **none**,
median gap **64 days** (max 363). SUSE's `first_fixed` behaves like "a recent build known
to contain the fix", not "the first". Preferring it would push 613 records above the
build that demonstrably shipped the fix. `CVE-2024-9143` on `sles:15.7` is the shape:
`recommended` `0:3.2.3-150700.3.20`, `first_fixed` `0:3.5.0-150700.5.45.2`.

**`fixed` is dead.** Exactly **one** (document, vulnerability) in 64,231 populates it,
and it never survives scoping. Kept in the tuple because costing nothing beats
rediscovering it.

### The exception: an unattested version is not a fix

Lowest-wins alone leaves a residue. In **47** of the 666 disagreements only `first_fixed`
is attested — `recommended` names a pre-fix GA build that no advisory ever shipped for
that CVE — so the emitted boundary sits *below* the real fix and an unpatched install
compares as fixed. That is a false negative: 47 of 2,696,427 fixed records (**0.0017%**),
confined to `CVE-2025-38250` (24 kernel subpackages) and `CVE-2026-58221` (23
samba/ctdb/ldb subpackages), both on `sles:16.0`.

So a candidate that no advisory attests, beside one that is attested, drops out before
the version comparison. The evidence is already in hand: `SLESCSAFAdvisoryClient` indexes
`(CVE, NEVR) -> advisory date` for "Fix dates" below, and `FixDates.attests()` reads that
same index as evidence rather than as a date.

Two guards keep it from over-reaching, because advisory coverage is only ~58% and an
index gap must never raise a version:

- **Only across categories.** Competing versions inside `recommended` alone are parallel
  streams, not a spec disagreement, so attestation is never consulted there.
- **Only when attestation discriminates.** If every candidate is attested, or none is,
  the index says nothing and lowest-wins stands unchanged.

### Known limitation

A single `FixedIn` cannot express two parallel version streams, so where a SLES release
carries two, one boundary is wrong for one of them. **This affects 1,681 of 2,326,075
(cve, namespace, package) tuples — 0.072%, about 1 in 1,400** — and 1,681 emitted fixed
records.

A tuple is at risk when its candidate versions span more than one **upstream** version,
because release order then says nothing across the boundary: `2.11.1-6.40.1` being lower
than `2.24.0-8.20.1` does not make it a fix for anything in the `2.24.0` line. Of the
2,738 tuples where `_choose_fix` has to choose at all, 1,057 are rebuilds within one
upstream version (`0:2.22-100.8.1` vs `0:2.22-100.15.4`) where the lowest is simply
correct, and the remaining 1,681 are at risk. Every one spans exactly two streams, never
three.

`CVE-2024-35195` / `python-requests` / `sles:12.5` is the shape. SP5 carries `2.11.1-6.x`
and `2.24.0-8.x` side by side; `recommended` names `0:2.11.1-6.40.1` and
`0:2.24.0-8.20.1`; the emitted boundary is `0:2.11.1-6.40.1`. The corpus also ships
`2.24.0-8.14.1` and `2.24.0-8.17.1`, and an install of either sits above the boundary —
reported fixed — while being below its own stream's fix. Biggest contributors by tuple
count: `java-1_6_0-ibm` and `java-1_6_0-ibm-fonts` (282 each),
`typelib-1_0-WebKit2WebExtension-4_0` (212), `java-1_7_0-ibm-devel` (194), `wireshark`
(122), across 665 CVEs. 1,102 of the 1,681 (65.6%) are on `sles:11.*`, so most of the
exposure sits on releases long out of support.

Taking the highest instead would invert this into false positives for every install
patched on the lower stream — a larger set, and the direction this provider consistently
avoids. Fixing it properly needs several `FixedIn` records per package, which the OS
schema has no room for.

Note what this number is *not*. It counts tuples where the emitted boundary **cannot** be
right for both streams, not tuples where a scan will actually miss something: that also
needs a real build sitting in the unprotected window and someone running it. Narrowing it
further means arguing about whether a higher stream inherited the lower stream's fix,
which SUSE's data does not record — so 0.072% is the honest, checkable ceiling.

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

**This is the opposite of what this repo does for Ubuntu Pro/ESM, deliberately.**
Ubuntu's analogous rule (`ubuntu/README.md`, "Pro-only-fix → base wont-fix inference")
synthesizes a base **wont-fix** for any (CVE, source-package) Pro lists and base doesn't
— recording "base users won't get a fix" rather than copying Pro's fixed version down.
Canonical earns that by encoding the intent structurally: it *omits* the base ecosystem
from `affected[]`, so base's absence is itself the signal. SUSE's VEX has no equivalent
— a missing plain entry is just missing — and SUSE ships LTSS-track builds into
artifacts that report a plain CPE (point 2 below). Don't read the two providers as one
pattern; the data differs, so the inference does.

What justifies it:

1. **LTSS continues the same lineage longer; it isn't a fork.** SUSE's lifecycle page
   calls LTSS "the identical codebase", patches "backports to the original service pack
   version, not forward ports to newer versions" — so a version fixing a CVE on LTSS is
   evidence about that package's *code*, whichever channel ships it.
2. **Plain-CPE artifacts demonstrably carry LTSS-track builds.**
   `registry.suse.com/suse/sles12sp4` reports `cpe:/o:suse:sles:12:sp4` and ships
   `libpcre1-8.45-8.7.1`, published *only* under `12 SP4-LTSS` and `12 SP4-ESPOS` — no
   version-bearing `...Server 12 SP4:libpcre1-8.45-8.7.1` exists anywhere in the corpus.
   That artifact selects `sles:12.4`, where without borrowing the fix is unreachable.
   SUSE stops plain-track fixes once a SP passes general support, and 100% of the
   364,705-pair set above is past-general-support SPs, so this is the common shape rather
   than a one-off.

**What this section must not claim.** Earlier revisions asserted that a container image
can never be "on LTSS" and that no real scan selects `sles:X.Y+ltss`. Neither is
established, and the claim has crept back in more than once — it is not evidence, so
delete it again if it reappears. We have never examined a paid-LTSS image. syft reads
`/etc/os-release`'s `CPE_NAME`, so an LTSS-entitled artifact reporting an LTSS CPE would
be detected and the namespace selected normally; we simply don't know what one reports.
The OVAL parser's `_release_resolver` docstring says `sles-ltss-release` "is not
available as a container image", but that is an inherited assertion, not a measurement.
The rule stands on points 1 and 2 — code lineage, and one observed plain-CPE artifact
carrying an LTSS-only build — not on `+ltss` being unreachable.

`CVE-2022-1271` (`liblzma5`) is the measured quality-gate regression this fixed:
`recommended` only under `SUSE Linux Enterprise Server 12 SP4-LTSS`, no bare `12 SP4`
entry, so `sles:12.4` could never reach it — a labeled true positive a locally-built db
missed entirely.

Deliberately narrow:

- **One-directional (LTSS → plain).** No reverse borrow: there's no demonstrated false
  positive driving it, and the SP1 data showed real module/package-scope differences that
  way (see "Plain vs LTSS" above) that make a blind copy riskier.
- **Only real fixed versions cross** — never `known_not_affected` ("0") or won't-fix
  ("None").
- **Never overrides a real plain answer**: a plain fixed version or `"0"` wins, even
  where the versions disagree.

**A plain `"None"` it does override.** The rule used to skip any package plain had any
entry for, including a bare `known_affected` → `"None"` — wrong in the direction that
produces false positives. Once a SP leaves general support SUSE stops plain-track fixes
but leaves the `known_affected` line standing, so a plain `"None"` there describes
*which channel ships the RPM*, not whether the code is fixed; every such namespace is a
past-general-support SP. Three concrete supports:

1. **`known_affected` isn't reliable as "no fix available"**: in a 1,500-document sample
   SUSE names the same package both `known_affected` and fixed *within one namespace* in
   4.3% of cases (632 of 14,555) — the staleness the source-named rule below cleans up.
2. **SUSE's own plain-CPE images ship LTSS-track builds** — the `sles12sp4` /
   `libpcre1-8.45-8.7.1` artifact in point 2 above. "No fix available on the plain
   channel" isn't even true of the thing being scanned.
3. **`"None"` is stronger than "unavailable to you"**: *no version fixes this; every
   version matches, no comparison performed.* `CVE-2017-6004` and `CVE-2019-20838` gave
   `libpcre1 → "None"` on `sles:12.4` with the fix on `-LTSS` at 8.45-8.7.1 — flagging
   the installed 8.45-8.7.1, which *is* the fix. Siblings `CVE-2017-7245`/`7244`/`7186`
   were right only because plain had no `known_affected` line.

**The cost, stated precisely.** "Fixed on LTSS only" *is* expressible — that's what
`sles:X.Y+ltss` is for, and the fix lands there either way. What a `+ltss`-only record
cannot do is say anything to a plain scan: `sles:12.4` would carry no record at all, so
an unpatched plain install comes back clean. That is the alternative being rejected, and
it is a false negative.

It's rejected because an LTSS-only listing is sometimes a reporting artifact rather than
a distribution fact. SUSE publishes `libpcre1-8.45-8.7.1` only under `12 SP4-LTSS` and
`12 SP4-ESPOS`, yet that exact NVR ships inside `registry.suse.com/suse/sles12sp4`, which
reports a plain CPE (point 2 above). Some fixes SUSE reports as LTSS-only are present on
plain builds, so confining the record to `+ltss` hides a fix that is really there.

So the trade is deliberate and worth saying plainly: **we would rather sometimes
advertise a fix that turns out to be paywalled than emit a false negative.** A paywalled
fix is a wrong remediation hint on a finding that is otherwise correct; the alternatives
are a `"None"` that calls an already-patched install vulnerable, or silence on a plain
scan that really is exposed.

It's also not a regression. The OVAL path never distinguished the tracks at all:
`_release_resolver` collapses every release name into one namespace per version,
preferring `sles-release` but falling back to `sles-ltss-release` — so where only LTSS
data existed, OVAL already published it under the plain namespace, with none of the
guards above. This provider makes the same assumption, more narrowly.

Over a random 6,000-document sample (9.3% of the corpus) this converts **986 plain
`"None"` records across 117 CVEs**, concentrated in `sles:12.5` (222), `sles:15.6` (179),
`sles:15.4` (164) and `sles:12.4` (155).

The `"0"` boundary is deliberate and asymmetric: a plain `"0"` is an explicit
`known_not_affected` determination, so borrowing over it would invert SUSE's own "never
vulnerable there", match every plain version *below* the borrowed one and manufacture
the false positives this change removes. A 3,000-document sample found 442 real (plain
`"0"`, LTSS fixed) pairs, so this is load-bearing.

**Known limitation.** Some "LTSS fixed, plain absent" pairs are LTSS-only content never
meant to infer about plain — kernel live-patches (`kgraft-patch-*`), old LTSS-specific
repackagings — ~4.3% of qualifying pairs corpus-wide. Filtering precisely needs
cross-document knowledge (does this package exist *anywhere* on plain SLES) unavailable
one document at a time: a conscious tradeoff, not an oversight — revisit if it proves to
matter.

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

SUSE keeps publishing affected/fixed data for these. `CVE-2023-45918`'s description
reads `"DO NOT USE THIS CANDIDATE NUMBER. ... This candidate was withdrawn by its CNA.
Further investigation showed that it was not a security issue."`, yet the document lists
**616 `known_affected` products, 425 fixed** and three advisories
(`SUSE-SU-2024:1132-1`, `1133-1`, `1133-2`), with nothing retracting it
(`tracking.status` `interim`, no `flags`, `impact: low` its only `threats` entry).
**CSAF 2.0 has nowhere to encode it**: `document/tracking/status` is
`enum: ["draft", "final", "interim"]`; `vulnerabilities[].flags[].label` only justifies
*not affected* (`component_not_present`, `vulnerable_code_not_present`, …), never *not a
vulnerability*. It is machine-readable one level up (`cveMetadata.state: "REJECTED"`,
`dateRejected`, `rejectedReasons`), which SUSE mirrors as prose — all this feed has.

**Matching prose is the wrong layer; this is deliberately the cheap fix.** The
principled version reads `state: "REJECTED"` off the CVE List / NVD data once, for every
provider; a rule inside one provider reaches only vendors who mirror MITRE's sentences,
hence SLES-only. No central filter exists today — the `nvd` provider carries
`vulnStatus` without branching on it; the nearest precedents are vendor-sourced
(`ubuntu/os_downconvert.py` drops OSV records with a real `withdrawn` field,
`alpine/rejections.py` reads Alpine's NAK list). **Revisit this section if a central
filter ever lands: this rule should be deleted, not maintained.** Tolerable meanwhile:
MITRE-generated boilerplate, stable 20+ years; anchored to
`document.notes[category="description"]`, so a phrase in a reference summary can't trip
it; 40 documents sampled against `cvelistV5` came back **40/40 at `state: "REJECTED"`**.

MITRE has several rejection wordings and SUSE mirrors all of them, so the best-known
phrase alone catches only a bit over half:

| Marker (matched case-insensitively) | Documents |
|---|---|
| `DO NOT USE THIS CANDIDATE NUMBER` | 447 |
| `has been rejected or withdrawn` (the modern CNA wording) | 312 |
| `DO NOT USE THIS CVE RECORD` (duplicate-reservation rejections) | 27 |
| `** REJECT **` (legacy prefix) | 35 |
| **union, deduped** | **789 of 64,231 (1.23%)** |

The first two barely overlap — one document carries both. A random 120-document sample
of *non*-matching documents turned up 2 `REJECTED` upstream (`CVE-2023-52802`,
`CVE-2024-40946`), both using the CNA wording the union now covers; 2/120 ≈ 1.7% against
1.23% corpus-wide suggests the set is near complete. `** DISPUTED **` (4 documents) and
`** UNSUPPORTED WHEN ASSIGNED **` (8) stay out: live `PUBLISHED` records upstream —
disputed means contested, not withdrawn, and unsupported-when-assigned is a real
vulnerability in already-end-of-life software.

Of the 789, **475 produce in-scope SLES records**, 188 of those only `"0"` (harmless —
`"0"` can't cause a report). Real surface: **287 CVEs / 24,499 records** across 38
namespaces, **19,528** fixed versions (reported below the fix) and **4,971** `"None"`
(reported at *every* version), including `CVE-2023-45918` on `sles:15`. It also discards
SUSE's fixed-version data for the 238 documents where SUSE shipped a fix anyway — right,
since a rejected CVE ID is not a vulnerability.

The marker lives in a note the provider was silently failing to read: SUSE puts the CVE
description in `document.notes` with `category: "description"` — all 447 "CANDIDATE
NUMBER" documents carry it there, only 270 repeat it under the vulnerability as
`category: "general"` titled `"CVE description"`. The parser scanned `vuln.notes` for
`category == "description"`, matching nothing real, so every record here shipped
`Description: ""`. `_description_for()` now reads the document note, enabling the
rejection check; zero of the 64,231 documents have an empty one, so the
`"CVE description"` fallback never fires.

## Fix dates

`FixedIn.Available` comes from `fixdate.Finder`, the same machinery the OVAL path uses,
so switching feeds doesn't drop the field; dates attach only to real fixed versions,
since the finder returns nothing for `"0"` and `"None"`.

**Neither SUSE feed dates a fix directly.** `remediations[].date` is empty in both the
VEX and advisory archives, so a document-level date is the finest granularity available
— and in VEX even that is unusable: `tracking.initial_release_date` is when SUSE's CVE
page was created, and 52% of documents share one bulk-generation day (`2023-02-15`).
OVAL is no better: 77% of its `<issued>` dates are the single day `2022-09-02`, when
SUSE regenerated the file.

The advisory archive (`csaf.tar.bz2`, one document per SUSE-SU) is the one place a real
date exists: there the document is one advisory, so `initial_release_date` is the day
those packages shipped. `csaf_advisory_client.py` indexes it as
`(CVE, arch-stripped NEVR) -> earliest release date`, feeding hits to the finder as
`advisory` candidates; unmatched records fall back to first-observed. Always fetched --
a fix date is output, not an option. Over 1,500 real documents **58.2% of in-scope SLES
fixed records get a real advisory date** (37,799 of 64,894), at a 188 MB download and a
~70s index build holding ~1.4M entries (~0.9 GB peak).

Three implementation details:

- **The key omits the product deliberately**: advisories ship to
  `...Module for Basesystem 15 SP6` where VEX records the base OS, so an exact
  `(CVE, product, NEVR)` key resolves far fewer tuples; where both resolve, they agree
  99% of the time.
- **The remaining ~42% is not a matching bug**: VEX's `recommended` is the *currently
  shipping* rebuild, not the build that first fixed the CVE, so after a rebuild no
  advisory ships that NEVR. Looser keys (`(CVE, package name)`, CVE alone) reach 87% or
  99% coverage at 60% and 29% exactness, tail errors over a decade wide — worse than no
  date.
- **185 advisory documents are not valid UTF-8** (latin-1 bytes in prose), decoded
  leniently, not skipped; every field the index reads is ASCII.

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
