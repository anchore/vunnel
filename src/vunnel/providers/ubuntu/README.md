# Ubuntu provider

## Overview

This provider ingests Canonical's OSV and OpenVEX feeds, walked one CVE at a
time, to get vulnerability data about Ubuntu.

**Which releases come from where.** Canonical's archives currently name every
LTS release from trusty (14.04) onward at whichever support tier is still
current for it — base while supported, the `esm-infra`/`esm-apps` pockets
after — plus the two most recently added releases, questing (25.10, an
interim) and resolute (26.04, the next LTS). Those are built per CVE straight
from the feeds. Everything else is served instead from the frozen tracker
snapshot in `input/normalized-cve-data/` through the legacy passthrough: the
interim releases from precise (12.04) through mantic (23.10), none of which
ever appeared in OSV or OpenVEX, and oracular (24.10) and plucky (25.04),
which the feeds still name today but only as the residue Canonical's own sweep
of those two releases left behind — a record naming either one in the feed is
refused, on every channel, rather than trusted. See "The hosting promise, and
its two exceptions" below.

Even restricted to the releases the feeds do cover, that data is incomplete in
5 ways:

1. It does not cover Ubuntu versions that no longer receive any support
2. It does not mark CVEs as "won't fix" when Canonical has decided not to
   publish a fix.
3. It does not report when a fix became available
4. It does not list vulnerabilities for packages in base Ubuntu that are only
   fixed in ESM.
5. It cannot say that a package is *not* vulnerable. Its `affected[]` lists
   what is affected, so a package Canonical has cleared is simply absent,
   which is indistinguishable from one nobody has looked at yet.

To work around the first limitation, this provider relies on the
`normalized_cve_data` directory written into the cached workspaces by previous
versions of the provider, which cloned down the ubuntu-cve-tracker git repo and
examined the history to learn what the vulnerable status of packages in EOLed
Ubuntu versions was before it was removed.

To work around the second and the fifth, this provider also downloads
Canonical's OpenVEX feed and reads its statements beside the OSV record for the
same CVE. They are the more complete statement of which packages a CVE affects
in a release, so what is emitted for a release is the union of its OSV records
and its statements: won't-fix rules out an advisory, a confirmed-not-vulnerable
assertion is stated as such, and a package only the statements name becomes a
finding with no fix version.

To work around the third limitation, this provider builds an in-memory
overlay from the USN records in the OSV tarball (`osv/usn/**`) — each USN's
top-level `published` field is the moment Canonical pushed the patched
package to the archive, i.e. the real fix-ship date. The overlay supplies
this as a high-confidence candidate to the fix-date finder so that, e.g.,
turning on Pro ingestion doesn't make every Pro fix look like it shipped
today (which is what the legacy "first-observed in grype-db" heuristic
would record on the first build to see Pro data). The grype-db-observed
fix-date cache remains the fallback for the ~23% of fix tuples that don't
have a matching USN entry (FIPS / Realtime / Nvidia-BlueField tiers don't
ship via USN).

To work around the fourth limitation, this provider infers the existence of a
"wont-fix" record for packages that are fixed in Ubuntu Pro but not mentioned
in regular Ubuntu of the same version number.

Canonical has confirmed (2026-09-16) that its `osv-all.tar.xz` and
`vex-all.tar.xz` archives will keep hosting every release from questing
(25.10) on indefinitely, in its last good state, with end-of-life marked
additively rather than by removal. So this provider holds no last good state
of its own: what it emits is what the day's download says, plus the frozen
snapshot for the releases the download does not name.

All three sources are keyed by CVE — the OSV feed is one record per CVE, the
OpenVEX feed one document per CVE, and the snapshot one file per CVE — and
assembling what a release says about a CVE means seeing all three at once. So
the run walks CVEs:

1. Both archives are downloaded and each is streamed exactly once, reducing
   every document to a compact row keyed by CVE in a scratch file under
   `input/`, with the byte range of each row kept in memory.
2. The union of the three key sets is walked in order. For each CVE its two
   rows are read back by offset and its snapshot file opened, and every
   release the feed speaks for produces one disposition per source package.
3. Every release the feed does not speak for is emitted from the snapshot by
   the passthrough that has always served the pre-OSV releases.

Two releases, 24.10 (oracular) and 25.04 (plucky), were swept by Canonical
before this hosting promise was made and the feed still carries the residue.
See "The hosting promise, and its two exceptions" below for how those two are
refused.

## Data sources

The provider reads three things, in priority order:

| Source | URL / path | Role | Lifecycle |
|---|---|---|---|
| OSV CVE feed (`osv/cve/**`) | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` | Authoritative ranges + fix versions for currently-tracked releases | Streamed each run into `input/osv-rows.tsv`, one row per CVE, rewritten from the archive every run; never extracted to disk |
| OSV USN feed (`osv/usn/**`) | same tarball | Authoritative fix-ship dates (USN.published) — see "USN fix-date overlay" below | In-memory index built each run from the same pass; not persisted |
| OpenVEX feed | `https://security-metadata.canonical.com/vex/vex-all.tar.xz` | Which packages a CVE affects in a release, fix disposition, and confirmed-not-vulnerable assertions — see "Why VEX" below | Streamed each run into `input/vex-rows.tsv`, one row per CVE, rewritten from the archive every run |
| `input/normalized-cve-data/` | local | Releases absent from the feeds above, and what neither feed states for the ones present | Frozen; populated by the v3 provider, kept untouched after v3's removal; read one file per CVE during the merge |
| (fix-date cache) | `input/grype-db-observed-fix-dates.db` | Cross-provider fallback for fix dates when no USN advisory shipped the fix | Refreshed each run |

`normalized-cve-data/` covers every release the v3 provider ever tracked, not
only the ones that were already EOL at the cutover. Which releases it actually
serves is decided per run by which base releases today's OSV download names, so
a release that leaves the feed moves onto this path on the next run — as do
24.10 and 25.04, which the feed still names and which are refused.

USN records are **not emitted** as their own records — the previous provider
didn't surface them either. They're used purely as a metadata source: the
USN→CVE join supplies real fix-ship dates that the CVE records themselves
don't carry. Emitting USN-keyed advisories alongside CVE entries is a
possible future enhancement.

## Output: one OS-schema record per namespace and CVE

```
data/ubuntu/
  input/
    osv-all.tar.xz                # today's download (overwritten each run)
    vex-all.tar.xz                # today's download (overwritten each run)
    osv-rows.tsv                  # one distilled row per CVE (overwritten each run, a gigabyte either way)
    vex-rows.tsv                  # one distilled row per CVE (overwritten each run, a gigabyte either way)
    normalized-cve-data/          # frozen tracker snapshot, load-bearing
    grype-db-observed-fix-dates.db
  results/
    results.db                    # OS-schema output
```

That is everything this provider reads or writes under `input/`. A workspace
built by an earlier version of it can still carry `ubuntu-cve-tracker/`,
`distro-info/`, `fragments/`, `vex-fragments/` or `tracker-index/` from
before the walk-by-CVE rewrite; `_clean_input` deletes each one, once, the run
it first finds it, and nothing here writes any of them again. It also sweeps
`*.part` — the staging file `http.download_to_file` renames onto an archive
once the transfer finishes. A run killed mid-download never reaches that
rename and never reaches the helper's own cleanup either, so ~100 MB would
otherwise sit in an `input/` that nothing else clears.

Every record is the v3 `{"Vulnerability": {...}}` OS shape, whichever source
decided it, and its identifier is `{namespace}/{cve-lowercase}`, e.g.
`ubuntu:20.04/cve-2024-1234`. A base release is `ubuntu:X.YY`; plain Ubuntu Pro
(ESM) is the `ubuntu:X.YY+esm` distro channel.

The namespace is the release's canonical identity rather than the literal
ecosystem string. Canonical appends `:LTS` when a release reaches general
availability, so `Ubuntu:26.04` and `Ubuntu:26.04:LTS` are one release
published under two names over its life, and records written before the rename
would otherwise be stranded under a namespace of their own. Genuinely different
things stay separate: `Ubuntu:20.04:LTS`, `Ubuntu:Pro:20.04:LTS` and
`Ubuntu:Pro:FIPS:20.04:LTS` are three identities.

### Why the walk is by CVE

Every source is already keyed by CVE, and a release's answer for one CVE needs
all three of them at once: the OSV record for the fix versions, the statements
for what is and is not affected, and the snapshot for what neither feed states.
A release-major walk has to hold one release's worth of all three to do the
same job, which is what a re-encoding of both feeds into per-release SQLite
bought — 12 GB of it for a 100 MB download.

Neither archive can be read any other way. Both are single-block xz streams
whose members are not in path order, so reaching a member by name decompresses
everything before it, and a merge join over the two as they arrive is
impossible: the OSV record and the VEX document for one CVE sit at unrelated
positions. Extracting the JSON to disk would give the filesystem as an index,
at 33 GiB for the two feeds.

So each archive is streamed once and each document reduced to the fields the
output needs, written as `<cve>\t<json>` with the byte range of each row kept
in memory. There are tens of thousands of CVEs per feed, so the index is small
and the union of the key sets is sorted in memory — no external sort, and the
snapshot is already one file per CVE.

### Why channels stay separate from the base release

Today's tarball publishes 32 distinct ecosystems:

- Base: `Ubuntu:14.04:LTS` through `Ubuntu:26.04:LTS`, plus interim
  releases like `Ubuntu:25.10`
- Subscription tiers: `Ubuntu:Pro:18.04:LTS`,
  `Ubuntu:Pro:FIPS-updates:20.04:LTS`,
  `Ubuntu:Pro:Realtime:22.04:LTS`, `Ubuntu:Nvidia-BlueField:22.04:LTS`,
  etc.

Plain Pro is emitted as its own `+esm` channel rather than collapsed into the
base release, because the two have different fix policies and different CVE
coverage and downstream is expected to gain subscription-tier-aware matching.
The sub-tiers map to no namespace at all: their builds diverge from base, so
their fixes cannot resolve a base disclosure.

## Per-run flow

```
Provider.update()
 └─ Parser.get()
      ├─ _clean_input()            # remove input state nothing reads any more
      ├─ _download_archive()       # stream osv-all.tar.xz to disk
      ├─ _download_vex_archive()   # stream vex-all.tar.xz to disk
      ├─ fixdater.download()
      ├─ _read_osv_archive():
      │     one pass over osv-all.tar.xz:
      │       osv/usn/**  → the (eco, pkg, fix-ver) → USN.published overlay
      │       osv/cve/**  → one row per CVE into input/osv-rows.tsv
      │                     (id, severity, published, the CVE-program rejection
      │                      as a boolean, one entry per affected[] element
      │                      reduced to ecosystem, package, purl, fix versions)
      │                   → and the set of base releases the feed speaks for
      ├─ _read_vex_archive():
      │     one pass over vex-all.tar.xz:
      │       vex/cve/**  → one row per CVE into input/vex-rows.tsv
      │                     (token, package, disposition), source products only,
      │                     the won't-fix prose match applied once
      ├─ yield from _iter_normalized_cve_data()   # the snapshot passthrough first
      └─ yield from _iter_merged()                # the merge last
            for each CVE in sorted(osv rows | vex rows | snapshot files):
              skip it whole if the CVE program rejected it
              for each base release the feed speaks for:
                1. the release's own OSV entries, which carry the fix versions
                2. the statements at any token of the release
                3. the snapshot's own rows
                4. the Pro-to-base inference, for a package only the
                   extended-support build names and nothing above spoke about
                5. the snapshot's extended-support clearances
                then a fix date per fix version, and one FixedIn per package
              for each plain-Pro slice: the `+esm` channel, fixes only
```

Emission order is policy-only with one exception: a release the feed carries an
extended-support build of and no base data for is spoken for by both the
passthrough and the merge, and the merge's record — which has seen every
source — is the one written last.

Each source package on a namespace becomes one of four things:

| disposition | FixedIn |
|---|---|
| researched not-affected | `Version: "0"`, `NoAdvisory: false`, and nothing else for the package |
| one or more fix versions | one entry per version, plus its fix date in `Available` |
| no fix, won't fix | `Version: "None"`, `NoAdvisory: true` |
| no fix, not stated as won't fix | `Version: "None"`, `NoAdvisory: false` |

Nothing is cached between a feed and a record, so an improvement to the
fix-date data, to the prose match that decides won't-fix, or to how a statement
is read reaches every record on the next run without anything upstream having
to change.

## Pro-only-fix → base wont-fix inference

Canonical encodes "this CVE will only be fixed in Pro/ESM, not base
Ubuntu" by **omitting the base ecosystem** from the OSV record's
`affected[]` while listing the Pro tier. E.g. CVE-2018-20796 lists
`Ubuntu:Pro:20.04:LTS / glibc` but no `Ubuntu:20.04:LTS / glibc` — the
intent is "base focal users won't get a fix; only Pro subscribers
will." v3 captured this via `status: ignored` on base in the tracker;
OSV drops the signal entirely.

For each release, once the record's own entries are in hand, any source
package the plain-Pro slice names (`Ubuntu:Pro:X.YY:LTS` only — see below) and
the base slice does not becomes a base wont-fix entry. Both halves of the
record are read together, so there is no pairing step to get wrong.

**Why only plain Pro, not FIPS/Realtime/Nvidia-BlueField:** plain Pro
packages are byte-identical to base packages while base is supported,
then diverge via ESM-backported patches — same vulnerable code, so the
inference is sound. FIPS rebuilds specific packages against
FIPS-validated cryptographic modules (different crypto code paths);
Realtime is the PREEMPT_RT kernel (different locking/scheduling code);
Nvidia-BlueField is a separate SmartNIC OS. A CVE in those builds
doesn't reliably imply the same CVE on base, so we don't infer from
them.

**It reaches a release the feed has stopped carrying base data for.**
Base 24.04 eventually drops out of the feed while Pro:24.04 is still tracked,
and a new CVE gets a Pro-only fix. The inference still puts the disclosure in
`ubuntu:24.04`, because it reads the Pro slice of the record it has in hand
rather than anything held over from a previous run. What it cannot supply is
the release's own data, and that is the snapshot's job: a release the feed
names no base build of is served by both, and the passthrough fills in what
the inference has no access to.

**Both a statement and a snapshot row outrank it, by running first.** The
inference is applied last among the five steps that decide a package —
after the release's own OSV entries, the VEX statements at any of its
tokens, and the frozen snapshot's rows — so it only ever fills a package
none of them has an opinion about. There is nothing here for it to
correct: everything else on a package is something Canonical said about
it on that release, this alone is concluded from an omission, and running
last means a real answer is never something the inference has to be told
apart from. The one thing it still asks explicitly is whether the release
shipped the package at all: an inferred package carries no `purl` of its
own — the Pro entry's names a Pro pocket — so a statement that the
release never shipped it has to be looked up at the base codename by
hand, or the pass silently does nothing while appearing to work.

The guess is a good one, which is why it is made at all: where VEX can speak to
an inferred package the two agree about 98.5% of the time. Running the inference
last means the other 1.5% is decided by the vendor rather than by precedence
rules.

## USN fix-date overlay

Canonical's OSV CVE records don't carry per-fix dates — the record's
top-level `published` is the *vulnerability* disclosure date, often
months or years before the fix actually shipped. VEX doesn't help either:
spot-checked against real records, statement timestamps on `status:
"fixed"` entries are CVE-publish dates, not fix-ship dates (e.g., a
chromium 65 fix carries a timestamp from 2012).

The fix-ship date lives in the USN's top-level `published` field. Real
example: CVE-2023-38545 (curl) → USN-6429-1 published `2023-10-11T11:34:51Z`,
which is the public coordinated disclosure date.

The overlay is built out of the same single pass over `osv-all.tar.xz` that
distils the CVE records — a single-block xz stream costs a full decompression
per traversal, and one is enough — and is an in-memory index keyed by
`(ecosystem, source-pkg, fixed-version) → earliest USN published date`. When
the merge dates a fix version, the overlay's date is supplied as a
high-confidence (`accurate=True`) candidate to `fixdater.best()`, which beats
first-observed when both are present. The grype-db-observed first-observed
cache remains the fallback.

**Why this matters now**: when we add Pro ingestion (or any data shape
v3 didn't carry), the grype-db-observed cache won't have history for the
new rows. Without the USN overlay, those fixes would all date to the
first build that captured them — i.e., "the day we turned on Pro." With
the overlay, we read the real fix-ship date out of the USN that shipped
it, regardless of how long ago.

**Coverage** measured against today's full tarball: 77% of CVE fix
tuples have a matching USN tuple overall. Plain-Pro coverage runs
88–100% across all releases — exactly the regime the cutover stresses.
FIPS-updates / Realtime / Nvidia-BlueField have low USN coverage (those
tiers ship through non-USN channels); they fall through to first-observed
without regression. The 23% USN-miss case has no impact vs. the prior
behavior — the overlay only adds dates, never removes them.

**Date precedence inside `fixdater.best()`**: candidates with
`accurate=True` are upper-bound filters; the most-accurate, earliest
remaining candidate wins. The USN overlay's `(date, kind="advisory",
accurate=True)` candidate beats first-observed when both are present and
beats CVE.published (which is `accurate=False`) unconditionally.

## Why OpenVEX (not just OSV)

Canonical's OSV publication intentionally collapses six tracker
statuses into one shape:

| ubuntu-cve-tracker status | OSV representation |
|---|---|
| DNE, not-affected | (absent from `affected[]`) |
| released | `affected[]` with `fixed:` event |
| **needs-triage, needed, ignored, pending, deferred, in-progress** | **`affected[]` with `events: [{"introduced": "0"}]` — indistinguishable** |

Documented at
[documentation.ubuntu.com/security/security-updates/osv/](https://documentation.ubuntu.com/security/security-updates/osv/).
The collapse loses the "won't fix" signal — a single sentinel `affected`
entry could mean Canonical is still triaging or has decided not to
patch.

The same data in OpenVEX preserves granularity. For `status: "affected"`,
the `action_statement` field uses four canonical opening phrases:

```
"...decided to not fix it..."        → wont-fix (ignored, won't patch)
"...is no longer supported..."       → wont-fix (EOL flavor)
"...needs fixing"                    → not-fixed (will be patched eventually)
"...needs fixing, and...actively..." → not-fixed (active work)
```

VEX also carries `not_affected` — a positive assertion that a package in
a release is not vulnerable — which OSV cannot express at all: its
`affected[]` lists what is affected, so a package Canonical has cleared is
simply absent, indistinguishable from one nobody has looked at.

The provider reduces each document to one row per CVE holding
`(token, source package, disposition)` for every `arch=source` product. Only
source products are read: Canonical repeats each statement across every binary
architecture with the same disposition, the OSV side keys on source packages
too, and reading only those cuts the row count by about an order of magnitude.
The prose match that separates "decided not to fix" from "needs fixing" is
applied once, as the archive streams past, because every statement is read
exactly once in this shape. A `fixed` statement makes no row at all: the
version on its product URL is not the version that fixed the CVE, so it has
nothing left to state.

What is emitted for a release is the union of those rows and its OSV entries,
per `(cve, source package)`. Won't-fix sets
`FixedIn.VendorAdvisory.NoAdvisory = true`, which the grype v6 transformer
renders as `WontFixStatus` and users see as `(won't fix)`. `not_affected`
splits on its justification. `vulnerable_code_not_present`, or no
justification at all, is a researched conclusion about a package the release
ships: the package becomes a `FixedIn` version of exactly `"0"`.
`component_not_present` says the release does not ship
the package — the tracker's `DNE`, which this provider has never emitted
anything for — so the OSV entry is dropped and nothing takes its place. A
package only the statements name is added: `affected` and
`under_investigation` as a finding with no fix version, a justified
`not_affected` as the `"0"`, and `fixed` and `component_not_present` as
nothing at all.

The `"0"` is not a version comparison. The grype v6 OS transformer reads a
package group whose every `FixedIn` version is exactly `"0"` as an
unaffected package, and writes it as a row that cancels what another source
reports for the same package rather than as a match; a group mixing a `"0"`
with anything else falls through to a `< 0` constraint instead. So the
assertion replaces the entry it contradicts rather than sitting beside it,
and it is what the tracker-cache passthrough has always emitted for a
`not-affected` package.

A clearance at any token of the release states it, the release's own archive
or an extended-support pocket (`esm-infra/focal`, `trusty/esm`), and it
outranks everything else said about the combination — an OSV `fixed` event,
an OSV entry, the release's own `affected` statement, the Pro-to-base
inference and the tracker row. Canonical publishes the conclusion against
whichever pocket it was doing the work for, and the same team maintains both
builds of the package; a base release saying `needs-triage`, or saying
nothing, is an absence of research rather than a contradiction. The pre-OSV
provider made the same call.

A *finding* does not travel that way: only a release's own archive can put
one in its namespace, because a pocket states what is true of its own
rebuild. `fips`, `realtime`, `bluefield` and `ros-esm` tokens map to no
output namespace and say nothing anywhere. The two sets are
`_POCKETS_THAT_ASSERT` and `_POCKETS_THAT_ASSERT_FINDINGS` in
`vex_overlay.py`. The `+esm` channel carries fix versions only and never a
`"0"`.

The clearance is read before the fix events for a reason worth knowing:
Canonical's OSV generator re-encodes a tracker `not-affected (<version>)`
row as a range fixed at that version, byte-identical to a real fix, so an
entry can carry both a fix event and a clearance. Reading the events first
let the encoding win and put the package back below a boundary it was never
under — 25 false positives on one image in a single quality-gate run.

`under_investigation` is read and deliberately changes nothing: it means
"not yet determined", which this provider has emitted as
vulnerable-with-no-fix since long before it read OSV.

The join key is the PURL `distro=` qualifier (e.g. `distro=noble`,
`distro=esm-infra/jammy`). Both OSV and VEX embed it identically, with one
exception: the oldest ESM pocket is written both `trusty/esm` and
`esm-infra-legacy/trusty`, on both sides, so the two spellings are folded
onto one key before the lookup.

No version is ever taken from a VEX statement. The `@version` on a
product URL is the package's current version in that pocket, not the
version that fixed the CVE. A statement decides whether a package is
affected; the OSV record beside it decides what version fixed it, which is
why a `fixed` statement with no OSV record behind it states nothing.

## The hosting promise, and its two exceptions

Everything above rests on one claim Canonical made to us directly, not on
anything published: on 2026-09-16, Canonical told us that its `osv-all.tar.xz`
and `vex-all.tar.xz` archives will keep hosting questing (25.10) and every
later release indefinitely, in their last good state, with end-of-life marked
additively in OSV and OpenVEX rather than by removing the release. So nothing
here freezes and nothing is held over: what a release gets is what today's
download says about it, whatever its support status. There is no calendar, no
clock and no `now` anywhere in this provider.

A release the download does not name is served from the frozen snapshot
instead, which is also what happens the day Canonical splits the archive into
a "live" tarball and an "old" one, if it ever does. Adding the second URL is a
second pass over the same distil step, writing into the same rows.

The promise has a hole this provider cannot close by itself: nothing here
would notice a release that simply stops being named at all, in either
archive, with no snapshot behind it to fall back to and no announcement like
the one above. That release would quietly stop being emitted until someone
adds wherever Canonical moved it as a second URL. The backstop is
`tests/quality/config.yaml`'s `expected_namespaces` list for this provider,
which names every Ubuntu namespace from 12.04 through 26.04: the quality gate
fails the day one of them stops showing up, which is the alarm this provider
has no code-level equivalent of.

What the promise does not cover is what happened before it was made.
24.10 (oracular) and 25.04 (plucky) were swept by Canonical in 2025 and
2026, and what the feed carries for them now is the residue the sweep left
behind — a husk of a few hundred mostly-withdrawn records that never gets
regenerated. Nothing in the archive distinguishes that husk from a healthy
release that is merely out of support, so the two are named explicitly in
`_KNOWN_HUSK_RELEASES` and refused: no record is emitted for either from the
feed, on any channel, and neither is counted among the releases the feed
speaks for, so the snapshot serves them instead. A VEX codename the version
table does not know is read, not refused.

Nothing else is refused and nothing is decided by a threshold: a release
past its published end-of-life date is read like any other, which is the whole
point of the promise above.

## Why `normalized-cve-data` is still load-bearing

Live VEX has **the same coverage gap as live OSV**: only currently-
tracked releases are present (jammy, noble, focal, bionic, trusty/ESM,
xenial/ESM, questing, resolute, plus Pro/FIPS/etc.). Releases that were EOL
before Canonical's OSV/VEX feeds launched — precise, quantal, raring,
saucy, utopic, vivid, wily, yakkety, zesty, artful, cosmic, disco,
eoan, groovy, hirsute, impish, kinetic, lunar, mantic — are absent.

The v3 provider's `normalized-cve-data/` cache covers every release the
tracker knew about, not only those (it was populated from
`ubuntu-cve-tracker` git history before v3 was retired). The new provider
reads it via the vendored `map_parsed` from `parser_legacy.py` and emits
OS-schema records for every release today's OSV download does not name a base
build of — so it also serves 24.10 and 25.04, which the download does name and
which are refused because what it names is post-sweep residue.

`normalized-cve-data` records carry `status: "ignored"` directly, which
`map_parsed` already converts to `FixedIn[].VendorAdvisory.NoAdvisory =
True` — grype's OS transformer renders this as `WontFixStatus`. So the
EOL slice already preserves won't-fix without any VEX involvement; the
overlay only matters for the OSV path.

### It is also the third source for releases the feeds do carry

Canonical lists a package under a release in OSV only while it means to keep
tracking it there, and when it stops, the fix version goes with it: 3,727
`(release, CVE, package)` combinations lost a real fix version that way and
1,197 records were left naming no fix at all. The snapshot holds the same
version for every one of them, byte for byte, and holds won't-fix rows for
CVEs the OSV feed never carried.

So it is read for every release, not only the ones the feeds have dropped. It
is already one file per CVE, which is the key the merge walks, so the file is
opened when that CVE comes round and closed again — there is nothing to
transpose and no index to build. `DNE` rows are dropped on the way in — 16.9
million of the 20.7 million — since they say the release never shipped the
package and there is nothing to emit for that.

It also holds a clearance the statements do not. A base release row that is an
absence of research — `needs-triage` — standing next to an ESM pocket in
`ignored_patches[]` that researched the same source package and concluded the
vulnerable code is not there is not a contradiction, and the research wins. It
is the same claim a `not_affected` statement at that pocket makes, read out of
Canonical's other file for the combinations where there is no statement to read
it out of at all. It is not given the same weight: the statement is current and
measured and overwrites a fix version, this one is neither and backs off where a
version is already on record. A row whose `version` looks like a version is a fix and not a
clearance, which is `parser_legacy`'s own test. It overrides and never creates:
the pre-OSV provider downgraded a row that was already there and invented no
record.

What it contributes, and in what order:

- a combination either feed mentions, with no fix version, takes the
  snapshot's `released` version. OSV's own `fixed` event always wins.
- a combination neither feed mentions is emitted from the snapshot's status,
  by the same mapping `map_parsed` uses: `released` a fix, `ignored`
  won't-fix, `not-affected` the `"0"` row, `DNE` nothing, every other triage
  state a finding with no fix.
- a VEX statement always outranks the row for disposition, including
  `component_not_present`, which leaves no entry for a row to attach to and
  so is asked about rather than looked for.
- the row is read before the Pro-to-base inference runs, so a combination the
  inference would otherwise have guessed at from the Pro sibling instead takes
  Canonical's own record for the base release, where the snapshot has one. A
  `released` row is not a disposition and is left to the fix-version rule
  above.
- an `ignored_patches[]` clearance is applied last of all, because a clearance
  outranks every disposition the steps before it put down — including the row
  read out of the same file a moment earlier. It stops at a fix version: a `"0"`
  row cancels findings from every other source, and writing one over a version
  already on record trades a real match for silence on the word of a frozen
  snapshot. A VEX clearance does overwrite a version, which is the one place the
  two clearances deliberately differ — see below.

Fix dates for a snapshot-sourced version are resolved the same way as any
other fix version, through `_resolve_fix_dates` — the USN overlay first, then
the grype-db-observed cache, then the CVE's own `published` date as a last
resort. Base namespaces only; the `+esm` channel is unchanged. Fix versions
are historical facts, so a frozen snapshot does not go stale for them; the
other dispositions are staler, which is why they are read only where nothing
current speaks at all.

Until Canonical publishes EOL data in some refreshable format,
`normalized-cve-data/` stays in `input/`. It is frozen forever — the
provider never writes to it.

## Operational invariants

- **`input/` is load-bearing.** `normalized-cve-data/` is the frozen
  security-tracker snapshot: the only source for every release the feeds do not
  carry and for the fix versions they have stopped carrying, and nothing
  regenerates it. Losing it is unrecoverable. `Provider.__init__` enforces this
  via `disallow_existing_input_policy(config.runtime)` plus an explicit check on
  `config.runtime.on_error.input`. The two `*-rows.tsv` scratch files beside it
  are rewritten every run and can be deleted freely.
- **Don't bump `__version__` or `__distribution_version__`.** The
  framework treats version changes as workspace-clear triggers and
  would wipe `input/`, and the frozen snapshot in it is not recoverable. A
  version bump buys nothing in return: nothing downstream gates on it.
- **Identifiers collide in exactly one case.** Both the snapshot passthrough
  and the merge speak for a release the feed carries an extended-support build
  of and no base data for, on the same `ubuntu:{X.YY}/cve-X` identifier. The
  passthrough runs first so that the merge's record, which has seen every
  source, is the one `INSERT OR REPLACE` keeps.
- **A record for a refused release is discarded silently.** A known-husk
  release is never counted among the releases the feed speaks for, so nothing
  it names reaches a namespace and the snapshot serves it instead.
- **`compatible_schema()` is intentionally NOT implemented.** The
  parser yields `(identifier, Schema, payload)` triples directly; the
  classmethod is a per-provider filter bitnami uses to gate on schema
  version, which we don't need.

## Schema versions

Every emitted record carries the OS schema. The OSV records' own
`schema_version` — 1.7.0 for about 99% of today's tarball, with a 1.6.3 tail
mostly on older Pro:14.04 records — decides nothing downstream here, because
the OS shape is the same whichever version the record it was assembled from
declared.

## Withdrawn records

Canonical sets the OSV `withdrawn` field (6.1% of records today) on a
record it will no longer regenerate, not on a finding it has retracted:
the majority of withdrawn records still carry released fix versions,
concentrated on releases in extended support, and none is ever modified
after being withdrawn. They are emitted, and the timestamp itself is
not carried: nothing downstream of this provider reads it, and the one class of
record that is a real retraction is recognized another way.

The exception is a CVE the CVE program itself rejected, which is a real
retraction and would be a knowingly false finding. The `details` prose is
the only signal that separates the two, and Canonical writes it two
ways — `** REJECT **` and `Rejected reason:` — so both are matched,
case-insensitively and tolerating leading whitespace. The second form
appears on records carrying no `withdrawn` timestamp at all, so rejection
is checked independently of withdrawal. A third form, `** DISPUTED **`,
is not matched: it is MITRE's tag on a record it has kept live and
published, not one it rejected, and matching it suppressed real findings.
This is still a proxy for the CVE program's own record state, not that
state itself — it reads Canonical's re-rendering of the rejection text in
`details`, so a rejection Canonical never re-renders into `details` is
missed. It is read once, as the archive streams past, and carried on the CVE's
row as a boolean, because a rejection is a fact about the CVE and not about any
release the record happens to name: the releases it names are only the ones
Canonical was still publishing for when the rejection landed, so a release it
does not name has to inherit the fact, and the statements it would otherwise be
rebuilt from carry no `details` to be asked. A rejected CVE is dropped whole,
on every release and every channel.

## What grype expects

The v6 dpkg matcher queries by namespace via `search.ByDistro`, and the legacy
OS transformer turns each record here into the DB row shape it wants. That is
why the OS schema is what this provider emits: grype `main` carries no
transformer for Canonical's OSV shape, and the disposition a record carries is
assembled from three sources rather than read off one OSV envelope, so there is
no per-release OSV envelope left to hand it instead.

The mappings the record already makes:

- Primary ID = the upstream CVE, not `UBUNTU-CVE-*`. The UBUNTU-CVE id is
  Canonical's internal record key; users see CVE-X in grype output, and a
  record with no upstream alias is emitted nowhere.
- Vendor severity (`severity[type=Ubuntu]`) → `Vulnerability.Severity`, one of
  Negligible / Low / Medium / High / Critical, else Unknown.
- `Ubuntu:24.04:LTS` → `NamespaceName: "ubuntu:24.04"`.
- `Ubuntu:Pro:14.04:LTS` → `NamespaceName: "ubuntu:14.04+esm"`, the distro
  channel that mirrors RHEL EUS's `rhel:X.Y+eus`, carrying the real Pro fix
  version. `Ubuntu:Pro:FIPS*`, Realtime and Nvidia-BlueField map to no
  namespace: their builds diverge from base, so their fixes cannot resolve a
  base disclosure.
- won't-fix → `FixedIn.VendorAdvisory.NoAdvisory = true`, which grype renders
  as `WontFixStatus` and users see as `(won't fix)`.
- a researched clearance → `FixedIn.Version: "0"` and nothing else for that
  package, which grype reads as an unaffected package that cancels what another
  source reports.

### Configuration

```yaml
providers:
  ubuntu:
    downconvert_emit_esm: true    # default: true
```

`downconvert_emit_esm` controls whether plain Ubuntu Pro (ESM) slices are
emitted as `ubuntu:X.YY+esm` channel records. Set it `false` for the frozen-v5
lane, whose build isn't validated against `+esm` channels — plain Pro then maps
to nothing, like the sub-tiers, and only base records are emitted.

`downconvert_osv_to_os` is still accepted at its default (`true`) so an
existing config loads, and is read nowhere: every record is the OS shape now,
unconditionally. The flag used to pick between emitting native OSV envelopes
and downconverting them to this shape, but the merge assembles a release's
disposition from three sources at once and two of them can name a package the
OSV record never carried, so there is no per-release OSV envelope left to hand
out as the other choice. Setting it `false` raises, since there is nothing
left it could mean.

### What the OS shape cannot say

- **Provenance is lost.** Four mechanisms can put a package on a base record —
  the release's own OSV entries, the Pro-to-base inference, a statement at any
  token of the release, and the frozen snapshot — and the OS schema has no
  field that tells them apart. That is the point, since the rows have to be
  indistinguishable from the ones v3 produced, but it means a record cannot be
  traced back to the source that decided it without re-running the merge.
- **Six Canonical statuses collapse to four.** Canonical's own OSV publication
  already collapsed `released/needed/active/deferred/pending/ignored` into one
  shape; what this reconstructs from the statements and the snapshot is the
  fixed / won't-fix / no-fix / not-affected distinction and no more.
