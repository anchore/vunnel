# Ubuntu provider

## Overview

This provider ingests Canonical's OSV to get vulnerability data about Ubuntu.
However, this data is incomplete in 5 ways:

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
Canonical's OpenVEX feed, caches its statements per distro token, and reads
them when records are emitted. They are the more complete statement of which
packages a CVE affects in a release, so what is emitted for a release is the
union of its OSV records and its statements: won't-fix becomes a label, a
confirmed-not-vulnerable assertion is stated as such, and a package only the
statements name becomes a finding with no fix version.

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

Canonical stops publishing an Ubuntu release some days to weeks after it
reaches end of life, so the provider has to hold the last good state of a
release itself. The strategy is:

1. The OSV and OpenVEX data is downloaded, along with Ubuntu's release
   calendar.
2. Each feed is sharded on disk: one cache per Ubuntu release for OSV, one per
   distro token for VEX.
3. On subsequent runs a release's caches are replaced wholesale from the day's
   feed while the release is live, and are never written again from midnight
   UTC on its published end-of-life date. From that instant vunnel emits the
   last state the release was published in.

The freeze is decided from the calendar and the clock, and never from the
feed. Canonical does not remove a dead release cleanly: the sweep leaves
behind a husk of never-regenerated withdrawn records that still name it, so a
provider that waits for the release to disappear overwrites good data with the
husk instead. See "Surviving end of life" below.

## Data sources

The provider reads four things, in priority order:

| Source | URL / path | Role | Lifecycle |
|---|---|---|---|
| OSV CVE feed (`osv/cve/**`) | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` | Authoritative ranges + fix versions for currently-tracked releases | Streamed each run, never extracted to disk |
| OSV USN feed (`osv/usn/**`) | same tarball | Authoritative fix-ship dates (USN.published) — see "USN fix-date overlay" below | In-memory index built each run; not persisted |
| OpenVEX feed | `https://security-metadata.canonical.com/vex/vex-all.tar.xz` | Which packages a CVE affects in a release, fix disposition, and confirmed-not-vulnerable assertions — see "Why VEX" below | Streamed each run into `input/vex-fragments/`, one per distro token, under the same freeze rule |
| Release calendar | `https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv` | End-of-life date and LTS status per release; the only input to the freeze decision | Fetched each run into `input/distro-info/ubuntu.csv`; the cached copy is the fallback |
| `input/normalized-cve-data/` | local | Releases absent from the feeds above, and what neither feed states for the ones present | Frozen; populated by the v3 provider, kept untouched after v3's removal; indexed once into `input/tracker-index/` |
| (fix-date cache) | `input/grype-db-observed-fix-dates.db` | Cross-provider fallback for fix dates when no USN advisory shipped the fix | Refreshed each run |

`normalized-cve-data/` covers every release the v3 provider ever tracked, not
only the ones that were already EOL at the cutover. Which releases it actually
serves is decided per run by whether an OSV fragment exists for the release, so
retiring a fragment moves that release onto this path — which is what happens
for 24.10 and 25.04, both of which were swept before the freeze rule existed.

USN records are **not emitted** as their own envelopes — the previous provider
didn't surface them either. They're used purely as a metadata source: the
USN→CVE join supplies real fix-ship dates that the CVE records themselves
don't carry. Emitting USN-keyed advisories alongside CVE entries is a
possible future enhancement.

## Output: per-ecosystem fragments + legacy passthrough

```
data/ubuntu/
  input/
    osv-all.tar.xz                # today's download (overwritten each run)
    vex-all.tar.xz                # today's download (overwritten each run)
    distro-info/
      ubuntu.csv                  # the release calendar, refetched each run
    fragments/                    # persistent, load-bearing
      ubuntu-14.04-lts.db
      ubuntu-18.04-lts.db
      ubuntu-20.04-lts.db
      ubuntu-pro-16.04-lts.db
      ubuntu-pro-fips-updates-20.04-lts.db
      …                           # one per release identity
    vex-fragments/                # persistent, load-bearing
      .bootstrap-complete         # written once, after the first VEX write pass
      focal.db
      esm-infra-focal.db
      …                           # one per PURL distro token
    normalized-cve-data/          # frozen tracker-derived data
    tracker-index/                # the same data transposed by release
      .index-complete             # written once, after the build
      trusty.db
      focal.db
      …                           # one per release codename
    grype-db-observed-fix-dates.db
  results/
    results.db                    # mixed-schema (OSV + OS) output
```

Each fragment file is an envelope-shaped `results.db` containing only
one release's slices. Envelope identifier is
`{release-slug}/{cve-id-lowercase}`, e.g.
`ubuntu-20.04-lts/ubuntu-cve-2024-1234`.

The slug is the release's canonical identity rather than the literal
ecosystem string. Canonical appends `:LTS` when a release reaches general
availability, so `Ubuntu:26.04` and `Ubuntu:26.04:LTS` are one release
published under two names over its life, and records written before the
rename would otherwise be stranded in a fragment of their own. Genuinely
different things stay separate: `Ubuntu:20.04:LTS`, `Ubuntu:Pro:20.04:LTS`
and `Ubuntu:Pro:FIPS:20.04:LTS` are three identities and three fragments.

### Why per-release fragments when Canonical publishes per-CVE

OSV records describe a CVE across N releases in one document. We
re-shard into one envelope per (release, CVE) for two reasons:

1. **Survive EOL transitions without operator action.** At midnight UTC
   on a release's published end-of-life date the provider stops opening a
   writer for it. The fragment persists, frozen at the state of the last
   live run, and subsequent runs continue to emit it. No operator step and
   no snapshot; the calendar and the clock decide, per run. See
   "Surviving end of life" for why the decision cannot be made from the
   feed.

2. **Match the downstream contract.** grype's dpkg matcher resolves
   per-namespace via `search.ByDistro`. Per-ecosystem fragments map 1:1
   to that contract; the alternative (multi-release records the
   transformer slices) just moves the same work downstream.

### Why fragments stay separate for Pro/FIPS/Realtime/etc.

Today's tarball publishes 32 distinct ecosystems:

- Base: `Ubuntu:14.04:LTS` through `Ubuntu:26.04:LTS`, plus interim
  releases like `Ubuntu:25.10`
- Subscription tiers: `Ubuntu:Pro:18.04:LTS`,
  `Ubuntu:Pro:FIPS-updates:20.04:LTS`,
  `Ubuntu:Pro:Realtime:22.04:LTS`, `Ubuntu:Nvidia-BlueField:22.04:LTS`,
  etc.

We keep these as separate fragments rather than collapsing them into
the base release. Different tiers have different fix policies and
different CVE coverage; downstream is expected to gain
subscription-tier-aware matching eventually, and collapsing here would
be a one-way decision. Cost: ~2.5 GB of additional fragment storage
across 20 sub-ecosystems.

## Per-run flow

```
Provider.update()
 └─ Parser.get()
      ├─ _clean_input()            # retire the known-husk fragments, once
      ├─ _download_archive()       # stream osv-all.tar.xz to disk
      ├─ _download_vex_archive()   # stream vex-all.tar.xz to disk
      ├─ _load_calendar()          # fetch ubuntu.csv; cached copy is the fallback
      ├─ now = datetime.now(UTC)   # sampled once; one decision for the whole run
      ├─ fixdater.download()
      ├─ _load_usn_overlay()       # build in-memory (eco, pkg, fix-ver) → USN.published index
      ├─ _write_fragments(calendar, now):
      │     frozen = every interim release past its eol instant
      │     for each osv/cve/**/*.json (streaming, no extraction):
      │         slice_by_ecosystem(record)        # group affected[] by release identity
      │         for each slice:
      │             skip and count it if the release is frozen
      │             open fragment writer (lazy, DELETE_BEFORE_WRITE)
      │             insert envelope
      ├─ vex_store.write(calendar, now):
      │     same rule per distro token, into input/vex-fragments/
      ├─ _load_vex_overlay()       # index the cached statements, not today's download
      ├─ yield from _iter_normalized_cve_data()   # legacy first
      └─ yield from _iter_fragments()             # OSV second
            for each base ecosystem:
              yield real base envelopes (patch_fix_date applied;
                                         USN overlay provides authoritative
                                         fix-ship dates as accurate candidates;
                                         VEX labels won't-fix and restates
                                         confirmed-not-vulnerable entries)
              merge inferred wont-fix entries from sibling Pro fragments
                into existing envelopes, or synthesize new ones
              merge the release's own VEX statements for packages neither
                names, synthesizing an envelope where OSV has no record
```

Three annotations live in `affected[].database_specific.anchore`:

- `fixes[]` — `{version, date, kind}` populated by `patch_fix_date` at yield
  time. Source priority: (1) USN overlay (`USN.published`, marked
  accurate=True; covers ~77% of fix tuples across the live feed and 88–100%
  of plain-Pro tiers), (2) grype-db-observed first-observed cache, (3)
  CVE-record `published` date as a last-resort low-confidence fallback.
  Applied **at yield time** so improvements to either USN data or the
  fix-date cache flow through to frozen fragments on the next run without
  rewriting them.
- `status` — `"wont-fix"` when Canonical's VEX feed marks this
  `(cve, distro, source-pkg)` as won't-fix, and `"not-affected"` when it
  states the package is not vulnerable, which downconverts to a `FixedIn`
  version of exactly `"0"`. Applied **at yield time**
  from the cached VEX statements, which freeze alongside the OSV
  fragments, so the prose match that produces it stays revisable rather
  than being fixed forever in a fragment that can never be rewritten. A
  label baked into a fragment by an earlier build is preserved: the yield
  path only ever adds one.
- `vex` — `{token, disposition}` on an entry that exists only because a
  VEX statement named the package: the release's OSV record for the CVE
  does not carry it, or there is no OSV record for the CVE at all. Three
  mechanisms can put an entry on a base record, and this is what tells
  them apart.
- `inference` — when a base wont-fix entry was synthesized from a
  Pro-only-fix record (see next section). Applied **at yield time** on
  synthesized base entries. Carries `kind: "pro-only-fix"` and
  `source_ecosystems` (the Pro ecosystems whose presence triggered the
  inference) — gives downstream a precise join key for future
  Pro-fix-suggestion behavior.

These have deliberately different update semantics. Fix dates can be
refined retroactively from new tracking data; the won't-fix status is a
"what Canonical decided at this moment" snapshot that must survive the
release leaving both upstream feeds; the inference is recomputed every
yield from current Pro data, so frozen base fragments still pick up
newly-published Pro-only fixes after base EOLs.

## Pro-only-fix → base wont-fix inference

Canonical encodes "this CVE will only be fixed in Pro/ESM, not base
Ubuntu" by **omitting the base ecosystem** from the OSV record's
`affected[]` while listing the Pro tier. E.g. CVE-2018-20796 lists
`Ubuntu:Pro:20.04:LTS / glibc` but no `Ubuntu:20.04:LTS / glibc` — the
intent is "base focal users won't get a fix; only Pro subscribers
will." v3 captured this via `status: ignored` on base in the tracker;
OSV drops the signal entirely.

At yield time, for each base ecosystem fragment we look at sibling
plain-Pro fragments (`Ubuntu:Pro:X.YY:LTS` only — see below). For any
`(CVE, source-package)` tuple Pro lists but base doesn't, we
synthesize a base wont-fix entry. Synthesized entries are merged into
the existing base envelope when one exists; they become a new envelope
when base has no entry for that CVE at all.

**Why only plain Pro, not FIPS/Realtime/Nvidia-BlueField:** plain Pro
packages are byte-identical to base packages while base is supported,
then diverge via ESM-backported patches — same vulnerable code, so the
inference is sound. FIPS rebuilds specific packages against
FIPS-validated cryptographic modules (different crypto code paths);
Realtime is the PREEMPT_RT kernel (different locking/scheduling code);
Nvidia-BlueField is a separate SmartNIC OS. A CVE in those builds
doesn't reliably imply the same CVE on base, so we don't infer from
them.

**Why at yield time, not write time:** consider the post-EOL scenario.
Base 24.04 eventually drops out of OSV; its fragment freezes. Pro:24.04
is still tracked. A new CVE-X gets a Pro-only fix. Yield-time inference
sees the fresh Pro:24.04 record alongside the frozen base 24.04
fragment and produces a synthetic base wont-fix entry — base 24.04
users get the disclosure without us rewriting the frozen base data. A
write-time inference would have to either overwrite the frozen base
fragment (losing pre-EOL real data) or special-case the wipe-and-rewrite
semantics; both are worse.

**Provenance for future grype behaviors:** the synthesized entry's
`anchore.inference.source_ecosystems` carries the Pro ecosystems that
triggered it. Downstream can use this as a join key to look up the Pro
fix version for "vulnerable, fix available via Pro upgrade" presentation
when a user opts in to Pro-fix suggestions.

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

The provider streams `osv/usn/**` and builds an in-memory index keyed by
`(ecosystem, source-pkg, fixed-version) → earliest USN published date`.
At yield time, when `patch_fix_date` walks each `fixed:` event, the USN
overlay's date is supplied as a high-confidence (`accurate=True`)
candidate to `fixdater.best()`, which beats first-observed when both are
present. The grype-db-observed first-observed cache remains the fallback.

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

The provider caches the statements per distro token under
`input/vex-fragments/`, storing status, justification and action
statement as published and no verdict. It has to be a cache rather than a
fresh read of each download: Canonical erases a dead release from VEX
harder than from OSV, regenerating every surviving document without it, so
a release's assertions vanish the day it is swept. The fragments are
replaced wholesale while the token's release is live and frozen from its
end-of-life instant, exactly as the OSV fragments are.

The statements are then read when records are emitted, and what is emitted
for a release is the union of them and its OSV entries, per
`(cve, source package)`. Won't-fix sets
`affected[].database_specific.anchore.status = "wont-fix"`, which the
grype v6 transformer renders as `WontFixStatus` and users see as
`(won't fix)`. `not_affected` splits on its justification.
`vulnerable_code_not_present`, or no justification at all, is a researched
conclusion about a package the release ships: the entry is replaced with
`status = "not-affected"`, which downconverts to a `FixedIn` version of
exactly `"0"`, and that includes entries the Pro-to-base inference
synthesized, where the assertion outranks the inference.
`component_not_present` says the release does not ship the package — the
tracker's `DNE`, which this provider has never emitted anything for — so the
entry is dropped and nothing takes its place. A package only the statements
name is added: `affected` and `under_investigation` as a finding with no fix
version, a justified `not_affected` as the `"0"`, and `fixed` and
`component_not_present` as nothing at all.

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
`vex_cache.py`. The `+esm` channel carries fix versions only and never a
`"0"`.

The clearance is read before the fix events for a reason worth knowing:
Canonical's OSV generator re-encodes a tracker `not-affected (<version>)`
row as a range fixed at that version, byte-identical to a real fix, so an
entry can carry both a fix event and a clearance. Reading the events first
let the encoding win and put the package back below a boundary it was never
under — 25 false positives on one image in a single quality-gate run.

`under_investigation` is stored and deliberately changes nothing: it means
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

## Surviving end of life

A release's caches freeze at 00:00:00 UTC on the `eol` date published in
`distro-info-data`'s `ubuntu.csv`. Before that instant, and forever for an
LTS release at every support tier, they are replaced wholesale from the
day's feed. From that instant nothing is written for the release, whatever
the feed says.

The decision reads the calendar and the clock and nothing else — not the
archive, not the fragment on disk, not any record's contents — and there is
no grace period and no unfreeze. A release the calendar does not list is
live: a release cannot be at end of life before it exists in the calendar.
Every Pro, FIPS, Realtime and BlueField channel derives from an LTS
release and is therefore never frozen.

It has to be a date rather than a property of the feed because Canonical
does not remove a dead release cleanly. Some days to weeks after end of
life the generator stops emitting the release, leaving behind only the
records that were never regenerated — a husk of a few hundred mostly
withdrawn entries that still name it. Absence never happens, so a provider
waiting for absence overwrites a complete release with its residue. Across
every completed sweep the margin between the published date and the sweep
has been at least four days, and no LTS-derived channel has ever been
swept.

Two releases were swept before this rule existed and their fragments were
written from the residue. Those are named in `_KNOWN_HUSK_RELEASES` and
retired once, on the first run, so the tracker-derived passthrough serves
them instead; the same pass removes a fragment whose file name is a
superseded spelling of a release that already has one. Nothing else is
retired, and nothing is decided by a threshold: a release past its
end-of-life date whose fragment is healthy is kept and frozen, which is
what the rule is for.

The VEX cache is new, and the freeze rule protects a cache but cannot
create one. So on the run that introduces it to a workspace, and only that
run, a frozen token with no fragment is written once from the feed, unless
its release is one of the known husks. A marker beside the fragments
records that this happened, and after it exists no frozen token is ever
written again. The OSV fragments are not a new cache kind and get no
equivalent.

## Why `normalized-cve-data` is still load-bearing

Live VEX has **the same coverage gap as live OSV**: only currently-
tracked releases are present (jammy, noble, focal, bionic, trusty/ESM,
xenial/ESM, questing, plus Pro/FIPS/etc.). Releases that were EOL
before Canonical's OSV/VEX feeds launched — precise, quantal, raring,
saucy, utopic, vivid, wily, yakkety, zesty, artful, cosmic, disco,
eoan, groovy, hirsute, impish, kinetic, lunar, mantic — are absent.

The v3 provider's `normalized-cve-data/` cache covers every release the
tracker knew about, not only those (it was populated from
`ubuntu-cve-tracker` git history before v3 was retired). The new provider
reads it via the vendored `map_parsed` from `parser_legacy.py` and emits
OS-schema envelopes for releases not already covered by an OSV fragment —
so it also serves 24.10 and 25.04, whose fragments were retired because
they had been written from Canonical's post-sweep residue.

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

So it is read for every release, not only the ones the feeds have dropped.
Because the emit path walks one release at a time and the snapshot is one
file per CVE, it is transposed once into `input/tracker-index/`, one fragment
per codename keyed on `(codename, CVE, source package)`, and joined per
release like the other two caches. The source never changes, so the index is
built when missing and never rebuilt; a completion marker records the build
so an interrupted one is resumed rather than half-trusted. `DNE` rows are not
indexed — 16.9 million of the 20.7 million — since they say the release never
shipped the package.

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

Fix dates for a snapshot-sourced version come from the same `patch_fix_date`
pass as every other fix. Base namespaces only; the `+esm` channel is
unchanged. Fix versions are historical facts, so a frozen snapshot does not
go stale for them; the other dispositions are staler, which is why they are
read only where nothing current speaks at all.

Until Canonical publishes EOL data in some refreshable format,
`normalized-cve-data/` stays in `input/`. It is frozen forever — the
provider never writes to it.

## Operational invariants

- **`input/` is load-bearing.** `fragments/` carries frozen OSV state
  for releases no longer in the feed; `normalized-cve-data/` carries
  pre-cutover EOL data. Losing either is unrecoverable. `Provider.__init__`
  enforces this via `disallow_existing_input_policy(config.runtime)`
  plus an explicit check on `config.runtime.on_error.input`.
- **Don't bump `__version__` or `__distribution_version__`.** The
  framework treats version changes as workspace-clear triggers and
  would wipe `input/`. Per-envelope schema URLs (each record carries
  its own OSV or OS schema URL) are the dispatch signal downstream
  consumers gate on — a global version bump is both redundant and
  destructive.
- **Identifier shapes do not collide.** OSV fragment envelopes use
  `ubuntu-{slug}/ubuntu-cve-X` (hyphen-prefixed); legacy envelopes use
  `ubuntu:{X.YY}/cve-X` (colon-prefixed). The emit order (legacy
  first, OSV last) is policy-only — `INSERT OR REPLACE` collisions
  don't happen in practice today.
- **The release calendar is fetched every run.** Published end-of-life
  dates get corrected upstream, so a vendored copy can be silently wrong
  for years. A failed fetch falls back to the cached
  `input/distro-info/ubuntu.csv` and logs a warning naming the fallback;
  a failed fetch with no cached copy fails the run before anything is
  written, because carrying on with every release treated as live is the
  one direction that can ingest a sweep. A download that does not parse
  is treated as a failed fetch and never replaces the cached copy.
- **Two log lines report the freeze, and change nothing.** One per run
  per frozen release still present in the feed, naming it and the number
  of records skipped; one per run per live interim release inside the
  warning window, naming it and the instant it freezes. The emitted
  records are identical with them and without them.
- **`compatible_schema()` is intentionally NOT implemented.** The
  parser yields `(identifier, Schema, payload)` triples directly; the
  classmethod is a per-provider filter bitnami uses to gate on schema
  version, which we don't need.

## Schema versions

Records pass through with their declared `schema_version` preserved.
Today's tarball carries 1.7.0 (~99%) plus a 1.6.3 tail (~1%, mostly
older Pro:14.04 records). Each fragment envelope's schema URL reflects
the record's own version — `OSVSchema(version=record["schema_version"])`
— so downstream sees the actual shape per record rather than a
provider-pinned constant.

## Withdrawn records

Canonical sets the OSV `withdrawn` field (6.1% of records today) on a
record it will no longer regenerate, not on a finding it has retracted:
the majority of withdrawn records still carry released fix versions,
concentrated on releases in extended support, and none is ever modified
after being withdrawn. They are emitted. Canonical does not delete them
from the tarball either, so the timestamp rides through the slicing into
each fragment payload and downstream can still see it.

The exception is a CVE the CVE program itself rejected, which is a real
retraction and would be a knowingly false finding. The `details` prose is
the only signal that separates the two, and Canonical writes it three
ways — `** REJECT **`, `** DISPUTED **` and `Rejected reason:` — so all
three are matched, case-insensitively and tolerating leading whitespace.
The third form appears on records carrying no `withdrawn` timestamp at
all, so rejection is checked independently of withdrawal. The check runs
on every emit path, including the merge that synthesizes a base entry
from a Pro record and copies its description verbatim.

## What grype expects

The v6 dpkg matcher queries by namespace via `search.ByDistro`. An OSV
transformer for these fragments turns each envelope into the same DB row
shape the legacy OS transformer produces; note that grype `main` carries
no such transformer today, which is why the downconversion below is on by
default. The mappings it has to make:

- Primary ID = upstream CVE (`vuln.Upstream[0]`), not `UBUNTU-CVE-*`.
  The UBUNTU-CVE id is Canonical's internal record key; users see CVE-X
  in grype output.
- Vendor severity (`type: "Ubuntu"`) → CHMLN scheme, lowercase string.
  Matches the legacy OS transformer's ordering so OSV-sourced and
  OS-sourced rows are downstream-fungible.
- `Ubuntu:24.04:LTS` → `db.OperatingSystem{Name: "ubuntu", MajorVersion:
  "24", MinorVersion: "04", Codename: "noble"}`.
- `Ubuntu:Pro:14.04:LTS` → same shape + `Channel: "esm"`.
- `affected[].database_specific.anchore.status == "wont-fix"` →
  `Fix{State: WontFixStatus}` on the no-fix sentinel range.

## OSV → OS downconversion

For consumers whose grype-db build process has no OSV transformer for
these fragments, the provider rewrites every fragment envelope into the
v3 `{"Vulnerability": {...}}` OS-schema shape as it is yielded. This is
on by default. Configure it via:

```yaml
providers:
  ubuntu:
    downconvert_osv_to_os: true   # default: true
    downconvert_emit_esm: true    # default: true; only meaningful when downconvert_osv_to_os is on
```

`downconvert_emit_esm` controls whether plain Ubuntu Pro (ESM) slices are
emitted as `ubuntu:X.YY+esm` channel records. Set it `false` for the frozen-v5
lane, whose build isn't validated against `+esm` channels — plain Pro then maps
to `None` like the sub-tiers, and only base records are emitted.

When the toggle is on:

- The on-disk fragment store remains OSV-shaped — only the *yielded*
  records change. Toggling between runs requires no cache wipe.
- The legacy `normalized-cve-data` passthrough is unchanged (already OS-shape).
- Output is uniformly OS-schema: an old grype-db build sees exactly the
  same row shapes the v3 provider produced.

### Mapping rules

| OSV input | OS output |
|---|---|
| `upstream[0]` (`CVE-*`) | `Vulnerability.Name` |
| `severity[type=Ubuntu].score` | `Vulnerability.Severity` (Negligible/Low/Medium/High/Critical, else Unknown) |
| `Ubuntu:22.04:LTS` ecosystem | `NamespaceName: "ubuntu:22.04"` |
| `Ubuntu:Pro:22.04:LTS` (plain ESM) | `NamespaceName: "ubuntu:22.04+esm"` — the `+esm` distro channel (mirrors RHEL EUS's `rhel:X.Y+eus`), carrying the real Pro fix version. Gated by `downconvert_emit_esm`. A plain-Pro slice with no fix emits no `+esm` record (the base wont-fix already discloses it) |
| `Ubuntu:Pro:FIPS*` / Realtime / BlueField | **dropped** — their builds diverge from base, so their fixes can't resolve a base disclosure |
| `database_specific.anchore.status == "not-affected"` | `FixedIn.Version: "0"`, `NoAdvisory: false`, and nothing else for that package |
| `ranges[].events[].fixed: "x.y.z"` | `FixedIn.Version: "x.y.z"`, `NoAdvisory: false` |
| no `fixed` + `database_specific.anchore.status == "wont-fix"` | `FixedIn.Version: "None"`, `NoAdvisory: true` |
| no `fixed`, no wont-fix marker | `FixedIn.Version: "None"`, `NoAdvisory: false` |
| `database_specific.anchore.fixes[].date` | `FixedIn.Available: {Date, Kind}` |

Pro-only-fix data still surfaces in OS output: by the time downconversion
runs, the inference pass in `_yield_base_with_inferences` has already
merged the synthesized wont-fix entries into the base ecosystem's
`affected[]` list, so they emerge as `FixedIn{Version="None", NoAdvisory=true}`
rows on the base namespace.

### Trade-offs

- **Provenance is lost.** OSV's `database_specific.anchore.inference` and
  per-status annotations have no representation in the OS schema. The
  resulting OS rows are indistinguishable from those v3 produced from
  cve-tracker — which is the point, but it means downstream cannot tell
  which records came from Pro inference vs. real base entries.
- **Six Canonical statuses collapse to three.** OSV-via-Canonical already
  collapsed `released/needed/active/deferred/pending/ignored` to a single
  `affected` status; downconversion preserves only the fixed / won't-fix /
  no-fix / not-affected distinction reconstructed from the VEX statements.
- This is a *compatibility shim*, not a recommended long-term path. New
  consumers should adopt the OSV transformer rather than enable this.
