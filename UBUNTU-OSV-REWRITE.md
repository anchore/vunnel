# Ubuntu Provider OSV Rewrite — Spec

Status: draft (revised — per-release fragments + streaming)
Branch: `osv-in-ubuntu`
Owner: Will Murphy

## Goal

Rewrite the Ubuntu provider so that it ingests Canonical's published OSV
tarball as its source of truth, instead of parsing the `ubuntu-cve-tracker`
git repo line-by-line. The new provider streams `osv-all.tar.xz`, slices
each CVE record by ecosystem, and persists **per-ecosystem `results.db`
fragments** under `input/fragments/`. Fragments for ecosystems present in
today's tarball are wiped and re-written; fragments for ecosystems no
longer present are **left untouched (frozen)**, which is what lets the
provider survive Ubuntu releases dropping out of the OSV feed without
operator intervention.

For at-cutover EOL releases that have never been in Canonical's OSV feed
(precise → mantic), the provider continues to read the existing
`input/normalized-cve-data/` cache (already present on every workspace
that has ever run the v3 provider) and emit OS-schema envelopes via the
v3 `map_parsed()` routine. This path is phase 1 — phase 2 converts those
records into the fragment shape once and drops the v3 mapper.

## Why

- Canonical now publishes a maintained OSV feed; consuming it removes the
  bespoke parser, the bzr→git transition handling, and the revision-history
  walk for EOL releases.
- OSV is the schema we want new downstream consumers to grow against
  (matches bitnami, etc.).
- The current parser does heavy work to derive fixed-version info that the
  OSV feed gives us natively.
- The per-release fragment shape lets us **freeze the last good OSV state
  for any release that drops out of the feed**, automatically, with no
  hardcoded EOL list and no operator intervention at the next EOL
  transition (questing, plucky, oracular, …).

## Non-goals

- Re-deriving severity/priority differently than Canonical publishes — we
  defer to the OSV record's severity.
- Migrating existing archived results from OS schema to OSV schema. The
  old shape is preserved on disk as legacy data (phase 1: read in place;
  phase 2: one-shot convert into the fragment shape and delete the v3
  mapper).
- **Interpreting Ubuntu-specific fields in the OSV record.** Release
  codenames, binary vs. source package names, ESM channels, etc. are
  passed through to grype-db's OSV transformer. The provider's job is to
  download, slice, patch fix dates, and emit; downstream owns the
  semantics.

---

## Source data

- URL: `https://security-metadata.canonical.com/osv/osv-all.tar.xz`
- Format: `tar.xz` archive of per-record OSV JSON files.
- Compressed size: ~30 MB. Uncompressed: ~7.3 GB (compression ratio ~0.4%
  — extremely repetitive JSON).
- Member count: ~57,500. Of those, ~50,500 are `osv/cve/**/*.json` (the
  rest are USN records, deferred).
- Schema declared in records: mostly `1.7.0`, a small tail of `1.6.1`.
  We pass the record's declared version straight through into
  `OSVSchema(version=...)`; see "Schema version" below.
- Coverage: Canonical-supported releases only. Anything Ubuntu has dropped
  from upstream (e.g. precise, trusty pre-ESM, etc.) is **not** in the
  archive and must come from `input/normalized-cve-data/`.

The archive is downloaded to disk (30 MB) via `http_wrapper.get(...,
stream=True)` chunked-write. It is **never extracted to disk** — the
provider opens it with `tarfile.open(archive_path, mode="r:xz")` and
iterates members sequentially, parsing each JSON into memory and
discarding after slicing. Peak memory ≈ one record (~50–150 KB).

### Layout inside the tarball

```
osv/
  cve/
    {year}/
      UBUNTU-CVE-{year}-{nnnn}.json   # per-CVE records — INGESTED
  usn/
    USN-{nnnn}-{rev}.json             # per-advisory records — DEFERRED
```

**The new provider ingests only `osv/cve/**`.** USN records are deferred
(see "USN parsing deferred" below).

`UBUNTU-CVE-*` records describe a CVE's state across releases. Severity
is at the top level (`severity[].type == "Ubuntu"`). About 38% of them
carry no `fixed:` event in their ranges (just `{"introduced": "0"}`) —
those are "we acknowledge this affects us, no fix shipped yet" entries.
The remaining ~62% carry the per-release fixed-version events that
`osv.patch_fix_date` operates on.

Per the "defer downstream" non-goal, the provider does not interpret any
of the Ubuntu-specific fields — `ecosystem`, `purl`,
`ecosystem_specific.binaries`, `database_specific.cves_map` all pass
through to grype-db's OSV transformer.

### USN parsing deferred

The tarball also contains `osv/usn/USN-*.json` records, which carry
per-advisory fix data. Analysis (see `scripts/osv_ubuntu_compare.py` and
`scripts/osv_ubuntu_check_tracker_coverage.py`):

- 97% of USN fix tuples (`ecosystem, source_pkg, fixed_version`) already
  appear in the upstream `UBUNTU-CVE-*` records they reference.
- The remaining 3% (~1,400 tuples) split into:
  - 928 from 453 USNs with no upstream CVE at all,
  - 487 USN tuples whose upstream CVE doesn't list that fix.
- Of those ~1,400 USN-only fix tuples, **only ~280 (~20%) are visible to
  the current provider** via `released (<ver>)` lines in
  `ubuntu-cve-tracker/active|retired`.

Those ~280 are preserved automatically by the at-cutover legacy
passthrough (they appear in `normalized-cve-data/` from prior v3 runs).
So dropping USN ingestion is a **no-op regression versus the current
provider**.

The remaining ~1,130 USN-only fix tuples (mostly kernel variants —
`linux-*`, `nvidia-graphics-drivers-*`, `intel-microcode` — and recent
2025/2026 advisories) are net-new ground we'd gain from USN parsing, but
nothing today depends on them. Adding USN parsing later is mechanical:
walk `osv/usn/*.json` with the same streaming loader, emit into USN-keyed
fragments, no schema/wiring change.

### Record shape highlights (for sanity, not for parser logic)

- `affected[].package.ecosystem` is `Ubuntu:{version}:LTS` or
  `Ubuntu:{version}` (with Pro/FIPS/Realtime/Nvidia variants — 32
  distinct ecosystems observed in today's tarball). Three-segment+,
  distinct from the legacy `ubuntu:{version}` namespace shape.
- `affected[].package.name` is the **source** package; binaries are
  enumerated in `affected[].ecosystem_specific.binaries[]`.
- `affected[].package.purl` is a `pkg:deb/ubuntu/...` PURL.
- USN records nest CVE-level severity under
  `affected[].database_specific.cves_map.cves[].severity`.

The provider does not interpret any of this. It is grype-db's OSV
transformer's job to know that `Ubuntu:18.04:LTS` means a particular
namespace, that binaries should be expanded, etc.

### Schema version

Canonical's records declare `schema_version: "1.7.0"`. `vunnel`'s
`OSV_SCHEMA_VERSION` constant pins `"1.6.1"`, but
`schema/vulnerability/osv/schema-1.7.0.json` is already in the repo, so
`OSVSchema(version="1.7.0")` resolves to a real URL.

**Decision: yield the schema per-record from the parser.** Read
`record["schema_version"]` and hand back `OSVSchema(version=that_version)`
alongside each record (the bitnami pattern at
`providers/bitnami/parser.py:77`, adapted slightly). No change to the
`OSV_SCHEMA_VERSION` constant; we don't depend on it. This composes
naturally with the legacy passthrough: legacy yields `OSSchema(...)`,
OSV yields `OSVSchema(version=record_version)`.

### Dead files in `input/` from the old provider

After this lands, `data/ubuntu/input/` will contain:

- `ubuntu-cve-tracker/` (the git clone — ~14 GB) — **dead, recommend wipe**
- `normalized-cve-data/` (~3.3 GB, 66.5k files) — **live**: at-cutover EOL source (phase 1)
- `ubuntu-security-notices.zip` — dead (from a prior experiment)
- `vex-all.tar.xz`, `vex/` — dead (VEX experiment, prior branch)
- `osv-all.tar.xz` — live (today's download, ~30 MB)
- `fragments/` — live (per-ecosystem cache, ~5 GB after first run)
- `grype-db-observed-fix-dates.db` — live (fixdate cache)

The new provider leaves the dead files alone. DEVELOPING.md gets a
one-liner for operators to manually wipe `ubuntu-cve-tracker/`,
`ubuntu-security-notices.zip`, `vex-all.tar.xz`, `vex/` when migrating.
We deliberately do not auto-delete: removing files unprompted from a
kept `input/` is surprising, and the load-bearing input policy makes us
cautious about *any* implicit file deletion.

Phase 2 (after `normalized-cve-data` is converted to fragments) drops
that 3.3 GB too.

---

## Output shape

The provider writes a **mixed-schema `results.db`**:

| Record source | Schema written | `Envelope.schema` URL |
|---|---|---|
| OSV records (today's + frozen fragments) | `OSVSchema(record["schema_version"])` | `…/osv/schema-1.7.0.json` (mostly) |
| Legacy passthrough (phase 1: `normalized-cve-data/` via `map_parsed()`) | `OSSchema()` | `…/os/schema-1.1.0.json` |

`Provider.__schema__` is `OSVSchema()` — that's the schema the provider
*generates by default*. The parser hands back the actual schema object
alongside each record (OSV records carry the version pulled from
`record["schema_version"]`; legacy records carry the OS schema URL).

### Per-ecosystem fragment layout

Each fragment in `input/fragments/` is a `results.db` SQLite file
containing OSV envelopes for **one ecosystem only**. Rows are keyed by
identifier `{ecosystem-slug}/{cve-id-lowercase}`, e.g.
`ubuntu-20.04-lts/ubuntu-cve-2024-1234`. Payload is the sliced OSV
record (full top-level fields + just that ecosystem's `affected[]`
entries; `affected[]` typically 1–5 entries when sliced, vs. ~5–30
across all ecosystems in the source record).

Ecosystem-to-slug mapping is mechanical: lowercase, replace `:` with `-`.
Examples:

- `Ubuntu:22.04:LTS` → `ubuntu-22.04-lts`
- `Ubuntu:Pro:FIPS-updates:20.04:LTS` → `ubuntu-pro-fips-updates-20.04-lts`
- `Ubuntu:25.10` → `ubuntu-25.10`

### Versioning

- **`__version__` stays at 3.** Processing-version field; bumping it
  would trip `provider.py:282-285` and `workspace.clear()` the input
  directory between runs — which wipes the frozen fragments and the
  at-cutover legacy cache.
- **`__distribution_version__` stays at 1** (derived from
  `int(__schema__.major_version)`). Bumping this *also* trips
  `workspace.clear()` via `Provider.version() == __version__ +
  (distribution_version - 1)`. We initially planned to bump it; that was
  wrong. Per-envelope schema URLs (each record carries its own
  `/osv/schema-1.7.0.json` or `/os/schema-1.1.0.json`) are the actual
  signal downstream dispatches on — a global version bump is both
  redundant and destructive in this case.

**The workspace-clear interaction is the central operational gotcha of
this rewrite.** Either version field, if bumped, will erase
`input/fragments/` (losing all frozen-EOL OSV data) and
`input/normalized-cve-data/` (losing the at-cutover EOL data). Don't
change either without confirming downstream can be re-seeded.

Downstream needs to handle mixed schemas in one `results.db` — different
schema *families* (OSV + OS) coexisting in the envelopes from a single
provider run. Confirm with grype-db before merging.

---

## Architecture

```
Provider.update()
 └─ Parser.get() yields (identifier, schema, payload)
      ├─ fixdater.download()
      ├─ _download_archive()                          # stream osv-all.tar.xz to disk
      ├─ _write_fragments()                           # one-pass stream over tarball
      │     └─ for each osv/cve/**/*.json member:
      │           parse → patch_fix_date → for each ecosystem in affected[]:
      │             open fragment writer (wipe-on-first-use) → insert sliced envelope
      ├─ for each frozen-or-fresh fragment in input/fragments/:
      │     yield (id, OSVSchema(record_version), payload)
      └─ for each at-cutover legacy record in input/normalized-cve-data/:
            map_parsed(...) → yield (id, OSSchema, envelope)
```

### Why fragment refresh is wipe-then-write (no merge)

Each run, we know exactly which ecosystems are present in today's
tarball — they're the union of `affected[].package.ecosystem` strings
across all CVE records. For each one, we wipe its fragment file at first
write and replace it wholesale with today's data. There is no merge
logic, no diffing against yesterday's data: today's tarball is
authoritative for any ecosystem it covers.

For ecosystems **not** present in today's tarball, the fragment file is
not touched. That's the freeze semantics: when 25.10 (questing) drops
out of OSV at its EOL, `ubuntu-25.10.db` simply stops being rewritten;
it persists with its last-known content, which is the last run's
authoritative 25.10 OSV data. No special-case code, no hardcoded EOL
list, no operator intervention.

### Withdrawn records

Canonical uses the OSV `withdrawn` field (RFC 3339 timestamp at the
top level) when retracting a CVE record. **They do not delete records
from the tarball.** Measured against today's tarball:

- 3,504 of ~57,500 OSV records (6.1%) carry a `withdrawn` timestamp.
- All withdrawn records retain their full `affected[]` data; they are
  marked as withdrawn, not stripped.
- Withdrawn records appear across all years (heaviest in 2011–2017,
  some recent additions in 2024–2025).

Because withdrawn is a top-level field, the `_slice_by_ecosystem`
helper copies it into every per-ecosystem fragment slice automatically.
Downstream consumers (grype-db) are responsible for whether to honor
`withdrawn` (typically: skip matching against withdrawn records).

**This means our wipe-and-rewrite logic correctly propagates
withdrawals.** When a record's status flips, today's tarball carries the
new version, we rewrite the fragment, downstream sees the new
`withdrawn` field. No special handling needed in the parser.

**Known limitation:** if Canonical ever *deletes* a record from the
tarball without withdrawing it first (the file simply disappears), our
freeze logic would continue to serve the stale cached version of any
ecosystem the deleted record affected, because we have no way to
distinguish "ecosystem dropped (correctly freeze)" from "this specific
record vanished (should retract)." Given their evident policy of using
`withdrawn` for retractions, this scenario should be rare. If it
becomes a real problem, we'd add a record-level retraction pass: after
the fragment rewrite, scan each fragment for CVE ids not seen in
today's tarball (for ecosystems that ARE in today's tarball) and remove
those rows. Defer until we observe the failure mode.

### Identifier shapes (no natural collision)

- **OSV fragment records:** `{ecosystem-slug}/{cve-id-lowercase}` — e.g.
  `ubuntu-20.04-lts/ubuntu-cve-2024-1234`. One identifier per
  (ecosystem, CVE) pair. (USN ingestion deferred.)
- **Legacy records:** lifted from the existing envelope's `identifier`
  field — `ubuntu:{release}/{cve}`, e.g. `ubuntu:14.04/cve-2011-0221`.

These do **not** collide. The legacy entries use a colon namespace
prefix (`ubuntu:14.04`), the OSV fragment entries use a hyphen-prefixed
slug (`ubuntu-20.04-lts`). Both shapes coexist in the output
`results.db` and downstream interprets them through their envelope
schema URL.

### File layout

```
input/
  osv-all.tar.xz                          # downloaded each run, overwritten
  fragments/                              # persists between runs
    ubuntu-14.04-lts.db                   # ESM, currently in OSV
    ubuntu-16.04-lts.db
    ubuntu-18.04-lts.db
    ubuntu-20.04-lts.db
    ubuntu-22.04-lts.db
    ubuntu-24.04-lts.db
    ubuntu-25.10.db                       # current non-LTS
    ubuntu-pro-18.04-lts.db
    ubuntu-pro-fips-updates-20.04-lts.db
    …                                     # 32+ files, one per ecosystem
  normalized-cve-data/                    # phase 1: at-cutover EOL source
    CVE-1999-1572
    CVE-2000-1254
    …                                     # ~66.5k files, ~3.3 GB
  grype-db-observed-fix-dates.db          # fixdate cache (existing)
results/
  results.db                              # mixed-schema output
```

**Input directory is operationally load-bearing.** Two things in
`input/` must survive between runs:

1. `fragments/` — losing this means losing all frozen OSV data for
   releases that have dropped out of the feed since the last successful
   refresh.
2. `normalized-cve-data/` — losing this means losing all at-cutover EOL
   data (precise → mantic).

The provider's `__init__` guards against any config that lets the
framework wipe `input/`:

```python
provider.disallow_existing_input_policy(config.runtime)
if config.runtime.on_error.input != provider.InputStatePolicy.KEEP:
    raise ValueError(
        f"on_error.input policy is {config.runtime.on_error.input!r}; "
        f"only 'keep' is allowed for the ubuntu provider",
    )
```

The first call is the existing helper (`provider.py:108`); the second
covers `on_error.input`, which the helper currently doesn't check. If
this dual-guard pattern shows up in other providers we can promote it to
a shared `disallow_input_deletion(cfg)` helper later.

### Disk profile (measured against today's Canonical tarball)

| Artifact | Size | Notes |
|---|---|---|
| `osv-all.tar.xz` | 30 MB | downloaded each run |
| `fragments/` (sum) | ~5.2 GB | 32 SQLite files, biggest is `ubuntu-20.04-lts.db` at ~1.2 GB |
| `normalized-cve-data/` | 3.3 GB | phase 1; dropped at phase 2 |
| `grype-db-observed-fix-dates.db` | ~140 MB | fixdate cache (existing) |
| `results.db` (output) | ~5–6 GB | union of all fragments + legacy slice |

Total phase 1 peak disk under `data/ubuntu/`: ~14 GB (input + output).
Phase 2 (no normalized-cve-data): ~11 GB.

For comparison, today's v3 provider holds **~17 GB** in `input/` alone
(14 GB git clone + 3.3 GB normalized-cve-data). The fragment design's
biggest single cost is per-ecosystem duplication of OSV records'
top-level fields — Pro/FIPS/Realtime variants share the same CVEs as
the base ecosystem but carry their own copies of description,
references, severity, etc. If grype-db's downstream mapping treats
those variants as the same namespace, collapsing them at slice time
would save ~2.5 GB.

---

## Components

### 1. Streaming download (`Parser._download_archive`)

Pattern lifted from `providers/rhel/csaf_client.py:99` and
`providers/secureos/parser.py:115`:

```python
archive_path = os.path.join(self.workspace.input_path, "osv-all.tar.xz")
with http.get(self._osv_url_, self.logger, stream=True,
              timeout=self.download_timeout) as r, \
     open(archive_path, "wb") as fh:
    for chunk in r.iter_content(chunk_size=65536):
        fh.write(chunk)
```

`stream=True` + chunked writes throughout — the body is small (30 MB)
but consistent with the codebase's pattern.

### 2. Streaming read + per-ecosystem fragment write (`Parser._write_fragments`)

**No extraction to disk.** The tarball is opened directly:

```python
with tarfile.open(archive_path, mode="r:xz") as tar:
    for member in tar:
        if not member.isfile():
            continue
        if not (member.name.startswith("osv/cve/") and member.name.endswith(".json")):
            continue
        rec = orjson.loads(tar.extractfile(member).read())
        osv.patch_fix_date(rec, self.fixdater)
        for eco, sliced in _slice_by_ecosystem(rec):
            writer = self._get_or_create_writer(eco)  # wipes fragment on first use
            writer.insert(identifier=f"{slug(eco)}/{rec['id'].lower()}", payload=sliced)

for writer in self._writers.values():
    writer.close()
```

Peak in-memory: one record (~50–150 KB) + open SQLite writer handles
(one per ecosystem encountered, ~32 max). Peak disk for input: just the
30 MB tarball.

### 3. Slicing logic (`_slice_by_ecosystem`)

```python
def _slice_by_ecosystem(rec: dict) -> Iterator[tuple[str, dict]]:
    by_eco = defaultdict(list)
    for aff in rec.get("affected", []):
        eco = aff.get("package", {}).get("ecosystem")
        if not eco:
            continue
        by_eco[eco].append(aff)

    top = {k: v for k, v in rec.items() if k != "affected"}
    for eco, entries in by_eco.items():
        yield eco, {**top, "affected": entries}
```

Records with no `affected[]` entries are skipped entirely (they
contribute no fragment data; the CVE is in the tarball as metadata only).

### 4. Fragment writer lifecycle

`Parser._get_or_create_writer(eco)`:
- First call for a given `eco` in this run: wipe `fragments/{slug(eco)}.db`,
  open a new `SQLiteWriter`.
- Subsequent calls: return the cached writer.
- All writers closed in a `finally:` at end of `_write_fragments()`.

Critically: an ecosystem only gets its fragment wiped if today's tarball
has at least one record affecting it. Empty/dropped ecosystems are
untouched, which preserves the freeze.

### 5. Fix-date patching

Each parsed record gets `vunnel.utils.osv.patch_fix_date(rec, fixdater)`
applied **before** slicing. The fixdate annotations land in
`affected[].ranges[].database_specific.anchore.fixes[]`, which is on
the per-ecosystem `affected[]` entry, so each fragment carries its own
patched fix-date data. About 38% of records have no `fixed:` events
(just `{"introduced": "0"}`) and patch_fix_date is a no-op for them.

`Parser` owns the `fixdate.Finder` and acts as a context manager so its
`__enter__`/`__exit__` propagate (same pattern as bitnami/debian).

### 6. No release filtering in the provider

The OSV record is passed through verbatim (after `patch_fix_date` and
slicing). We do **not**:
- map codenames → version numbers (codename info, if needed, can come
  from `endoflife.date` — see below),
- drop ecosystems that aren't in some allowlist,
- collapse Pro/FIPS sub-ecosystems (see open question),
- collapse binary↔source package names,
- override severity.

Anything Ubuntu-specific in the OSV record is grype-db's OSV transformer
to interpret. The provider's contract is "what Canonical published, plus
fix dates, sliced per ecosystem."

This drops the `ubuntu_version_names` map (replaced by endoflife.date if
needed elsewhere), the `additional_versions` config knob, and the
patch-state machinery — all of it.

### 7. At-cutover legacy passthrough (phase 1)

For releases that have never appeared in Canonical's OSV feed
(precise, quantal, raring, …, mantic), the provider reads
`input/normalized-cve-data/` and runs each record through the existing
v3 `map_parsed()` function to produce OS-schema envelopes:

```python
def _iter_legacy_records(self):
    norm_dir = os.path.join(self.workspace.input_path, "normalized-cve-data")
    if not os.path.isdir(norm_dir):
        return
    for cve_id in sorted(os.listdir(norm_dir)):
        if not _CVE_FILENAME_RE.match(cve_id):
            continue
        with open(os.path.join(norm_dir, cve_id), "rb") as f:
            cve_file = CVEFile.from_dict(orjson.loads(f.read()))
        for ns, vid, record in map_parsed(cve_file, self.fixdater, self.logger):
            if ns_is_eol_pre_cutover(ns):  # see below
                yield (f"{ns}/{vid}", OSSchema(), {"Vulnerability": record})
```

`ns_is_eol_pre_cutover(ns)` filters to only the releases that are
at-cutover EOL (precise → mantic), avoiding double-emission for
releases that are *also* in OSV. The set is derived dynamically: a
namespace is at-cutover-EOL iff its version is in `normalized-cve-data`
but no fragment exists for it (i.e., not present in OSV today).

This path stays in place for phase 1. Phase 2 converts
`normalized-cve-data` into fragment files once and drops `map_parsed()`
and the v3 dataclasses (`CVEFile`, `Patch`, etc.).

### 8. endoflife.date integration

The existing `eol` provider hits `https://endoflife.date/api/v1/products/full`.
Ubuntu records there expose `name` (e.g. `22.04`), `codename`
(e.g. `Jammy Jellyfish`), `eolFrom`, `eoasFrom`, `isLts`, `isEol`,
`isMaintained`.

The ubuntu provider does not depend on endoflife.date for control flow
— today's tarball + the on-disk fragment set is sufficient. Two places
it can be wired in:

1. **Codename ↔ version mapping** (replaces hardcoded
   `ubuntu_version_names`). Useful in the legacy passthrough where
   normalized-cve-data records have codenames like `bionic` instead of
   `18.04`. Phase 1: lazy fetch with disk cache, fall back to the
   hardcoded map if the API is unreachable. Phase 2: drop the hardcoded
   map entirely.
2. **Sanity checks** (optional). Warn if a release endoflife.date says
   `isMaintained: true` is missing from today's OSV tarball (Canonical
   regression). Warn if we have a fragment for a release endoflife.date
   doesn't recognize (stale fragment). Non-load-bearing.

---

## Provider config

```python
@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            existing_input=provider.InputStatePolicy.KEEP,
        ),
    )
    request_timeout: int = 125
```

Drops: `additional_versions`, `enable_rev_history`, `parallelism`,
`git_url`, `git_branch` — all artifacts of the old git-based parser.

`Provider.tags()` keeps `vulnerability`, `os`. Drops `multicore`,
`incremental`, `large` — the new download is a single 30 MB streaming
fetch; total wall time should drop substantially.

**`compatible_schema()` is NOT implemented.** The parser yields
`(identifier, Schema, payload)` triples directly, and `Provider.update()`
passes each tuple's schema straight into `writer.write(...)`. The
`compatible_schema` classmethod is a provider-internal filter that
bitnami uses to gate on schema version — we don't need that filter since
the parser is the one constructing schema objects (it can only construct
ones it understands).

---

## Touch list

- `src/vunnel/providers/ubuntu/__init__.py` — Provider/Config (mostly
  unchanged from the current branch; already on the new shape).
- `src/vunnel/providers/ubuntu/parser.py` — replace `_extract()` +
  `_iter_osv_records()` + `_iter_legacy_records()` with the streaming
  + per-ecosystem-fragment + normalized-cve-data passthrough flow.
- `src/vunnel/providers/ubuntu/parser_legacy.py` (new) — vendor the
  minimum slice of v3 parser (`CVEFile`, `Patch`, `map_parsed`,
  `map_namespace`) needed to consume `normalized-cve-data`. No
  `GitWrapper`, no resolver, no rev-history walker.
- Tests:
  - `tests/unit/providers/ubuntu/test_ubuntu.py` — replace
    `TestParserOSVIteration` with `TestParserFragmentWriter`. Add
    freeze-on-missing-ecosystem and wipe-on-present-ecosystem tests.
  - Add a `normalized-cve-data` fixture directory + legacy passthrough
    tests.
  - Snapshots: regenerate with the new identifier shape.
- `tests/quality/` — re-run `vulnerability-match-labels` once the
  fragment design lands.
- `scripts/build_ubuntu_legacy_db.py` — repurpose or delete. With the
  fragment shape it's no longer relevant for the OSV path; could become
  a phase-2 conversion tool that builds fragments from
  `normalized-cve-data`.
- DEVELOPING.md — operator notes for dead-file cleanup in `input/`.

---

## Open questions

1. **Schema mixing downstream.** Does grype-db's importer accept two
   schema URLs (OSV + OS) from one provider's `results.db`? Gating
   question — confirm with the grype-db team before merging. We own
   grype-db, so the answer is "fix it if it doesn't work."
2. ~~**Pro/FIPS sub-ecosystem collapse.**~~ **Resolved: keep them
   separate.** Pro/FIPS/Realtime/Nvidia ecosystems are commercially
   distinct subscription tiers with their own fix policies and CVE
   coverage. Downstream may eventually want them as separate namespaces
   for accurate matching against subscription-bearing customers.
   Collapsing at slice time would lose the ecosystem distinction and be
   hard to reverse. Cost of keeping them separate: ~2.5 GB of fragment
   storage across 20 sub-ecosystems. Worth it to keep the door open for
   future Pro/ESM-aware matching.
3. **Phase 2 timing.** When do we convert `normalized-cve-data` into
   fragment files and drop the v3 mapper? Probably one release cycle
   after phase 1 ships, once we're confident no workspace is missing
   the cache. Worth a follow-up issue.
4. **Apply `_patch_fix_date` to legacy records?** Debian does
   (`parser.py:512`); for OS-schema records the fix-date hook lives in
   `FixedIn[].Available`, not in `database_specific.anchore`. A separate
   patcher would be needed. **Lean: skip.** Legacy data is frozen by
   definition; defer until we have a reason to change it.

---

## Phasing

1. ~~Land this spec; gather feedback.~~ Done (this revision).
2. ~~Stand up the OSV ingest with extract-to-disk + single-results.db
   passthrough.~~ Done (current branch; 18 unit tests passing).
3. **Refactor to streaming + per-ecosystem fragments.** Replace
   `_extract`/`_iter_osv_records` with streaming tar reader + fragment
   writers. Replace single-`legacy/results.db` passthrough with
   `normalized-cve-data` + `map_parsed()` legacy path. Update tests +
   snapshots.
4. **Wire endoflife.date for codename mapping.** Replace the v3
   hardcoded `ubuntu_version_names` dict with a lazy fetch + disk
   cache.
5. **Validate against grype-db.** Resolve open questions 1 and 2 with a
   small probe (mixed-schema results.db + Pro/FIPS variant test).
   Iterate on grype-db side if needed.
6. **Run `tests/quality/`** — confirm `vulnerability-match-labels` is
   stable. Note that this branch was already dirty on quality tests
   before the rewrite.
7. **Cut PR.** Coordinate with grype-db owners on the mixed-schema
   envelope and Pro/FIPS handling.
8. **Phase 2 (follow-up):** convert `normalized-cve-data` to fragments,
   drop v3 mapper, drop `parser_legacy.py`, shave ~3.3 GB off
   `input/`.

---

## Revision history

- **2026-05-27** (current): switched from single `osv/` extracted
  directory + single `legacy/results.db` to **per-ecosystem
  `fragments/*.db`** with **streaming tarball read** (no extraction to
  disk). Switched legacy source from a frozen v3 `results.db` snapshot
  (operator-curated via `build_ubuntu_legacy_db.py`) to **direct read
  of `normalized-cve-data/`** (already in every v3 workspace,
  no operator action). Added endoflife.date integration plan. Added
  phase 2 plan for converting normalized-cve-data to fragments.
  Confirmed Canonical uses OSV `withdrawn` (6.1% of records) and added
  withdrawn-handling section. Resolved Pro/FIPS sub-ecosystem collapse
  as "keep separate" to preserve future Pro/ESM-aware matching.
- **2026-05-22** (initial): extract-to-disk + monolithic legacy
  passthrough design. See git history at commit `ac45370` for the
  original spec.
