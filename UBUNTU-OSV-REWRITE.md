# Ubuntu Provider OSV Rewrite — Spec

Status: draft
Branch: `vex-ubuntu-rewrite`
Owner: Will Murphy

## Goal

Rewrite the Ubuntu provider so that it ingests Canonical's published OSV
tarball as its source of truth, instead of parsing the `ubuntu-cve-tracker`
git repo line-by-line. The new provider emits OSV-shaped records for
releases Canonical publishes data for, and continues to emit the existing
OS-schema records for releases Canonical no longer covers (legacy
passthrough, modeled on the Debian provider's `input/legacy/` mechanism).

## Why

- Canonical now publishes a maintained OSV feed; consuming it removes the
  bespoke parser, the bzr→git transition handling, and the revision-history
  walk for EOL releases.
- OSV is the schema we want new downstream consumers to grow against
  (matches bitnami, etc.).
- The current parser does heavy work to derive fixed-version info that the
  OSV feed gives us natively.

## Non-goals

- Re-deriving severity/priority differently than Canonical publishes — we
  defer to the OSV record's severity.
- Migrating existing archived results from OS schema to OSV schema. The
  old shape is preserved on disk as legacy data; we do not rewrite history.
- **Interpreting Ubuntu-specific fields in the OSV record.** Release
  codenames, binary vs. source package names, ESM channels, etc. are
  passed through to grype-db's OSV transformer. The provider's job is to
  download, patch fix dates, and emit; downstream owns the semantics.

---

## Source data

- URL: `https://security-metadata.canonical.com/osv/osv-all.tar.xz`
- Format: `tar.xz` archive of per-record OSV JSON files.
- Schema declared in records: `1.7.0` (a small tail of `1.6.3` also
  observed). We pass the record's declared version straight through into
  `OSVSchema(version=...)`; see "Schema version" below.
- Coverage: Canonical-supported releases only. Anything Ubuntu has dropped
  from upstream (e.g. precise, trusty pre-ESM, etc.) is **not** in the
  archive and must come from the legacy cache.

The archive is streamed to disk via `http_wrapper.get(..., stream=True)`
and extracted with `vunnel.utils.archive.extract()` (which already handles
`.tar.xz` via `tarfile.open(mode="r:*")`).

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
of the Ubuntu-specific fields — `ecosystem`, `purl`, `ecosystem_specific.binaries`,
`database_specific.cves_map` all pass through to grype-db's OSV transformer.

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

Those ~280 are preserved automatically by the legacy passthrough (they
appear in the current provider's `results.db`, which we freeze into
`input/legacy/`). So dropping USN ingestion is a **no-op regression
versus the current provider**.

The remaining ~1,130 USN-only fix tuples (mostly kernel variants —
`linux-*`, `nvidia-graphics-drivers-*`, `intel-microcode` — and recent
2025/2026 advisories) are net-new ground we'd gain from USN parsing, but
nothing today depends on them. Adding USN parsing later is mechanical:
walk `osv/usn/*.json` with the same loader, no schema/wiring change.

### Record shape highlights (for sanity, not for parser logic)

- `affected[].package.ecosystem` is `Ubuntu:{version}:LTS` or
  `Ubuntu:{version}` — three-segment, distinct from the legacy
  `ubuntu:{version}` namespace shape.
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

After this lands, `data/ubuntu/input/` will still contain artifacts from
the v3 provider on existing workspaces:

- `ubuntu-cve-tracker/` (the git clone — ~hundreds of MB)
- `normalized-cve-data/` (the merged-state cache)
- `ubuntu-security-notices.zip` (USN scrape from a prior experiment)
- `vex-all.tar.xz`, `vex/` (VEX experiment, prior branch)

The new provider leaves these alone. Recommend a one-liner in
DEVELOPING.md telling operators to manually wipe them when migrating, or
have the new provider opportunistically delete known-dead paths on first
run.

---

## Output shape

The provider writes a **mixed-schema `results.db`**:

| Record source | Schema written | `Envelope.schema` URL |
|---|---|---|
| OSV records from `osv-all.tar.xz` | `OSVSchema(record["schema_version"])` | `…/osv/schema-1.7.0.json` (mostly) |
| Legacy passthrough (e.g. precise, eoan, kinetic) | `OSSchema` (whatever the envelope was written with) | `…/os/schema-1.1.0.json` |

`Provider.__schema__` is `OSVSchema()` — that's the schema the provider
*generates by default*. The parser hands back the actual schema object
alongside each record (OSV records carry the version pulled from
`record["schema_version"]`; legacy records carry the envelope's frozen
OS-schema URL untouched).

### Versioning

- **`__version__` stays at 3.** Processing-version field; bumping it
  would trip `provider.py:282-285` and `workspace.clear()` the input
  directory between runs — which wipes the legacy cache.
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
`input/legacy/results.db`. Don't change either without confirming
downstream can be re-seeded.

Downstream needs to handle mixed schemas in one `results.db` — different
schema *families* (OSV + OS) coexisting in the envelopes from a single
provider run. Confirm with grype-db before merging.

---

## Architecture

```
Provider.update()
 └─ Parser.get() yields (identifier, schema, payload)
      ├─ download_archive()       — stream osv-all.tar.xz to input/
      ├─ extract_archive()        — extract to input/osv/
      ├─ fixdater.download()
      ├─ for each legacy envelope:                    # legacy FIRST
      │     yield (id, env.schema, env.item)
      └─ for each file in osv/cve/**:                 # OSV LAST (wins)
            osv.patch_fix_date(record, fixdater)
            yield (id, OSVSchema, record)
```

**Emission order matters.** SQLite store uses `INSERT OR REPLACE` keyed
by identifier, so whichever record is emitted *last* wins on collision.
Legacy is emitted first; OSV overwrites if the same identifier appears in
both. Rationale: Canonical's feed is the authority for any release it
covers. Legacy data only fills gaps for releases the feed has dropped —
it should never override fresh upstream data.

### Identifier shapes (no natural collision)

- **OSV records:** `record["id"].lower()` — e.g.
  `ubuntu-cve-2011-0221`. One identifier per file in `osv/cve/**`.
  (USN ingestion is deferred, so no `usn-*` identifiers in the initial
  cut.) This matches the bitnami precedent at
  `providers/bitnami/__init__.py:75`.
- **Legacy records:** lifted from the existing envelope's `identifier`
  field — `ubuntu:{release}/{cve}`, e.g. `ubuntu:14.04/cve-2011-0221`.

These do **not** collide. The legacy entries are keyed by
(release, CVE), while the OSV entries are keyed by (CVE) or (USN). Both
shapes coexist in the output `results.db` and downstream interprets them
through their envelope schema URL.

The "OSV wins on collision" rule from the emission-order section above
is therefore policy-only — in practice nothing collides, so the order
doesn't actually overwrite anything today. We still want OSV emitted
last in case a future legacy seed uses the same identifier scheme.

### File layout

```
input/
  osv-all.tar.xz              # downloaded archive (overwritten each run)
  osv/                        # extracted archive contents (wiped + re-extracted each run)
    cve/{year}/UBUNTU-CVE-*.json
    usn/USN-*.json            # present but not ingested in this cut
  legacy/                     # manually-curated frozen results (persists between runs)
    results.db                # produced by scripts/build_ubuntu_legacy_db.py
results/
  results.db                  # mixed-schema output
```

**Input directory is operationally load-bearing.** The provider's
`__init__` must guard against any config that lets the framework wipe
`input/`, because `input/legacy/results.db` is the only source of records
for releases Canonical has dropped from the OSV feed. Losing it requires
reseeding from a frozen pre-rewrite production `results.db`, which may
not be readily available.

Two checks (both in `__init__`):

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

Notably, the v3 ubuntu provider sets `existing_input=KEEP` as a default
but does NOT call the guard — a caller who passes
`RuntimeConfig(existing_input=DELETE)` would silently get `input/` wiped
between runs. Under v3 that costs the git clone (rebuildable). Under the
new design it costs the legacy cache (unrecoverable).

---

## Components

### 1. Streaming download (`Parser._download`)

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

The xz archive is large enough that buffering the full body in memory is
wasteful — `stream=True` + chunked writes throughout.

### 2. Extraction

`vunnel.utils.archive.extract(archive_path, extract_dir)` — already
handles tar.xz transparently and applies path-traversal filtering.

**Wipe `input/osv/` before extracting.** Records that Canonical drops
from the feed (e.g. a CVE rotated out of `osv/cve/{year}/`) would
otherwise linger on disk from a prior run and silently get re-emitted as
stale data. `shutil.rmtree(osv_dir, ignore_errors=True)` immediately
before `extract()` is sufficient. The archive itself (`osv-all.tar.xz`)
is overwritten by the streaming download, so that side handles itself.

### 3. Iteration + fix-date patching

Walk `osv/cve/**/*.json` yielding parsed records. For each record, call
`vunnel.utils.osv.patch_fix_date(record, self.fixdater)` before
yielding — identical to `providers/bitnami/parser.py:90`. That helper
populates `affected[].ranges[].database_specific.anchore.fixes[]` with
`{version, date, kind}` triples derived from the fixdate `Finder`.

About 38% of CVE records carry no `fixed:` events (just
`{"introduced": "0"}`), so `patch_fix_date` is a no-op for them — that's
fine, the helper short-circuits gracefully. The remaining ~62% have
per-release fix versions that the helper populates.

`Parser` owns the `fixdate.Finder` and acts as a context manager so its
`__enter__`/`__exit__` propagate (same pattern as bitnami/debian).

### 4. No release filtering in the provider

The OSV record is passed through verbatim (after `patch_fix_date`). We do
**not**:
- map codenames → version numbers,
- drop releases that aren't in some allowlist,
- collapse binary↔source package names,
- normalize ESM channels,
- override severity.

Anything Ubuntu-specific in the OSV record is grype-db's OSV transformer
to interpret. The provider's contract is "what Canonical published, plus
fix dates."

This drops the `ubuntu_version_names` map, the `additional_versions`
config knob, and the patch-state machinery — all of it.

### 5. Legacy passthrough (the Debian-style cache)

Modeled directly on `providers/debian/parser.py:495-598`. Reads from
`workspace.input_path/legacy/`:

- **SQLite source:** `glob('legacy/**/results.db')` → `SQLiteReader` →
  iterate envelopes. Yield each envelope's identifier/schema/item
  unchanged. Envelopes carry the OS schema URL and are emitted as-is.
- **JSON source (optional):** support `legacy/**/vulnerabilities*.json`
  for one-time seeding from the old feed-service data drop, matching
  Debian's `_get_legacy_records_from_feed_service_datadrop`.

Emit order: **legacy first**, then OSV. OSV wins on identifier collision
(see "Emission order matters" above).

Seeding the cache: use `scripts/build_ubuntu_legacy_db.py` to copy the
current provider's `results.db` and delete any namespace whose version
appears in osv/cve/** ecosystems. The script keeps interim/EOL releases
(12.04, 12.10, 13.04, 14.10, …, 23.10) and drops every namespace OSV now
covers (14.04, 16.04, 18.04, 20.04, 22.04, 24.04+). Document this in
DEVELOPING.md as the operational seed step.

#### Open question: do we apply `_patch_fix_date` to legacy records?

Debian does (`parser.py:512`). For legacy OS-schema records the fix-date
hook lives in `FixedIn[].Available`, not in `database_specific.anchore`.
A separate patcher would be needed. **Lean: skip.** Legacy data is frozen
by definition; defer until we have a reason to change it.

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

`Provider.tags()` keeps `vulnerability`, `os`. Drop `multicore`,
`incremental`, `large` — the new download is a single tar extract; total
wall time should drop substantially.

**`compatible_schema()` is NOT implemented.** The parser yields
`(identifier, Schema, payload)` triples directly, and `Provider.update()`
passes each tuple's schema straight into `writer.write(...)`. The
`compatible_schema` classmethod is a provider-internal filter that
bitnami uses to gate on schema version — we don't need that filter since
the parser is the one constructing schema objects (it can only construct
ones it understands).

---

## Touch list

- `src/vunnel/providers/ubuntu/__init__.py` — rewrite Provider/Config.
- `src/vunnel/providers/ubuntu/parser.py` — rewrite. Delete the line
  parser, patch resolver, revision-history walker, all of it.
- `src/vunnel/providers/ubuntu/git.py` — **delete**. No git interaction
  in the new design.
- Tests:
  - `tests/unit/providers/ubuntu/` — gut and rewrite. Add fixtures for a
    small `osv-all.tar.xz` and a small `legacy/results.db`.
  - `tests/quality/` — confirm vulnerability-match-labels still pass
    (note: `vulnerability-match-labels` is dirty on this branch already).

---

## Open questions

1. **Schema mixing downstream.** Does grype-db's importer accept two
   schema URLs (OSV + OS) from one provider's `results.db`? Gating
   question — confirm with the grype-db team before merging. (Not before
   starting; we can build and validate the vunnel side first.)
2. **Dead files cleanup.** Have the provider opportunistically remove
   `ubuntu-cve-tracker/`, `normalized-cve-data/`, etc. on first run? Or
   leave that to operators? Lean: leave to operators; document in
   DEVELOPING.md. Removing files unprompted from a kept `input/` is
   surprising.

---

## Phasing

1. ~~Land this spec; gather feedback on the open questions.~~ Done.
2. ~~Capture a frozen `legacy/results.db` for testing.~~ Done — see
   `data/ubuntu/input/legacy/results.db` (176k rows, 18 namespaces).
3. Rewrite `providers/ubuntu/__init__.py` and `parser.py`; delete
   `git.py`. Implement download → wipe → extract → iterate → legacy
   passthrough → write.
4. Wire `osv.patch_fix_date`. Confirm fix dates appear in
   `affected[].ranges[].database_specific.anchore.fixes[]` for ~62% of
   records that carry `fixed:` events.
5. Rewrite `tests/unit/providers/ubuntu/`. Add fixtures for a small
   mock `osv-all.tar.xz` and a small `legacy/results.db`.
6. Run `tests/quality/` and confirm vulnerability-match-labels (noting
   the existing dirty state on this branch).
7. Cut PR; coordinate with grype-db on the mixed-schema envelope before
   merging.
