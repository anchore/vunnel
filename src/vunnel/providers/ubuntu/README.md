# Ubuntu provider

Ingests Canonical's published OSV and OpenVEX feeds, augments them with the
fix-disposition signal that OSV omits, and emits per-ecosystem
`results.db` fragments plus an OS-schema passthrough for releases that
were EOL before Canonical started publishing OSV.

## Data sources

The provider reads three things, in priority order:

| Source | URL / path | Role | Lifecycle |
|---|---|---|---|
| OSV CVE feed | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` | Authoritative ranges + fix versions for currently-tracked releases | Streamed each run, never extracted to disk |
| OpenVEX feed | `https://security-metadata.canonical.com/vex/vex-all.tar.xz` | Fix disposition (won't-fix vs other) — see "Why VEX" below | Streamed each run; in-memory index, not persisted |
| `input/normalized-cve-data/` | local | At-cutover EOL releases (precise → mantic) that have never appeared in either of the above | Frozen; populated by the v3 provider, kept untouched after v3's removal |
| (fix-date cache) | `input/grype-db-observed-fix-dates.db` | First-observed dates for fixed versions; standard across providers | Refreshed each run |

USN records inside `osv-all.tar.xz` (`osv/usn/**`) are **not ingested**.
97% of their fix tuples are already in the CVE records they reference;
the remaining ~280 source-reachable tuples are preserved automatically
by `normalized-cve-data`. Adding USN parsing later is a parser change
only — no schema or wiring impact.

## Output: per-ecosystem fragments + legacy passthrough

```
data/ubuntu/
  input/
    osv-all.tar.xz                # today's download (overwritten each run)
    vex-all.tar.xz                # today's download (overwritten each run)
    fragments/                    # persistent, load-bearing
      ubuntu-14.04-lts.db
      ubuntu-18.04-lts.db
      ubuntu-20.04-lts.db
      ubuntu-pro-16.04-lts.db
      ubuntu-pro-fips-updates-20.04-lts.db
      …                           # one per distinct ecosystem string
    normalized-cve-data/          # frozen at-cutover EOL data (phase 1)
    grype-db-observed-fix-dates.db
  results/
    results.db                    # mixed-schema (OSV + OS) output
```

Each fragment file is an envelope-shaped `results.db` containing only
one ecosystem's slices. Envelope identifier is
`{ecosystem-slug}/{cve-id-lowercase}`, e.g.
`ubuntu-20.04-lts/ubuntu-cve-2024-1234`.

### Why per-release fragments when Canonical publishes per-CVE

OSV records describe a CVE across N releases in one document. We
re-shard into one envelope per (release, CVE) for two reasons:

1. **Survive EOL transitions without operator action.** When a release
   drops out of the OSV feed (currently lunar/kinetic/etc.; eventually
   questing/plucky/oracular), its fragment file simply stops being
   rewritten. The fragment persists, frozen at the last-known state, and
   subsequent runs continue to emit it. There is no hardcoded EOL list
   and no manual snapshot step — the on-disk set of fragments IS the
   list of releases the provider knows about. When 25.10 EOLs in 2026
   the same machinery handles it.

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
      ├─ _download_archive()       # stream osv-all.tar.xz to disk
      ├─ _download_vex_archive()   # stream vex-all.tar.xz to disk
      ├─ fixdater.download()
      ├─ _load_vex_overlay()       # build in-memory wont-fix index
      ├─ _write_fragments(overlay):
      │     for each osv/cve/**/*.json (streaming, no extraction):
      │         slice_by_ecosystem(record)        # group affected[] by ecosystem
      │         _annotate_wont_fix(...)           # stamp anchore.status from VEX
      │         for each slice:
      │             open fragment writer (lazy, DELETE_BEFORE_WRITE)
      │             insert envelope
      ├─ yield from _iter_normalized_cve_data()   # legacy first
      └─ yield from _iter_fragments()             # OSV second
            (patch_fix_date applied here, at yield time)
```

Two annotations live in `affected[].database_specific.anchore`:

- `fixes[]` — `{version, date, kind}` derived from the fix-date cache.
  Applied **at yield time**, not at write time. This means improvements
  to the fix-date cache flow through to frozen fragments on the next run
  without rewriting them.
- `status` — `"wont-fix"` when Canonical's VEX feed marks this
  `(cve, distro, source-pkg)` as won't-fix. Applied **at write time**,
  baked into the fragment. When a release later EOLs and VEX stops
  carrying it, the frozen fragment retains the disposition.

These two annotations have opposite update semantics on purpose. Fix
dates can be refined retroactively from new tracking data; disposition
is a "what Canonical decided at this moment" snapshot that must survive
the release leaving both upstream feeds.

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

The provider downloads VEX, prefix-matches `action_statement` against
the won't-fix openings, and indexes the resulting
`(cve_id, distro_label, source_package)` tuples. At fragment-write time
each OSV slice's `(cve, distro, source-pkg)` is looked up; matches get
`affected[].database_specific.anchore.status = "wont-fix"`. The grype
v6 ubuntu transformer reads that annotation and emits `WontFixStatus`,
producing the `(won't fix)` annotation users see in scan output.

The join key is the PURL `distro=` qualifier (e.g. `distro=noble`,
`distro=esm-infra/jammy`). Both OSV and VEX embed it identically — no
codename/version translation needed.

## Why `normalized-cve-data` is still load-bearing

Live VEX has **the same coverage gap as live OSV**: only currently-
tracked releases are present (jammy, noble, focal, bionic, trusty/ESM,
xenial/ESM, questing, plus Pro/FIPS/etc.). Releases that were EOL
before Canonical's OSV/VEX feeds launched — precise, quantal, raring,
saucy, utopic, vivid, wily, yakkety, zesty, artful, cosmic, disco,
eoan, groovy, hirsute, impish, kinetic, lunar, mantic, oracular — are
absent.

The v3 provider's `normalized-cve-data/` cache covers those releases
(it was populated from `ubuntu-cve-tracker` git history before v3 was
retired). The new provider reads it via the vendored `map_parsed` from
`parser_legacy.py` and emits OS-schema envelopes for releases not
already covered by an OSV fragment.

`normalized-cve-data` records carry `status: "ignored"` directly, which
`map_parsed` already converts to `FixedIn[].VendorAdvisory.NoAdvisory =
True` — grype's OS transformer renders this as `WontFixStatus`. So the
EOL slice already preserves won't-fix without any VEX involvement; the
overlay only matters for the OSV path.

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

Canonical uses the OSV `withdrawn` field (6.1% of records today) for
retractions. They do **not** delete records from the tarball, so a
withdrawn CVE's `withdrawn` timestamp rides through the slicing into
each fragment payload. The grype `ubuntuStrategy` skips withdrawn
records entirely; the legacy passthrough is the only path a
withdrawn-by-OSV CVE can still reach the DB (via a frozen `results.db`
row for an EOL release).

## What grype expects

The v6 dpkg matcher queries by namespace via `search.ByDistro`. The
grype OSV transformer
([`grype/db/v6/build/transformers/osv/transform_ubuntu.go`](https://github.com/anchore/grype/blob/main/grype/db/v6/build/transformers/osv/transform_ubuntu.go))
turns each fragment envelope into the same DB row shape the legacy OS
transformer produces. Notable mappings:

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
