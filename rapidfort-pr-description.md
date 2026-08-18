# feat: add RapidFort vulnerability provider

## Summary

Adds a new `rapidfort` provider that ingests security advisory data from the
[RapidFort security-advisories](https://github.com/rapidfort/security-advisories)
GitHub repository and normalizes it into vunnel's OSSchema format for consumption
by Grype.

RapidFort advisories are intended for use when scanning RapidFort-curated images
(identified via maintainer metadata) to apply RapidFort-specific version checks
that differ from upstream distro advisories.

## What's included

### New provider — `src/vunnel/providers/rapidfort/`

| File | Purpose |
|------|---------|
| `__init__.py` | `Provider` and `Config` classes; registered in the global provider registry |
| `parser.py` | Advisory loading, normalization, and event-range processing |
| `git.py` | Shallow-clone wrapper (`--depth=1`) with retry-backoff for the advisory repo |

**Supported OS types and version formats:**

| OS | Version format | Example namespace |
|----|---------------|-------------------|
| Ubuntu | `dpkg` | `rapidfort-ubuntu:22.04` |
| Alpine | `apk` | `rapidfort-alpine:3.15` |
| Red Hat | `rpm` | `rapidfort-redhat:el9` |

**Namespace isolation:** advisories are stored under `rapidfort-{os}:{version}`
(e.g. `rapidfort-ubuntu:20.04`) so Grype keeps them separate from standard
upstream distro scans.

### Key design decisions

- **Event-based version ranges** (mirrors GHSA semantics): each `introduced`/`fixed`
  pair in an advisory event becomes a separate `FixedIn` entry with a
  `VulnerableRange` field. A single CVE can produce multiple `FixedIn` entries
  when it affects more than one release branch.
- **Release identifiers**: Red Hat advisories carry per-event identifiers (e.g.
  `el9`, `fc36`) that are preserved in the `Identifier` field and reflected in
  `VendorAdvisory.AdvisorySummary`.
- **Fix availability**: integrates with the existing `fixdate` system to populate
  the `Available` field on each `FixedIn` entry.
- **Merge across packages**: when the same CVE appears in multiple package files,
  `FixedIn` entries are merged into a single vulnerability record.

### Registration

- `src/vunnel/providers/__init__.py` — provider added to the global registry
- `src/vunnel/cli/config.py` — `Config` added to the `Providers` dataclass for
  CLI/YAML configuration

### Tests — `tests/unit/providers/rapidfort/`

| Test class / function | What it covers |
|-----------------------|----------------|
| `TestEventsToRangePairs` | Range-pair conversion: single, multi-range, introduced-only, fixed-only, deduplication, identifier preservation |
| `TestNormalize` | Multi-range CVE produces multiple `FixedIn` entries; `Available` field present; Red Hat per-range identifiers and `VendorAdvisory` |
| `TestMergeIntoNamespace` | Same CVE in two packages merges into one record; distinct CVEs stay separate |
| `TestMapSeverity` | Case-insensitive known severities; `Unknown` for `None`, empty string, unrecognized values |
| `test_provider_schema` | Full provider output validates against `schema-1.1.0.json` |
| `test_provider_via_snapshot` | Regression snapshots for Ubuntu, Alpine, and Red Hat advisory output |

**Test fixtures** cover all three supported OS types:

```
test-fixtures/
├── input/rapidfort-advisories/OS/
│   ├── ubuntu/curl_advisory.json      # multi-range CVE (2 events)
│   ├── alpine/zlib_advisory.json      # single-range CVE, apk format
│   └── redhat/curl_advisory.json      # per-release identifiers (el9/fc36/fc37)
└── snapshots/
    ├── rapidfort-ubuntu:20.04/
    ├── rapidfort-alpine:3.15/
    └── rapidfort-redhat:el9/
```

## Test plan

- [ ] `pytest tests/unit/providers/rapidfort/` — all 17 tests pass
- [ ] Verify `vunnel run rapidfort` clones the advisory repo and writes results
- [ ] Confirm `vunnel list` shows `rapidfort` in the provider list
- [ ] Confirm Grype resolves `rapidfort-ubuntu:*` / `rapidfort-alpine:*` /
      `rapidfort-redhat:*` namespaces when scanning RapidFort-curated images
