# NVD Fix-Date Performance Analysis

## Problem Summary

Two related bottlenecks cause NVD provider syncs to run slowly, both sharing the same root cause: per-item I/O inside a hot loop.

---

## Bottleneck 1: `NVDOverrides.cve()` — Per-CVE File Reads

**Location:** `src/vunnel/providers/nvd/overrides.py`

**Root cause:** `cve()` maintained a filepath index (CVE ID → path on disk) but opened, read, and JSON-parsed the file on every single call. With ~250k CVEs in a full sync, that is ~250k `open()` + `json.loads()` calls — one per CVE lookup.

A `# TODO: implement in-memory index` comment already marked the problem in the original code.

**Fix:** Replace the filepath index with a fully parsed in-memory dict built once on first access. All subsequent `cve()` calls become O(1) dict lookups with zero I/O.

---

## Bottleneck 2: `GrypeDBStore.get()` — Per-CPE SQLite Queries

**Location:** `src/vunnel/tool/fixdate/grype_db_first_observed.py`

**Root cause:** `get()` executed an individual `SELECT` against the SQLite fix-date database for every `(vuln_id, cpe_or_package)` pair during NVD processing. Each CVE can have 5–20 CPE matches, and a full NVD sync processes ~250k CVEs, yielding:

```
250,000 CVEs × 5–20 CPE matches = 1,250,000 – 5,000,000 SQLite queries per sync
```

Each query incurred:
- Python → SQLAlchemy → SQLite3 driver overhead
- A full query plan execution (even with indexes)
- Result deserialization

At even 0.1 ms per query, 2.5M queries = ~4 minutes of pure SQLite overhead.

**Scale of the problem:** The fix-date database typically contains tens of thousands of rows (one per CVE/package combination where a fix date was observed). The entire table fits comfortably in memory.

---

## Fix: Bulk-Load Both into Memory at Startup

The fix for both bottlenecks is the same pattern: **load once, look up in O(1)**.

### NVDOverrides fix

`_build_data_by_cve()` globs all `CVE-*.json` files, reads and parses each once, and stores the result in `__data_by_cve__: dict[str, Any]`. The dict is populated lazily on first call and reused for all subsequent `cve()` calls.

### GrypeDBStore fix

`_build_index()` executes a single `SELECT * FROM fixdates` after the ORAS download completes, then splits the results into two in-memory dicts:

- `_cpe_index`: keyed by `(vuln_id.lower(), full_cpe.lower())`
- `_pkg_index`: keyed by `(vuln_id.lower(), package_name.lower(), ecosystem.lower())`

`get()` is replaced with dict lookups against these indexes. The index is built lazily on first `get()` call, ensuring it works correctly whether or not the download was a no-op (digest cache hit).

The SQLAlchemy connection infrastructure (`_get_connection`, `cleanup_thread_connections`) is retained — it is still required by `get_changed_vuln_ids_since()`, which queries the `runs` table separately.

---

## Files Changed

| File | Change |
|------|--------|
| `src/vunnel/providers/nvd/overrides.py` | In-memory JSON dict; remove per-call file reads |
| `src/vunnel/tool/fixdate/grype_db_first_observed.py` | Add `_build_index()`, replace `get()` with dict lookup |
| `tests/unit/providers/nvd/test_overrides.py` | Update field name, add in-memory assertion |
| `tests/unit/tool/test_grype_db_first_observed.py` | Add index-based test |
