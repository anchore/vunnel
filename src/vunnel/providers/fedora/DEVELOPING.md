# Developing for the Fedora Provider

## How this provider works

1. Fedora security updates are published via the [Bodhi](https://bodhi.fedoraproject.org) update system.
2. Vunnel queries the Bodhi REST API for all updates with `status=stable` and `type=security`.
3. Each update is saved as its own file (`<alias>.json`, e.g. `FEDORA-2025-21c36b3aa5.json`) in the input directory.
4. Vunnel parses each update, extracts CVEs, and normalizes the data into the OS vulnerability schema.

### Incremental updates

The provider supports incremental updates using the Bodhi API's `pushed_since` parameter:

1. **First run**: Full download of all stable security updates across all Fedora releases.
2. **Subsequent runs**: Only updates pushed to stable since `last_updated` are fetched. Each update is written to its own file, overwriting any previous version of the same update.

The one-file-per-update storage model makes incremental updates simple: new or modified updates just overwrite their file in place, with no deduplication or merge logic needed.

### CVE extraction

CVEs are extracted from each update using a three-tier fallback:

1. Security bugs (bugs where `security=true`) — CVE IDs are parsed from the bug title.
2. `display_name` field — checked if no CVEs found in bugs.
3. `title` field — last resort fallback.

If no CVEs are found at all, the advisory ID (e.g. `FEDORA-2025-aaa1111111`) is used as the vulnerability identifier.

### Output and cross-update merging

Each CVE produces a separate vulnerability record. An update that fixes two CVEs yields two records. Records are keyed as `fedora:<release>/<CVE-ID>` (e.g. `fedora:40/CVE-2025-1234`).

In Bodhi, the same CVE is often fixed by multiple independent updates for different packages. For example, CVE-2004-2779 was fixed in `libid3tag` by FEDORA-2018-e06468b832 and in `mingw-libid3tag` by FEDORA-2018-4e26c06aef. An audit of the full dataset found 2,808 (CVE, release) pairs with fixes spread across multiple updates — 2,425 of those involve different packages.

The provider merges these into a single vulnerability record per CVE by accumulating `FixedIn` entries across all updates that reference the same CVE. The first update processed provides the base record (severity, metadata, link), and subsequent updates for the same CVE append their `FixedIn` packages to it. This ensures grype can match against all affected packages, not just whichever update happened to be processed first.

Three cases arise in practice:

| Case | Example | Handling |
|------|---------|----------|
| Multiple CVEs fixed by one update | kernel update fixes CVE-2014-5471 and CVE-2014-5472 | Each CVE gets its own record; all share the same `FixedIn` list from that update |
| One CVE fixed in multiple packages by one update | NSS update ships `nss`, `nss-softokn`, and `nss-util` builds | One record with all packages in `FixedIn` |
| One CVE fixed by different updates for different packages | CVE-2004-2779 fixed in `libid3tag` and `mingw-libid3tag` separately | `FixedIn` lists are merged across updates into one record |

## Design decisions

### Why `pushed_since` and not `modified_since`?

We audited all 22,077 stable security updates in the Bodhi API (as of February 2025) and found:

- **80% of updates have no `date_modified` at all** — they were submitted and pushed without any edits. A `modified_since` query would miss all of these.
- **20% have both `date_pushed` and `date_modified`**, and in every case `date_pushed >= date_modified`. Zero counterexamples.

This makes sense: the typical Bodhi workflow is create → edit → push to testing → push to stable. Edits happen before the push, so `date_pushed` is always >= `date_modified`.

### Why we don't need to handle revocation or obsolescence

Bodhi has 5 update statuses: `pending`, `testing`, `stable`, `unpushed`, and `obsolete`.

**Stable updates never become obsolete.** Bodhi's automatic obsolescence only applies to `pending` and `testing` updates (when a newer build of the same package is submitted). We verified this against the API: out of 1,979 obsolete security updates, zero had ever been pushed to stable.

This makes sense: once an RPM is in the stable repo, it's a historical fact. Fedora doesn't "un-push" packages. When a newer build is released, it simply gets added to stable alongside the old one, and users upgrade via `dnf update`.

Similarly, the `unpushed` status is only reachable from `testing` or `pending` — an update that reached stable cannot be unpushed.

Therefore, our local `FEDORA-*.json` files for stable updates will never become stale due to status transitions.

## FAQ

### What if the Bodhi API changes?

The provider uses the Bodhi REST API v1 (`/updates/` endpoint). The query parameters used are: `status`, `type`, `releases`, `rows_per_page`, `page`, and `pushed_since`. These are well-established and documented in the [Bodhi API docs](https://fedora-infra.github.io/bodhi/8.3/python_bindings.html).

### What happens if a download fails partway through?

- **Full sync failure**: Some update files may have been written, but `last_updated` is not recorded. The next run does a full sync from scratch (clearing partial files first).
- **Incremental failure**: Already-saved files from the current and previous runs remain on disk. Since `last_updated` is not updated, the next run retries the same time window, re-fetching and overwriting as needed. The results store (SQLite) is transactional — partial results are discarded on failure.

### What does the `releases` config option do?

By default (`releases: []`), the provider fetches updates for all Fedora releases from the Bodhi API. Setting `releases: ["40", "41"]` restricts it to specific releases. The release value corresponds to the version number (e.g. `"40"` queries for `F40`).
