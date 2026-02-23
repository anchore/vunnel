# Fix CPE format mismatch in grype-db fix date lookups

## Summary

This PR fixes a CPE format mismatch that prevented fix date lookups from finding matches in the grype-db historical database. Additionally, it includes minor improvements to logging and SQLite configuration.

## Problem

The grype-db fix date database stores CPEs in a simplified "v6" format (e.g., `a:vendor:product:1.0:::::`), while vunnel queries using the standard CPE 2.3 format (e.g., `cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`). This format mismatch caused lookups to miss valid matches in grype-db, resulting in:

- Unnecessary "first observed today" entries being created in the vunnel cache
- Loss of accurate historical fix date information that grype-db already had

## Solution

Added `cpe_to_v6_format()` to convert standard CPE 2.3 strings to the v6 format used by grype-db. Lookups now query for both formats, improving match rates against historical data.

Importantly, this change is safe for existing records:
- The vunnel store is always checked first with exact CPE matching
- Any previously recorded dates continue to be returned unchanged
- The v6 format conversion only affects new lookups where no vunnel record exists

## Other Changes

- **Logging improvements**: Added progress tracking and stats for fix date lookups to aid debugging
- **SQLite tuning**: Adjusted pragma settings (WAL mode, cache sizes, mmap) and moved pragma listeners to be instance-scoped rather than global
- **Thread-local connections**: SQLite connections are now thread-local to support concurrent access

## Testing

Existing unit tests pass.
