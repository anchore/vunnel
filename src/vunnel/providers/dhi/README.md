# Docker Hardened Images provider

The `dhi` provider ingests OS-package advisories for [Docker Hardened Images](https://www.docker.com/products/hardened-images/)
(DHI) from Docker's canonical [`docker-hardened-images/advisories`](https://github.com/docker-hardened-images/advisories)
repository and emits them unchanged as OSV provider results. Grype's `DHI-` OSV transformer turns them into
`dhi:distro:dhi:<release>` records.

## Source

| Setting            | Default                                                         |
|--------------------|-----------------------------------------------------------------|
| `repository_url`   | `https://github.com/docker-hardened-images/advisories.git`      |
| `repository_branch`| `main`                                                          |
| `advisories_path`  | `osv/dhi`                                                       |

Each run deletes any previous checkout, performs a shallow (`--depth 1`) clone of the configured branch into
`<workspace>/dhi/input/advisories`, and records the exact Git revision in the provider metadata `urls`
(`.../tree/<sha>/osv/dhi`). Set `runtime.skip_download: true` to reuse an existing checkout instead of cloning.

The repository publishes detached signatures and checksums (`*.sig`, `*.sha256`, `*.sha512`) alongside each
record. The provider does not verify them; only `*.json` files are read.

## Record selection and validation

The provider walks `advisories_path` recursively in sorted order and keeps records whose `id` starts with `DHI-`.
Any other JSON in that tree is ignored. A selected record must satisfy:

- `schema_version` is present and has the same major version as the provider schema (currently OSV 1.x); any
  other version fails the run rather than being skipped.
- `affected` is a non-empty list.
- every `affected[].package.ecosystem` starts with `Docker Hardened Images:` (for example
  `Docker Hardened Images:Alpine:3.24` or `Docker Hardened Images:Debian:13`).
- every `affected[].package.purl` is a `pkg:apk/dhi/...` or `pkg:deb/dhi/...` PURL.

Two records with the same `id` are tolerated only when their contents are identical; a conflicting duplicate
fails the run.

Example record:

```json
{
  "schema_version": "1.6.1",
  "id": "DHI-CVE-2016-2781-coreutils",
  "modified": "2026-06-30T00:00:00Z",
  "published": "2026-06-30T00:00:00Z",
  "upstream": ["CVE-2016-2781"],
  "affected": [
    {
      "package": {
        "ecosystem": "Docker Hardened Images:Alpine:3.24",
        "name": "coreutils",
        "purl": "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24"
      },
      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.11-r1"}]}],
      "versions": ["9.11-r0"]
    }
  ]
}
```

## Fix dates

DHI records do not carry fix-availability dates. As with the other OSV providers, each `fixed` event is passed
through the fix-date finder (`vunnel.utils.osv.patch_fix_date`), which consults the first-observed dataset and
falls back to the record's `published` date. The chosen date is written to
`affected[].ranges[].database_specific.anchore.fixes` as `{"version", "date", "kind"}` and consumed by grype-db.

## Output

Results are written to the SQLite result store keyed by the lower-cased advisory `id`, with the record payload
exactly as read from the repository apart from the `database_specific.anchore` fix-date annotation.

## Testing

Unit tests mock the clone step and read fixtures from `tests/unit/providers/dhi/test-fixtures/advisories`.
Regenerate the result snapshots with:

```bash
uv run pytest tests/unit/providers/dhi --snapshot-update
```
