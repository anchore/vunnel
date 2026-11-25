# CVE 5 test fixtures

Records are copied unmodified from the enriched CVE 5 dataset (`data/<year>/<bucket>/CVE-*.json` in the published `tar.zst`, build `cve-enriched-json-v5_2026-10-21T11:19:58Z`). `CVE-2023-2004.json` is a `REJECTED` record. `CVE-2022-35990.json` carries an `anchoreadp` entry that fails the CVE 5 schema (`lessThan` with no `versionType`). `CVE-2025-32897.json` and `CVE-2026-53424.json` carry the version bounds the fix-date tests read, and are packed only by those tests.
