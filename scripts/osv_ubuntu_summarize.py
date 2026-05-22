#!/usr/bin/env python3
"""
Summarize the contents of Canonical's osv-all.tar.xz.

Prints counts of CVE vs USN records, distinct schema versions, distinct
ecosystem strings, and a histogram of fixed-event counts per record type.
Useful as context for interpreting the cve-vs-usn coverage comparison.

Usage:
    python scripts/osv_ubuntu_summarize.py <path-to-tarball-or-extracted-dir>
"""

from __future__ import annotations

import json
import os
import sys
import tarfile
import tempfile
from collections import Counter


def extract_if_needed(path: str) -> str:
    if os.path.isdir(path):
        return path
    if path.endswith((".tar.xz", ".tar")):
        tmp = tempfile.mkdtemp(prefix="osv-ubuntu-")
        print(f"extracting {path} -> {tmp}", file=sys.stderr)
        with tarfile.open(path, "r:*") as tar:
            tar.extractall(tmp)  # noqa: S202 - local analysis script
        return tmp
    raise SystemExit(f"unknown input: {path}")


def count_fixes(record: dict) -> int:
    n = 0
    for aff in record.get("affected", []):
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if ev.get("fixed"):
                    n += 1
    return n


def histogram_bucket(n: int) -> str:
    if n == 0:
        return "0"
    if n == 1:
        return "1"
    if n <= 5:
        return "2-5"
    if n <= 20:
        return "6-20"
    return "21+"


def walk_records(root: str, subdir: str):
    base = os.path.join(root, "osv", subdir)
    if not os.path.isdir(base):
        raise SystemExit(f"missing {base}")
    for dirpath, _, files in os.walk(base):
        for fname in files:
            if fname.endswith(".json"):
                with open(os.path.join(dirpath, fname)) as f:
                    yield json.load(f)


def summarize(root: str, kind: str) -> None:
    n = 0
    schema_versions: Counter[str] = Counter()
    ecosystems: Counter[str] = Counter()
    upstream_count: Counter[int] = Counter()
    fix_hist: Counter[str] = Counter()
    no_fix_records = 0

    for rec in walk_records(root, kind):
        n += 1
        schema_versions[rec.get("schema_version", "?")] += 1
        upstream_count[len(rec.get("upstream", []))] += 1
        for aff in rec.get("affected", []):
            eco = aff.get("package", {}).get("ecosystem")
            if eco:
                ecosystems[eco] += 1
        fixes = count_fixes(rec)
        if fixes == 0:
            no_fix_records += 1
        fix_hist[histogram_bucket(fixes)] += 1

    print(f"\n=== {kind} ({n} records) ===")
    print(f"  schema_version: {dict(schema_versions)}")
    print(f"  records with 0 fix events: {no_fix_records} ({100.0 * no_fix_records / n:.1f}%)")
    print(f"  fix-event histogram (per record): {dict(fix_hist)}")
    print(f"  upstream-ref length histogram: {dict(sorted(upstream_count.items()))}")
    print(f"  top 10 ecosystems:")
    for eco, cnt in ecosystems.most_common(10):
        print(f"    {cnt:>8}  {eco}")
    print(f"  total distinct ecosystems: {len(ecosystems)}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    root = extract_if_needed(sys.argv[1])
    summarize(root, "cve")
    summarize(root, "usn")


if __name__ == "__main__":
    main()
