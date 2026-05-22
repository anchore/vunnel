#!/usr/bin/env python3
"""
Test the hypothesis: USN records carry no information that isn't already
present in their upstream UBUNTU-CVE-* records, so the ubuntu provider
can parse only osv/cve/ and skip osv/usn/.

For every USN, we compare three things against the union of its upstream
UBUNTU-CVE-* records:

  1. Fix tuples    (ecosystem, source_pkg, fixed_version)
  2. Affected keys (ecosystem, source_pkg)
  3. Binary tuples (ecosystem, source_pkg, binary_name, binary_version)

If USN data is genuinely a strict subset of what's in the referenced CVE
records, all three coverage percentages will be ~100%.

Usage:
    python scripts/osv_ubuntu_compare.py <path-to-tarball-or-extracted-dir>
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


def collect_fix_tuples(record: dict) -> set[tuple[str, str, str]]:
    out = set()
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if not eco or not name:
            continue
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                fixed = ev.get("fixed")
                if fixed:
                    out.add((eco, name, fixed))
    return out


def collect_affected_keys(record: dict) -> set[tuple[str, str]]:
    out = set()
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if eco and name:
            out.add((eco, name))
    return out


def collect_binary_tuples(record: dict) -> set[tuple[str, str, str, str]]:
    out = set()
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if not eco or not name:
            continue
        for b in aff.get("ecosystem_specific", {}).get("binaries", []):
            bname = b.get("binary_name")
            bver = b.get("binary_version")
            if bname and bver:
                out.add((eco, name, bname, bver))
    return out


def coverage(
    label: str,
    usn_sets: dict[str, set],
    cve_sets: dict[str, set],
) -> None:
    """Compare each USN's set against the union of its upstream CVE sets.

    usn_sets[usn_id] -> set of tuples from the USN
    cve_sets[cve_id] -> set of tuples from a CVE
    """
    total = 0
    covered = 0
    missing = 0
    samples: list[tuple[str, tuple]] = []
    usns_with_orphans = 0

    for usn_id, usn_set in usn_sets.items():
        cve_union: set = set()
        for cid in upstream_for[usn_id]:
            cve_union |= cve_sets.get(cid, set())

        had_orphan = False
        for tup in usn_set:
            total += 1
            if tup in cve_union:
                covered += 1
            else:
                missing += 1
                had_orphan = True
                if len(samples) < 15:
                    samples.append((usn_id, tup))
        if had_orphan:
            usns_with_orphans += 1

    pct = (100.0 * covered / total) if total else 0.0
    print(f"\n--- {label} ---")
    print(f"  total in USNs:           {total}")
    print(f"  covered by upstream CVE: {covered} ({pct:.2f}%)")
    print(f"  missing:                 {missing}")
    print(f"  USNs with >=1 orphan:    {usns_with_orphans}")
    if samples:
        print(f"  sample orphans:")
        for uid, tup in samples:
            print(f"    {uid}: {tup}")


# globals populated by main(); avoids passing 4 maps everywhere
upstream_for: dict[str, list[str]] = {}


def main() -> None:  # noqa: PLR0915
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    root = extract_if_needed(sys.argv[1])

    cve_dir = os.path.join(root, "osv", "cve")
    usn_dir = os.path.join(root, "osv", "usn")

    # Index every CVE record
    print("indexing CVE records...", file=sys.stderr)
    cve_fix_tuples: dict[str, set] = {}
    cve_affected_keys: dict[str, set] = {}
    cve_binary_tuples: dict[str, set] = {}
    for dirpath, _, files in os.walk(cve_dir):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(dirpath, fname)) as f:
                rec = json.load(f)
            cid = rec["id"]
            cve_fix_tuples[cid] = collect_fix_tuples(rec)
            cve_affected_keys[cid] = collect_affected_keys(rec)
            cve_binary_tuples[cid] = collect_binary_tuples(rec)
    print(f"  indexed {len(cve_fix_tuples)} CVE records", file=sys.stderr)

    # Walk USNs
    print("indexing USNs...", file=sys.stderr)
    usn_fix_tuples: dict[str, set] = {}
    usn_affected_keys: dict[str, set] = {}
    usn_binary_tuples: dict[str, set] = {}
    n_usn_no_upstream = 0
    unresolved_upstream: Counter[str] = Counter()
    upstream_lengths: Counter[int] = Counter()

    for fname in sorted(os.listdir(usn_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(usn_dir, fname)) as f:
            rec = json.load(f)
        uid = rec["id"]
        upstream = rec.get("upstream", [])
        upstream_lengths[len(upstream)] += 1
        if not upstream:
            n_usn_no_upstream += 1
            continue
        # validate that every upstream id resolves to an indexed CVE
        for cid in upstream:
            if cid not in cve_fix_tuples:
                unresolved_upstream[cid] += 1
        upstream_for[uid] = upstream
        usn_fix_tuples[uid] = collect_fix_tuples(rec)
        usn_affected_keys[uid] = collect_affected_keys(rec)
        usn_binary_tuples[uid] = collect_binary_tuples(rec)
    print(f"  indexed {len(usn_fix_tuples)} USNs (with upstream)", file=sys.stderr)
    print(f"  USNs without any upstream ref: {n_usn_no_upstream}", file=sys.stderr)

    print("\n=== USN -> upstream linkage ===")
    print(f"  upstream-ref length histogram: {dict(sorted(upstream_lengths.items()))}")
    print(f"  USNs with no upstream:         {n_usn_no_upstream}")
    print(f"  distinct unresolved upstream ids: {len(unresolved_upstream)}")
    if unresolved_upstream:
        print("  sample unresolved upstream refs:")
        for cid, cnt in unresolved_upstream.most_common(5):
            print(f"    {cid} (referenced by {cnt} USN(s))")

    coverage("Fix tuples (ecosystem, source_pkg, fixed_version)",
             usn_fix_tuples, cve_fix_tuples)
    coverage("Affected keys (ecosystem, source_pkg)",
             usn_affected_keys, cve_affected_keys)
    coverage("Binary tuples (ecosystem, source_pkg, binary_name, binary_version)",
             usn_binary_tuples, cve_binary_tuples)

    # Reverse check: CVE-only fixes that no USN ever published
    print("\n=== Reverse check: fix tuples in CVE but in no USN that references it ===")
    referenced_cves = {cid for refs in upstream_for.values() for cid in refs}
    cve_only_fixes = 0
    cves_with_orphan_fixes = 0
    samples: list[tuple[str, tuple]] = []
    for cid in referenced_cves:
        usn_union: set = set()
        for uid, refs in upstream_for.items():
            if cid in refs:
                usn_union |= usn_fix_tuples.get(uid, set())
        cve_fixes = cve_fix_tuples.get(cid, set())
        orphans = cve_fixes - usn_union
        if orphans:
            cves_with_orphan_fixes += 1
            for tup in orphans:
                cve_only_fixes += 1
                if len(samples) < 15:
                    samples.append((cid, tup))
    print(f"  CVEs referenced by >=1 USN:       {len(referenced_cves)}")
    print(f"  CVEs with fix tuples not in USNs: {cves_with_orphan_fixes}")
    print(f"  total CVE-only fix tuples:        {cve_only_fixes}")
    if samples:
        print("  sample CVE-only fix tuples:")
        for cid, tup in samples:
            print(f"    {cid}: {tup}")


if __name__ == "__main__":
    main()
