#!/usr/bin/env python3
"""
Break down USN-only fix tuples (orphans w.r.t. their upstream CVEs) by
ecosystem and by USN year. Helps answer: are the gaps concentrated in old
releases (legacy-cache territory) or spread across current ones?

Usage:
    python scripts/osv_ubuntu_orphan_breakdown.py <path-to-extracted-dir>
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter


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


_kernel_re = re.compile(r"^(linux($|-)|nvidia-graphics-drivers|intel-microcode)")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    root = sys.argv[1]
    cve_dir = os.path.join(root, "osv", "cve")
    usn_dir = os.path.join(root, "osv", "usn")

    cve_fixes: dict[str, set] = {}
    for dirpath, _, files in os.walk(cve_dir):
        for fname in files:
            if fname.endswith(".json"):
                with open(os.path.join(dirpath, fname)) as f:
                    rec = json.load(f)
                cve_fixes[rec["id"]] = collect_fix_tuples(rec)

    no_upstream_eco: Counter[str] = Counter()
    no_upstream_year: Counter[str] = Counter()
    no_upstream_count = 0

    orphan_eco: Counter[str] = Counter()
    orphan_year: Counter[str] = Counter()
    orphan_kernel = 0
    orphan_total = 0

    usn_year_re = re.compile(r"^USN-(\d+)-")  # not useful alone; use published
    for fname in sorted(os.listdir(usn_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(usn_dir, fname)) as f:
            usn = json.load(f)
        year = (usn.get("published") or "")[:4] or "?"
        upstream = usn.get("upstream", [])
        usn_fixes = collect_fix_tuples(usn)
        if not upstream:
            no_upstream_count += 1
            no_upstream_year[year] += 1
            for eco, _, _ in usn_fixes:
                no_upstream_eco[eco] += 1
            continue
        cve_union: set = set()
        for cid in upstream:
            cve_union |= cve_fixes.get(cid, set())
        for tup in usn_fixes:
            if tup in cve_union:
                continue
            orphan_total += 1
            eco, pkg, _ver = tup
            orphan_eco[eco] += 1
            orphan_year[year] += 1
            if _kernel_re.match(pkg):
                orphan_kernel += 1

    print("=== USNs with NO upstream (would be entirely dropped if we skip USNs) ===")
    print(f"  count: {no_upstream_count}")
    print("  by year (USN published):")
    for y, c in sorted(no_upstream_year.items()):
        print(f"    {y}: {c}")
    print("  top ecosystems of fixes in those USNs:")
    for e, c in no_upstream_eco.most_common(10):
        print(f"    {c:>6}  {e}")

    print()
    print("=== Orphan fix tuples (in USN but not in upstream CVE) ===")
    print(f"  total: {orphan_total}")
    pct_kernel = (100.0 * orphan_kernel / orphan_total) if orphan_total else 0
    print(f"  kernel/firmware-shaped pkg names: {orphan_kernel} ({pct_kernel:.1f}%)")
    print("  by year (USN published):")
    for y, c in sorted(orphan_year.items()):
        print(f"    {y}: {c}")
    print("  by ecosystem:")
    for e, c in orphan_eco.most_common():
        print(f"    {c:>6}  {e}")


if __name__ == "__main__":
    main()
