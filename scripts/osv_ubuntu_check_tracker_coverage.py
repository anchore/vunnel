#!/usr/bin/env python3
"""
Does the *current* ubuntu provider (which only parses ubuntu-cve-tracker
CVE files) cover the USN-only data we'd lose by going CVE-only on the
OSV feed?

We extract every (codename_stem, source_package, fixed_version) tuple
from `released (<ver>)` lines in active/ + retired/ CVE files, then check
whether the USN-only fixes (orphans + no-upstream USNs) are present in
that set.

If the current provider doesn't see these fixes either, deferring USN
parsing in the rewrite is a no-op regression. If it does, we're walking
something back.

Usage:
    python scripts/osv_ubuntu_check_tracker_coverage.py \\
        <extracted-osv-dir> <ubuntu-cve-tracker-dir>
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter

# Map OSV ecosystem strings → ubuntu codename stem used in CVE-tracker.
# We use a stem because patches like `bionic_pkg:`, `esm-apps/bionic_pkg:`,
# `esm-infra/bionic_pkg:` all reference the same release.
OSV_ECO_TO_CODENAME = {
    "Ubuntu:12.04:LTS": "precise",
    "Ubuntu:14.04:LTS": "trusty",
    "Ubuntu:16.04:LTS": "xenial",
    "Ubuntu:18.04:LTS": "bionic",
    "Ubuntu:20.04:LTS": "focal",
    "Ubuntu:22.04:LTS": "jammy",
    "Ubuntu:24.04:LTS": "noble",
    "Ubuntu:24.10": "oracular",
    "Ubuntu:25.04": "plucky",
    "Ubuntu:25.10": "questing",
    "Ubuntu:23.10": "mantic",
    "Ubuntu:23.04": "lunar",
    "Ubuntu:22.10": "kinetic",
    "Ubuntu:21.10": "impish",
    "Ubuntu:21.04": "hirsute",
    "Ubuntu:20.10": "groovy",
    "Ubuntu:19.10": "eoan",
    "Ubuntu:19.04": "disco",
    "Ubuntu:18.10": "cosmic",
    "Ubuntu:17.10": "artful",
    # ESM/Pro variants resolve to the same codename — the tracker uses
    # esm-apps/<codename>, esm-infra/<codename>, etc.
    "Ubuntu:Pro:14.04:LTS": "trusty",
    "Ubuntu:Pro:16.04:LTS": "xenial",
    "Ubuntu:Pro:18.04:LTS": "bionic",
    "Ubuntu:Pro:20.04:LTS": "focal",
    "Ubuntu:Pro:22.04:LTS": "jammy",
    "Ubuntu:Pro:24.04:LTS": "noble",
    "Ubuntu:Pro:FIPS:14.04:LTS": "trusty",
    "Ubuntu:Pro:FIPS:16.04:LTS": "xenial",
    "Ubuntu:Pro:FIPS:18.04:LTS": "bionic",
    "Ubuntu:Pro:FIPS:20.04:LTS": "focal",
    "Ubuntu:Pro:FIPS:22.04:LTS": "jammy",
    "Ubuntu:Pro:FIPS-updates:14.04:LTS": "trusty",
    "Ubuntu:Pro:FIPS-updates:16.04:LTS": "xenial",
    "Ubuntu:Pro:FIPS-updates:18.04:LTS": "bionic",
    "Ubuntu:Pro:FIPS-updates:20.04:LTS": "focal",
    "Ubuntu:Pro:FIPS-updates:22.04:LTS": "jammy",
    "Ubuntu:Pro:Realtime:22.04:LTS": "jammy",
    "Ubuntu:Pro:Realtime:24.04:LTS": "noble",
    "Ubuntu:Nvidia-BlueField:22.04:LTS": "jammy",
}


# Tracker line:  <distro>_<pkg>: <status>[ (<version>)]
# distro can be: bionic, esm-apps/bionic, esm-infra/bionic, esm-infra-legacy/trusty, trusty/esm, etc.
# We extract codename = last path segment, dropping any /esm suffix variants.
_patch_line_re = re.compile(
    r"^(?P<distro>[\w./-]+)_(?P<pkg>[^\s:]+):\s+(?P<status>\S+)(?:\s+\((?P<ver>[^)]+)\))?\s*$",
)


def codename_stem(distro_label: str) -> str:
    """Strip esm-apps/, esm-infra/, esm-infra-legacy/, trailing /esm etc."""
    # e.g. "esm-apps/bionic" -> "bionic"; "trusty/esm" -> "trusty"
    label = distro_label
    if "/" in label:
        parts = label.split("/")
        # take whichever segment matches a known codename
        for p in parts:
            if p in CODENAMES_SET:
                return p
        # fall through: return last segment
        return parts[-1]
    return label


def load_tracker_released_tuples(tracker_root: str) -> set[tuple[str, str, str]]:
    """Return {(codename_stem, source_pkg, fixed_version)} for status=released."""
    out: set[tuple[str, str, str]] = set()
    for sub in ("active", "retired"):
        d = os.path.join(tracker_root, sub)
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.startswith("CVE-"):
                continue
            full = os.path.join(d, fname)
            try:
                with open(full, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        m = _patch_line_re.match(line)
                        if not m:
                            continue
                        if m.group("status") != "released":
                            continue
                        ver = m.group("ver")
                        if not ver:
                            continue
                        cn = codename_stem(m.group("distro"))
                        if cn not in CODENAMES_SET:
                            continue
                        out.add((cn, m.group("pkg"), ver.strip()))
            except OSError:
                continue
    return out


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


def to_codename_tuple(eco_tuple: tuple[str, str, str]) -> tuple[str, str, str] | None:
    eco, pkg, ver = eco_tuple
    cn = OSV_ECO_TO_CODENAME.get(eco)
    if not cn:
        return None
    return (cn, pkg, ver)


CODENAMES_SET = set(OSV_ECO_TO_CODENAME.values())


def main() -> None:  # noqa: PLR0915
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    osv_root, tracker_root = sys.argv[1], sys.argv[2]

    cve_dir = os.path.join(osv_root, "osv", "cve")
    usn_dir = os.path.join(osv_root, "osv", "usn")

    print("indexing CVE records...", file=sys.stderr)
    cve_fixes: dict[str, set] = {}
    for dirpath, _, files in os.walk(cve_dir):
        for fname in files:
            if fname.endswith(".json"):
                with open(os.path.join(dirpath, fname)) as f:
                    rec = json.load(f)
                cve_fixes[rec["id"]] = collect_fix_tuples(rec)
    print(f"  {len(cve_fixes)} CVEs", file=sys.stderr)

    print("collecting USN-only fix tuples (orphans + no-upstream)...", file=sys.stderr)
    usn_only_fixes: list[tuple[str, str, str]] = []  # (eco, pkg, ver)
    no_upstream_fixes: list[tuple[str, str, str]] = []
    orphan_fixes: list[tuple[str, str, str]] = []

    for fname in sorted(os.listdir(usn_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(usn_dir, fname)) as f:
            usn = json.load(f)
        upstream = usn.get("upstream", [])
        usn_set = collect_fix_tuples(usn)
        if not upstream:
            for t in usn_set:
                no_upstream_fixes.append(t)
            continue
        cve_union: set = set()
        for cid in upstream:
            cve_union |= cve_fixes.get(cid, set())
        for t in usn_set:
            if t not in cve_union:
                orphan_fixes.append(t)

    usn_only_fixes = no_upstream_fixes + orphan_fixes
    print(f"  no-upstream USN fix tuples: {len(no_upstream_fixes)}", file=sys.stderr)
    print(f"  orphan USN fix tuples:      {len(orphan_fixes)}", file=sys.stderr)

    print("scanning tracker for released-version tuples...", file=sys.stderr)
    tracker_set = load_tracker_released_tuples(tracker_root)
    print(f"  tracker released tuples: {len(tracker_set)}", file=sys.stderr)

    def report(label: str, tuples: list[tuple[str, str, str]]) -> None:
        total = 0
        seen_in_tracker = 0
        unmapped_ecos: Counter[str] = Counter()
        missed_samples: list[tuple] = []
        seen_samples: list[tuple] = []
        for eco, pkg, ver in tuples:
            cn = OSV_ECO_TO_CODENAME.get(eco)
            if not cn:
                unmapped_ecos[eco] += 1
                continue
            total += 1
            key = (cn, pkg, ver)
            if key in tracker_set:
                seen_in_tracker += 1
                if len(seen_samples) < 5:
                    seen_samples.append((eco, key))
            else:
                if len(missed_samples) < 15:
                    missed_samples.append((eco, key))
        pct = (100.0 * seen_in_tracker / total) if total else 0.0
        print(f"\n--- {label} ---")
        print(f"  considered (eco mapped to codename): {total}")
        print(f"  found in tracker as released:        {seen_in_tracker} ({pct:.2f}%)")
        print(f"  not found in tracker:                {total - seen_in_tracker}")
        if unmapped_ecos:
            print(f"  unmapped ecosystems (skipped):")
            for eco, c in unmapped_ecos.most_common():
                print(f"    {c:>5}  {eco}")
        if seen_samples:
            print(f"  sample tracker-covered:")
            for eco, key in seen_samples:
                print(f"    {eco} -> {key}")
        if missed_samples:
            print(f"  sample NOT in tracker:")
            for eco, key in missed_samples:
                print(f"    {eco} -> {key}")

    report("No-upstream USN fix tuples", no_upstream_fixes)
    report("Orphan USN fix tuples (USN-only vs upstream CVE)", orphan_fixes)
    report("All USN-only fix tuples combined", usn_only_fixes)


if __name__ == "__main__":
    main()
