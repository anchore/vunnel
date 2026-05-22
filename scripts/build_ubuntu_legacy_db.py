#!/usr/bin/env python3
"""
Build the ubuntu provider's legacy passthrough database.

Copies the current ubuntu provider's results.db to a target path (typically
data/ubuntu/input/legacy/results.db), then deletes rows for any namespace
already covered by the OSV CVE feed. What remains is the set of records
the new provider cannot derive from osv/cve/** — older Ubuntu releases
that Canonical no longer publishes in the CVE feed.

A namespace is considered "covered" iff its version number (e.g. "14.04",
"22.04") appears in any `Ubuntu:...X.Y[...]` ecosystem string under
osv/cve/** in the tarball.

Useful in two contexts:
  1. As an operational step when rolling out the OSV rewrite.
  2. For tests / local development — produces realistic legacy fixtures.

Usage:
    python scripts/build_ubuntu_legacy_db.py \\
        --results-db data/ubuntu/results/results.db \\
        --osv-input  data/ubuntu/input/osv-all.tar.xz \\
        --output     data/ubuntu/input/legacy/results.db
    # add --dry-run to preview without writing

The --osv-input arg accepts either the .tar.xz directly or an
already-extracted directory containing osv/cve/...
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
from collections import Counter
from typing import TYPE_CHECKING

import orjson

if TYPE_CHECKING:
    from collections.abc import Iterable

_VERSION_RE = re.compile(r"(\d+\.\d+)")


def _harvest_ecosystems(record: dict, sink: set[str]) -> None:
    for aff in record.get("affected", []):
        eco = aff.get("package", {}).get("ecosystem")
        if eco:
            sink.add(eco)


def _iter_cve_records_from_dir(root: str) -> Iterable[dict]:
    cve_dir = os.path.join(root, "osv", "cve")
    if not os.path.isdir(cve_dir):
        raise SystemExit(f"missing {cve_dir}")
    for dirpath, _, files in os.walk(cve_dir):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(dirpath, fname), "rb") as f:
                yield orjson.loads(f.read())


def _iter_cve_records_from_tarball(path: str) -> Iterable[dict]:
    with tarfile.open(path, "r:*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            if not member.name.startswith("osv/cve/") or not member.name.endswith(".json"):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            yield orjson.loads(fh.read())


def discover_covered_versions(osv_input: str) -> tuple[set[str], list[str]]:
    """Return (covered X.Y version strings, sorted ecosystem strings observed).

    Walks osv/cve/** in the given input (tarball or extracted dir) and
    extracts the X.Y portion of every ecosystem string.
    """
    ecosystems: set[str] = set()
    if os.path.isdir(osv_input):
        records = _iter_cve_records_from_dir(osv_input)
    elif osv_input.endswith((".tar.xz", ".tar")):
        records = _iter_cve_records_from_tarball(osv_input)
    else:
        raise SystemExit(f"unrecognized --osv-input: {osv_input}")

    for rec in records:
        _harvest_ecosystems(rec, ecosystems)

    versions: set[str] = set()
    for eco in ecosystems:
        m = _VERSION_RE.search(eco)
        if m:
            versions.add(m.group(1))

    return versions, sorted(ecosystems)


def per_namespace_counts(db_path: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    conn = sqlite3.connect(db_path)
    try:
        for (i,) in conn.execute("SELECT id FROM results"):
            ns = i.split("/", 1)[0]
            counts[ns] += 1
    finally:
        conn.close()
    return counts


def ns_version(ns: str) -> str | None:
    # namespace looks like "ubuntu:14.04"
    parts = ns.split(":", 1)
    if len(parts) != 2:
        return None
    return parts[1]


def _classify_namespaces(counts: Counter[str], covered: set[str]) -> tuple[list[str], list[str], list[str]]:
    drop_ns, keep_ns, unknown_ns = [], [], []
    for ns in sorted(counts):
        ver = ns_version(ns)
        if ver is None:
            unknown_ns.append(ns)
        elif ver in covered:
            drop_ns.append(ns)
        else:
            keep_ns.append(ns)
    return drop_ns, keep_ns, unknown_ns


def _print_classification(
    counts: Counter[str],
    drop_ns: list[str],
    keep_ns: list[str],
    unknown_ns: list[str],
) -> None:
    drop_rows = sum(counts[ns] for ns in drop_ns)
    keep_rows = sum(counts[ns] for ns in keep_ns)
    unknown_rows = sum(counts[ns] for ns in unknown_ns)

    print(f"  namespaces to DROP (covered by OSV): {len(drop_ns)} ({drop_rows} rows)")
    for ns in drop_ns:
        print(f"    {counts[ns]:>8}  {ns}")
    print(f"  namespaces to KEEP in legacy (NOT covered by OSV): {len(keep_ns)} ({keep_rows} rows)")
    for ns in keep_ns:
        print(f"    {counts[ns]:>8}  {ns}")
    if unknown_ns:
        print(f"  namespaces with unparseable version (KEPT defensively): {len(unknown_ns)} ({unknown_rows} rows)")
        for ns in unknown_ns:
            print(f"    {counts[ns]:>8}  {ns}")
    print()


def _trim_db(src: str, dst: str, drop_ns: list[str], expected_remaining: int) -> None:
    """Copy src -> dst, delete covered-namespace rows, VACUUM, verify."""
    out_dir = os.path.dirname(os.path.abspath(dst))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="legacy-results-", suffix=".db", dir=out_dir or ".")
    os.close(tmp_fd)
    try:
        print(f"copying {src} -> {tmp_path}")
        shutil.copy2(src, tmp_path)

        conn = sqlite3.connect(tmp_path)
        try:
            print("deleting covered-namespace rows...")
            total_deleted = 0
            for ns in drop_ns:
                cur = conn.execute("DELETE FROM results WHERE id LIKE ? || '/%'", (ns,))
                total_deleted += cur.rowcount
                print(f"    {cur.rowcount:>8}  {ns}")
            conn.commit()
            print(f"  total deleted: {total_deleted}")

            remaining = conn.execute("SELECT count(*) FROM results").fetchone()[0]
            print(f"  remaining rows: {remaining}")

            print("running VACUUM to reclaim space...")
            conn.execute("VACUUM")
        finally:
            conn.close()

        if remaining != expected_remaining:
            raise SystemExit(f"row-count mismatch after delete: got {remaining}, expected {expected_remaining}")

        os.replace(tmp_path, dst)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Build the ubuntu legacy passthrough results.db.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--results-db", required=True, help="source results.db (current provider output)")
    ap.add_argument("--osv-input", required=True, help="osv-all.tar.xz or extracted dir")
    ap.add_argument("--output", required=True, help="output path for trimmed legacy results.db")
    ap.add_argument("--dry-run", action="store_true", help="report what would happen; do not write")
    args = ap.parse_args()

    if not os.path.isfile(args.results_db):
        raise SystemExit(f"results-db not found: {args.results_db}")
    if not os.path.exists(args.osv_input):
        raise SystemExit(f"osv-input not found: {args.osv_input}")
    if os.path.abspath(args.output) == os.path.abspath(args.results_db):
        raise SystemExit("--output must differ from --results-db (refuse to clobber source)")

    print(f"discovering covered versions from {args.osv_input} ...")
    covered, ecosystems = discover_covered_versions(args.osv_input)
    print(f"  distinct ecosystems in osv/cve/**: {len(ecosystems)}")
    print(f"  covered versions: {sorted(covered)}")
    print()

    print(f"scanning {args.results_db} ...")
    counts = per_namespace_counts(args.results_db)
    total = sum(counts.values())
    print(f"  total rows: {total}")
    print()

    drop_ns, keep_ns, unknown_ns = _classify_namespaces(counts, covered)
    _print_classification(counts, drop_ns, keep_ns, unknown_ns)

    if args.dry_run:
        print("dry-run: not writing anything")
        return

    if total == 0:
        raise SystemExit("source db is empty, nothing to do")

    expected_remaining = sum(counts[ns] for ns in keep_ns) + sum(counts[ns] for ns in unknown_ns)
    _trim_db(args.results_db, args.output, drop_ns, expected_remaining)
    size_mb = os.path.getsize(args.output) / (1024 * 1024)
    print(f"\nwrote {args.output}")
    print(f"  size: {size_mb:.1f} MiB")


if __name__ == "__main__":
    main()
