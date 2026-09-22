"""Regenerate `go_release_dates_data.py` from the golang/go tag history.

When a Go release shipped never changes, so the dates for everything already out
are committed rather than fetched at runtime. Run after a new Go release:

    task update-go-release-dates      # rewrite the table if new releases exist
    task check-go-release-dates       # fail if the table is missing a release

Dates are the committer date of the commit each `go*` tag points at, normalized
to UTC -- the same value, in the same timezone, that the gitiles fallback in
`go_release_dates.py` reads, so the table and the fallback always agree.

The output is a pure function of the golang/go tag history: regenerating with no
new releases rewrites the same bytes and leaves the worktree clean, so `git diff`
after `task update-go-release-dates` is exactly "are there uncommitted releases".
The clone is treeless because only commit metadata is needed (~34 MB, not the
full repo).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

GO_REPO_URL = "https://github.com/golang/go"

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "src" / "vunnel" / "providers" / "govulndb" / "go_release_dates_data.py"

# `go1`, `go1.21`, `go1.19.2` and the prerelease forms `go1.21rc4` / `go1.20beta1`
TAG_RE = re.compile(r"^go1(?:\.\d+){0,2}(?:(?:rc|beta)\d+)?$")

_HEADER = '''"""Release dates for every Go toolchain version published so far.

DO NOT EDIT BY HAND -- regenerate with `task update-go-release-dates`.

Keyed by golang/go release tag, the form `_stdlib_version_to_tag` produces.
Dates are the UTC date of the commit each tag points at, generated from {repo}.
"""

from __future__ import annotations

GO_RELEASE_DATES: dict[str, str] = {{
'''


def _version_sort_key(tag: str) -> tuple[object, ...]:
    """Sort by version so new releases slot in beside their siblings."""
    body = tag.removeprefix("go")
    pre_marker = ""
    pre_number = 0
    for marker in ("rc", "beta"):
        if marker in body:
            body, _, pre_num = body.partition(marker)
            pre_marker = marker
            # numeric, so rc10 sorts after rc5 rather than between rc1 and rc2
            pre_number = int(pre_num) if pre_num.isdigit() else 0
            break
    parts = tuple(int(p) for p in body.split(".") if p)
    parts += (0,) * (3 - len(parts))
    # prerelease sorts before the release it leads up to
    return (*parts, pre_marker == "", pre_marker, pre_number)


def collect_release_dates(repo_dir: str) -> dict[str, str]:
    out = subprocess.run(
        [  # noqa: S607
            "git",
            "for-each-ref",
            # format-local renders in $TZ, which is forced to UTC below
            "--format=%(refname:short)\t%(committerdate:format-local:%Y-%m-%d)\t%(*committerdate:format-local:%Y-%m-%d)",
            "refs/tags/go*",
        ],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True,
        env={"TZ": "UTC", "PATH": "/usr/bin:/bin:/usr/local/bin"},
    ).stdout

    dates: dict[str, str] = {}
    for line in out.splitlines():
        tag, committer, peeled = [*line.split("\t"), "", ""][:3]
        if not TAG_RE.match(tag):
            continue
        # go's tags are lightweight, but annotated ones report the date on the peeled ref
        released = peeled or committer
        if released:
            dates[tag] = released
    return dates


def build_table() -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = str(pathlib.Path(tmp) / "go.git")
        print(f"cloning {GO_REPO_URL} (treeless)...", file=sys.stderr)
        subprocess.run(  # noqa: S603
            ["git", "clone", "--bare", "--filter=tree:0", "--quiet", GO_REPO_URL, repo_dir],  # noqa: S607
            check=True,
        )
        return collect_release_dates(repo_dir)


def render(dates: dict[str, str]) -> str:
    lines = [_HEADER.format(repo=GO_REPO_URL)]
    lines.extend(f'    "{tag}": "{dates[tag]}",\n' for tag in sorted(dates, key=_version_sort_key))
    lines.append("}\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed table is out of date, without writing it",
    )
    args = parser.parse_args(argv)

    dates = build_table()
    if not dates:
        print("no go release tags found; refusing to write an empty table", file=sys.stderr)
        return 1

    rendered = render(dates)
    current = OUTPUT_PATH.read_text() if OUTPUT_PATH.exists() else ""

    if rendered == current:
        print(f"go release-date table is up to date ({len(dates)} tags)")
        return 0

    committed = _committed_tags(current)
    added = sorted(set(dates) - committed, key=_version_sort_key)

    if args.check:
        print("go release-date table is out of date; run `task update-go-release-dates`", file=sys.stderr)
        if added:
            print(f"missing releases: {', '.join(added)}", file=sys.stderr)
        return 1

    OUTPUT_PATH.write_text(rendered)
    if added:
        print(f"wrote {len(dates)} release dates to {OUTPUT_PATH} (new: {', '.join(added)})")
    else:
        print(f"wrote {len(dates)} release dates to {OUTPUT_PATH}")
    return 0


def _committed_tags(source: str) -> set[str]:
    return set(re.findall(r'^    "(go[^"]+)":', source, flags=re.MULTILINE))


if __name__ == "__main__":
    raise SystemExit(main())
