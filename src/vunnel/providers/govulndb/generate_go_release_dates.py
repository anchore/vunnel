"""Regenerate `go_release_dates_data.py` from the golang/go tag history.

When a Go release shipped never changes, so the dates for everything already out
are committed rather than fetched. Run after a new Go release:

    uv run python -m vunnel.providers.govulndb.generate_go_release_dates

Dates are the committer date of the commit each `go*` tag points at -- the same
value the gitiles fallback reads, so the table and the fallback agree. The clone
is treeless because only commit metadata is needed (~34 MB, not the full repo).
"""

from __future__ import annotations

import datetime
import pathlib
import re
import subprocess
import tempfile

GO_REPO_URL = "https://github.com/golang/go"

OUTPUT_PATH = pathlib.Path(__file__).parent / "go_release_dates_data.py"

# `go1`, `go1.21`, `go1.19.2` and the prerelease forms `go1.21rc4` / `go1.20beta1`
TAG_RE = re.compile(r"^go1(?:\.\d+){0,2}(?:(?:rc|beta)\d+)?$")

_HEADER = '''"""Release dates for every Go toolchain version published so far.

DO NOT EDIT BY HAND -- regenerate with:

    uv run python -m vunnel.providers.govulndb.generate_go_release_dates

Keyed by golang/go release tag, the form `_stdlib_version_to_tag` produces.
Generated from {repo} on {generated}; {count} tags.
"""

from __future__ import annotations

GO_RELEASE_DATES: dict[str, str] = {{
'''


def _version_sort_key(tag: str) -> tuple[object, ...]:
    """Sort by version so new releases slot in beside their siblings."""
    body = tag.removeprefix("go")
    pre = ""
    for marker in ("rc", "beta"):
        if marker in body:
            body, _, pre_num = body.partition(marker)
            pre = f"{marker}{pre_num}"
            break
    parts = tuple(int(p) for p in body.split(".") if p)
    parts += (0,) * (3 - len(parts))
    # prerelease sorts before the release it leads up to
    return (*parts, pre == "", pre)


def collect_release_dates(repo_dir: str) -> dict[str, str]:
    out = subprocess.run(
        [  # noqa: S607
            "git",
            "for-each-ref",
            "--format=%(refname:short)\t%(committerdate:short)\t%(*committerdate:short)",
            "refs/tags/go*",
        ],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True,
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


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = str(pathlib.Path(tmp) / "go.git")
        print(f"cloning {GO_REPO_URL} (treeless)...")
        subprocess.run(  # noqa: S603
            ["git", "clone", "--bare", "--filter=tree:0", "--quiet", GO_REPO_URL, repo_dir],  # noqa: S607
            check=True,
        )
        dates = collect_release_dates(repo_dir)

    if not dates:
        raise SystemExit("no go release tags found; refusing to write an empty table")

    lines = [
        _HEADER.format(
            repo=GO_REPO_URL,
            generated=datetime.datetime.now(tz=datetime.UTC).date().isoformat(),
            count=len(dates),
        ),
    ]
    lines.extend(f'    "{tag}": "{dates[tag]}",\n' for tag in sorted(dates, key=_version_sort_key))
    lines.append("}\n")

    OUTPUT_PATH.write_text("".join(lines))
    print(f"wrote {len(dates)} release dates to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
