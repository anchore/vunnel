"""Regenerate the committed Go release-date tables.

Release dates never change once a version ships, so the dates for everything
already out are committed rather than fetched at runtime. This writes two tables:

- `go_release_dates_data.py`: every golang/go release tag, dated by the committer
  date of the commit each `go*` tag points at, normalized to UTC -- the same value,
  in the same timezone, that the provider's gitiles fallback reads. The clone is
  treeless because only commit metadata is needed (~34 MB, not the full repo).
- `go_module_release_dates_data.py`: every `(module, fixed version)` the current
  go vulndb names, dated by the module proxy's `.info` `Time` -- the same value the
  provider's runtime fallback reads. The proxy is asked concurrently and with
  retries, since unlike the provider run there is no hurry. A version the proxy
  definitively does not know (404/410) is recorded as None so the provider does not
  ask about it on every run.

Run periodically -- oss-release runs `task update-go-release-dates` weekly and
opens a PR iff `git diff` is non-empty afterwards.

Dates already committed are kept and never re-fetched, and versions the vulndb no
longer names are dropped, so regenerating when nothing upstream has changed
rewrites the same bytes. The output depends on the committed tables and on what
the proxy answers as well as on upstream, though: a version that could not be
asked about this time (proxy flaky, retries spent) keeps whatever was committed
for it -- a network blip never rewrites the table -- and a new one is left out,
so the next regeneration asks again. The committed tables are a cache for the
provider, which asks about anything missing from them itself, so a few gaps cost
a few runtime lookups. What does fail the run is an outage: if every lookup it
attempted failed -- network errors, retries spent, redirects or unusable answers
alike -- it writes nothing and exits non-zero, so the weekly job alerts instead of
quietly doing nothing. If some lookups were answered, whatever failed is left for
the next run.
"""

from __future__ import annotations

import argparse
import io
import logging
import os
import pathlib
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from typing import TYPE_CHECKING, Any, NamedTuple

import orjson
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from vunnel.providers.govulndb import Config
from vunnel.providers.govulndb.go_module_release_dates_data import GO_MODULE_RELEASE_DATES
from vunnel.providers.govulndb.go_release_dates import (
    RELEASE_TAG_RE,
    STDLIB_MODULES,
    USER_AGENT,
    fixed_versions,
    is_plausible_release_date,
    module_info_url,
    module_key,
    parse_module_info,
)
from vunnel.providers.govulndb.go_release_dates_data import GO_RELEASE_DATES

if TYPE_CHECKING:
    from collections.abc import Mapping

# the github mirror, not go.googlesource.com (which the provider's runtime fallback reads):
# same tags and commits, and github serves a cheap treeless clone
GO_REPO_URL = "https://github.com/golang/go"
VULNDB_URL = Config().url

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROVIDER_DIR = REPO_ROOT / "src" / "vunnel" / "providers" / "govulndb"
OUTPUT_PATH = PROVIDER_DIR / "go_release_dates_data.py"
MODULE_OUTPUT_PATH = PROVIDER_DIR / "go_module_release_dates_data.py"


_HEADER = '''"""Release dates for every Go toolchain version published so far.

DO NOT EDIT BY HAND -- regenerate with `task update-go-release-dates`.

Keyed by golang/go release tag, the form `stdlib_version_to_tag` produces.
Dates are the UTC date of the commit each tag points at, generated from {repo}.
"""

from __future__ import annotations

GO_RELEASE_DATES: dict[str, str] = {{
'''

_MODULE_HEADER = '''"""Release dates for every module fix version the go vulndb names.

DO NOT EDIT BY HAND -- regenerate with `task update-go-release-dates`.

Keyed by `module@version`, the version exactly as the vulndb spells it. Dates are
the UTC date of the module proxy's `.info` `Time`. None marks a version the proxy
does not know, so the provider does not ask about it on every run.
"""

from __future__ import annotations

GO_MODULE_RELEASE_DATES: dict[str, str | None] = {
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
        env={**os.environ, "TZ": "UTC"},
    ).stdout

    dates: dict[str, str] = {}
    for line in out.splitlines():
        tag, committer, peeled = [*line.split("\t"), "", ""][:3]
        # the provider's own tag grammar, so every key is one it can look up
        if not RELEASE_TAG_RE.fullmatch(tag):
            continue
        # go's tags are lightweight, but annotated ones report the date on the peeled ref
        released = peeled or committer
        if not released:
            continue
        # the same window the runtime and the module half enforce: a forged or rewritten
        # mirror tag must not be committed as an accurate release date
        if not is_plausible_release_date(date.fromisoformat(released)):
            print(f"skipping {tag}: {released} can't be a go release date", file=sys.stderr)
            continue
        dates[tag] = released
    return dates


def build_stdlib_table() -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = str(pathlib.Path(tmp) / "go.git")
        print(f"cloning {GO_REPO_URL} (treeless)...", file=sys.stderr)
        subprocess.run(  # noqa: S603
            ["git", "clone", "--bare", "--filter=tree:0", "--quiet", GO_REPO_URL, repo_dir],  # noqa: S607
            check=True,
        )
        return collect_release_dates(repo_dir)


def download_vulndb_records() -> list[dict[str, Any]]:
    print(f"downloading {VULNDB_URL}...", file=sys.stderr)
    resp = requests.get(VULNDB_URL, timeout=300)
    resp.raise_for_status()
    records = []
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for name in zf.namelist():
            if name.startswith("ID/") and name.endswith(".json"):
                records.append(orjson.loads(zf.read(name)))
    return records


# Concurrent proxy lookups; the proxy is a CDN-fronted service built for `go mod download`
# fan-out. Deliberately a plain requests session rather than http_wrapper: the wrapper
# serializes requests per host, which would make the workers take turns.
PROXY_WORKERS = 16
PROXY_TIMEOUT = 60
# honour Retry-After, but no longer than this: urllib3 otherwise waits as long as it's
# told -- up to 6 hours. (retry_after_max needs urllib3 >= 2.6.3; the dev dependency
# group sets that floor.)
MAX_RETRY_AFTER_SECONDS = 60

PROXY_RETRIES = Retry(
    total=4,
    backoff_factor=2,
    # so 16 workers backing off together don't come back in lockstep
    backoff_jitter=1.0,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset({"GET"}),
    respect_retry_after_header=True,
    retry_after_max=MAX_RETRY_AFTER_SECONDS,
)

_logger = logging.getLogger("generate-go-release-dates")


def proxy_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", HTTPAdapter(pool_maxsize=PROXY_WORKERS, max_retries=PROXY_RETRIES))
    session.headers["User-Agent"] = USER_AGENT
    return session


class Resolved(NamedTuple):
    """What asking the proxy about some module versions learned."""

    dates: dict[str, str]
    # the proxy definitively doesn't know these (404/410)
    unknown: set[str]
    # asked, but got no usable answer (network error, retries spent, garbage body)
    failed: set[str]
    # how many had a URL we could ask at all; unexpressible module paths are never asked
    attempted: int


def resolve_modules(
    pairs: list[tuple[str, str]],
    session: requests.Session,
    workers: int = PROXY_WORKERS,
) -> Resolved:
    def one(pair: tuple[str, str]) -> tuple[str, str]:
        key = module_key(*pair)
        url = module_info_url(*pair)
        if url is None:
            return key, "unaskable"
        try:
            # as at runtime: the proxy answers these in place, so a redirect is a failed lookup
            # (the != 200 branch below), never a date from wherever it points
            resp = session.get(url, timeout=PROXY_TIMEOUT, allow_redirects=False)
        except requests.RequestException as e:
            _logger.warning(f"could not ask about {key}: {e}")
            return key, "failed"
        if resp.status_code in (404, 410):
            return key, "unknown"
        if resp.status_code != 200:
            _logger.warning(f"could not ask about {key}: HTTP {resp.status_code}")
            return key, "failed"
        d = parse_module_info(resp.content, url, _logger)
        return (key, d.isoformat()) if d else (key, "failed")

    out = Resolved(dates={}, unknown=set(), failed=set(), attempted=0)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for key, outcome in pool.map(one, pairs):
            if outcome == "unaskable":
                continue
            out = out._replace(attempted=out.attempted + 1)
            if outcome == "unknown":
                out.unknown.add(key)
            elif outcome == "failed":
                out.failed.add(key)
            else:
                out.dates[key] = outcome
    return out


class Outage(Exception):
    """Every lookup the generator attempted failed, so there's nothing worth writing."""


def build_module_table(
    records: list[dict[str, Any]],
    committed: Mapping[str, str | None],
    session: requests.Session | None = None,
) -> dict[str, str | None]:
    """The module table for these vulndb records. Raises Outage if every attempted lookup failed."""
    wanted = {(m, v) for m, v in fixed_versions(records) if m not in STDLIB_MODULES}

    table: dict[str, str | None] = {}
    to_resolve = []
    for module, version in wanted:
        key = module_key(module, version)
        # a committed date is final; a committed None is worth asking about again here
        if committed.get(key):
            table[key] = committed[key]
        else:
            to_resolve.append((module, version))

    print(f"{len(wanted)} module fix versions, {len(to_resolve)} to resolve", file=sys.stderr)
    if to_resolve:
        resolved = resolve_modules(sorted(to_resolve), session or proxy_session())
        if resolved.attempted and len(resolved.failed) == resolved.attempted:
            raise Outage(f"all {resolved.attempted} module proxy lookups failed")
        table.update(resolved.dates)
        table.update(dict.fromkeys(resolved.unknown))
        for key in resolved.failed:
            # couldn't ask this time: keep what was committed rather than rewrite the table
            if key in committed:
                table[key] = committed[key]
        if resolved.failed:
            print(
                f"could not ask about {len(resolved.failed)} of {resolved.attempted} module versions this time; "
                "kept their committed entries, and the next run will ask again",
                file=sys.stderr,
            )
    return table


def render_modules(table: dict[str, str | None]) -> str:
    lines = [_MODULE_HEADER]
    for key in sorted(table):
        released = table[key]
        # a JSON string literal is a valid Python one; None has no JSON spelling
        lines.append(f"    {orjson.dumps(key).decode()}: {'None' if released is None else orjson.dumps(released).decode()},\n")
    lines.append("}\n")
    return "".join(lines)


def render(dates: dict[str, str]) -> str:
    lines = [_HEADER.format(repo=GO_REPO_URL)]
    lines.extend(f'    "{tag}": "{dates[tag]}",\n' for tag in sorted(dates, key=_version_sort_key))
    lines.append("}\n")
    return "".join(lines)


def main() -> int:
    # no options; this gives --help and rejects unknown flags
    argparse.ArgumentParser(description=__doc__).parse_args()
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    dates = build_stdlib_table()
    if not dates:
        print("no go release tags found; refusing to write an empty table", file=sys.stderr)
        return 1

    try:
        modules = build_module_table(download_vulndb_records(), GO_MODULE_RELEASE_DATES)
    except Outage as e:
        # the stdlib table doesn't depend on the proxy, but is deliberately not written
        # either: a failed run opens no PR, so a partial write would change nothing
        print(f"{e}; writing nothing", file=sys.stderr)
        return 1
    if not modules:
        print("no module fix versions found; refusing to write an empty table", file=sys.stderr)
        return 1

    _update(OUTPUT_PATH, render(dates), _describe_stdlib(dates, GO_RELEASE_DATES))
    _update(MODULE_OUTPUT_PATH, render_modules(modules), _describe_modules(modules, GO_MODULE_RELEASE_DATES))
    return 0


def _describe_stdlib(dates: Mapping[str, str], committed: Mapping[str, str]) -> str:
    added = sorted(set(dates) - set(committed), key=_version_sort_key)
    return f"{len(dates)} release dates" + (f" (new: {', '.join(added)})" if added else "")


def _describe_modules(table: Mapping[str, str | None], committed: Mapping[str, str | None]) -> str:
    dated = sum(1 for key, released in table.items() if released and not committed.get(key))
    unknown = sum(1 for key, released in table.items() if released is None and key not in committed)
    dropped = len(set(committed) - set(table))
    return f"{len(table)} module fix versions ({dated} newly dated, {unknown} newly unknown, {dropped} dropped)"


def _update(path: pathlib.Path, rendered: str, description: str) -> None:
    current = path.read_text() if path.exists() else ""
    if rendered == current:
        print(f"{path.name} is up to date")
        return
    path.write_text(rendered)
    print(f"wrote {description} to {path}")


if __name__ == "__main__":
    raise SystemExit(main())
