"""Release dates for the Go versions the go.dev OSV records name as fixed.

go.dev's records carry no per-fix date, and their `published` field is a
disclosure timestamp rather than a fix-ship date. But for Go the fix *version*
names a published artifact whose release date is knowable:

- stdlib/toolchain: golang/go release tags. When a release shipped never
  changes, so everything already out is served from the committed
  `go_release_dates_data` table; only newer releases reach go.googlesource.com.
- everything else (`golang.org/x/...` and third-party modules): the module
  proxy's `.info` -> `.Time`, the tag time of the release.

Most third-party dates are deliberately not resolved. Grype's
`db/v6/build/govulndb_merge.go` drops any GO affected package that an aliased
GHSA also names, and lets the GHSA's ranges win on the rest, so for those the
date would be computed and then discarded -- thousands of proxy lookups, several
minutes a run, for nothing. A GO record that names no GHSA alias has no twin to
be merged into, so its packages survive and its dates are kept; those we do
resolve. See `should_resolve`. `stdlib` is the one module no GHSA names, so it
always survives the merge.

Dates are normalized to UTC, both here and in the committed table, so a release
is dated the same day no matter which source answered.

This overlay never raises: a lookup that cannot be answered -- host down,
garbage body, unrecognized version -- returns None and the caller falls back to
the advisory's published date. Fix dates are an enrichment, and losing one must
not cost the whole provider run.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.providers.govulndb.go_release_dates_data import GO_RELEASE_DATES
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from vunnel.tool import fixdate as _fixdate

MODULE_PROXY_URL = "https://proxy.golang.org"
GO_GIT_URL = "https://go.googlesource.com/go"

# these map to Go toolchain release tags, not proxy module versions
STDLIB_MODULES = {"stdlib", "toolchain"}

# the extended stdlib; unlike the toolchain these are ordinary proxy modules
EXTENDED_STDLIB_PREFIX = "golang.org/x/"

USER_AGENT = "vunnel/1.0 (govulndb-provider; +https://github.com/anchore/vunnel)"

# these are single-document metadata reads, not bulk downloads: the provider's
# download_timeout is sized for a multi-megabyte zip and would let one black-holed
# connection stall the run for minutes
DEFAULT_LOOKUP_TIMEOUT = 10
DEFAULT_LOOKUP_RETRIES = 2

# Module paths and versions come from upstream data and are interpolated into a
# URL, so they are validated against an allowlist rather than escaped: anything
# that could change which URL is being requested -- a scheme, an authority, a
# query, a fragment, a percent-escape, a `..` segment -- is simply not matched.
# The grammar is deliberately narrower than Go's own; a module we cannot express
# safely is one we decline to date. Matched with fullmatch, not match: `$` also
# matches just before a trailing newline, which would let "evil.com/mod\n" through.
_MODULE_PATH_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._~/-]*")
_MODULE_VERSION_RE = re.compile(r"v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9a-zA-Z.-]+)?(?:\+[0-9a-zA-Z.-]+)?")
_RELEASE_TAG_RE = re.compile(r"go[0-9]+(?:\.[0-9]+){0,2}(?:(?:rc|beta)[0-9]+)?")

# go only ever tags rc and beta prereleases
_PRERELEASE_RE = re.compile(r"(?:rc|beta)[0-9]+")

_MAX_MODULE_PATH_LENGTH = 512


class GoReleaseDateOverlay:
    """`(module, version) -> release date`, memoized by request URL.

    Keying on the URL rather than `(module, version)` collapses `stdlib` and
    `toolchain`, which share a release tag. Negatives are cached too.

    With `offline=True` (the provider's `skip_download`) only the committed
    table answers; nothing is fetched and unknown versions resolve to None.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        timeout: int = DEFAULT_LOOKUP_TIMEOUT,
        retries: int = DEFAULT_LOOKUP_RETRIES,
        backoff_in_seconds: int = 3,
        offline: bool = False,
    ):
        self._cache: dict[str, date | None] = {}
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        self.timeout = timeout
        self.retries = retries
        self.backoff_in_seconds = backoff_in_seconds
        self.offline = offline
        self._warned_offline = False

    def lookup(self, module: str, version: str) -> date | None:
        """Return the release date for a Go (module, version), or None on any miss."""
        if not module or not version:
            return None

        if module in STDLIB_MODULES:
            return self._lookup_stdlib(version)
        return self._lookup_module(module, version)

    def _lookup_stdlib(self, version: str) -> date | None:
        tag = _stdlib_version_to_tag(version)
        if tag is None:
            # e.g. govulndb's semver floor "1.21.0-0", which names no released artifact
            self.logger.debug(f"go version {version!r} names no release tag; no date for it")
            return None

        released = GO_RELEASE_DATES.get(tag)
        if released:
            return _parse_table_date(tag, released, self.logger)

        if self._skip_fetch(f"go release {tag}"):
            return None

        self.logger.debug(f"{tag} is not in the committed go release-date table, falling back to {GO_GIT_URL}")
        url = _stdlib_tag_url(tag)
        return self._cached(url, lambda: _stdlib_release_date(self._fetch_json(url, strip_xss_guard=True)))

    def _lookup_module(self, module: str, version: str) -> date | None:
        url = _module_info_url(module, version)
        if url is None:
            self.logger.debug(f"cannot build a safe proxy URL for {module}@{version}; no date for it")
            return None

        if self._skip_fetch(f"{module}@{version}"):
            return None

        return self._cached(url, lambda: _module_release_date(self._fetch_json(url, strip_xss_guard=False)))

    def _skip_fetch(self, what: str) -> bool:
        if not self.offline:
            return False
        if not self._warned_offline:
            self._warned_offline = True
            self.logger.info("skip_download is set: go release dates come from the committed table only, nothing will be fetched")
        self.logger.debug(f"skip_download is set; not fetching a release date for {what}")
        return True

    def _cached(self, url: str, resolve: Callable[[], date | None]) -> date | None:
        if url in self._cache:
            return self._cache[url]
        result = resolve()
        self._cache[url] = result
        return result

    def _fetch_json(self, url: str, strip_xss_guard: bool) -> dict[str, Any] | None:
        """GET `url` and decode its JSON body, or return None and log why.

        Deliberately total: every failure mode an upstream can present -- refused
        connection, timeout, 5xx, an HTML error page served as 200 -- becomes a
        missing date rather than an exception, because the caller has a usable
        fallback and the run does not.
        """
        try:
            # 404/410 mean unknown version, not a failure worth retrying
            resp = http.get(
                url,
                self.logger,
                retries=self.retries,
                backoff_in_seconds=self.backoff_in_seconds,
                timeout=self.timeout,
                status_handler=lambda r: None if r.status_code in (200, 404, 410) else r.raise_for_status(),
                user_agent=USER_AGENT,
            )
        except Exception as e:
            self.logger.warning(f"go release-date lookup failed for {url}: {e}")
            return None

        if resp.status_code != 200:
            self.logger.debug(f"no release-date record at {url} (HTTP {resp.status_code})")
            return None

        body = resp.content
        if strip_xss_guard:
            # gitiles prefixes JSON with a `)]}'` XSS-guard line that must be stripped
            body = body.split(b"\n", 1)[1] if body.startswith(b")]}'") and b"\n" in body else body

        try:
            payload = orjson.loads(body)
        except orjson.JSONDecodeError as e:
            self.logger.warning(f"ignoring unparseable release-date response from {url}: {e}")
            return None

        if not isinstance(payload, dict):
            self.logger.warning(f"ignoring unexpected release-date response from {url}: not a JSON object")
            return None
        return payload


def is_go_maintained(module: str) -> bool:
    """The toolchain/stdlib and extended stdlib -- the modules Go itself publishes."""
    return module in STDLIB_MODULES or module.startswith(EXTENDED_STDLIB_PREFIX)


def should_resolve(module: str, aliases: Iterable[str] | None) -> bool:
    """Whether a release date for this module is worth looking up.

    Go's own modules always are: no GHSA names `stdlib`, and the extended stdlib
    is cheap (a few dozen lookups a run) and survives often enough to matter.

    A third-party module only is when the advisory names no GHSA alias. Grype
    merges a GO record into its aliased GHSA twin and drops every affected
    package the GHSA also names, so a date computed for one of those is
    discarded; a record with no GHSA to merge into keeps its packages, and its
    date is the one that ships. Erring towards looking up costs a request and a
    thrown-away date; erring against it ships the disclosure date as if it were
    the fix date, so an alias we cannot resolve is treated as covering.
    """
    if not module:
        return False
    if is_go_maintained(module):
        return True
    return not any(isinstance(a, str) and a.upper().startswith("GHSA-") for a in (aliases or []))


def _module_info_url(module: str, version: str) -> str | None:
    """The proxy `.info` URL for a module version, or None if it cannot be built safely."""
    if not _valid_module_path(module) or not _MODULE_VERSION_RE.fullmatch(version):
        return None
    v = version if version.startswith("v") else f"v{version}"
    return f"{MODULE_PROXY_URL}/{_escape_module_path(module)}/@v/{_escape_module_path(v)}.info"


def _valid_module_path(module: str) -> bool:
    if len(module) > _MAX_MODULE_PATH_LENGTH or not _MODULE_PATH_RE.fullmatch(module):
        return False
    # `.` and `-` are legal in a path element but `.`/`..` elements are not, and
    # neither are empty ones: both would re-point the URL somewhere else
    return all(segment not in ("", ".", "..") for segment in module.split("/"))


def _stdlib_tag_url(tag: str) -> str:
    # safe to interpolate: the only source of `tag` is _stdlib_version_to_tag, which
    # returns None for anything that isn't _RELEASE_TAG_RE
    return f"{GO_GIT_URL}/+/refs/tags/{tag}?format=JSON"


def _module_release_date(payload: dict[str, Any] | None) -> date | None:
    if not payload:
        return None
    return _parse_iso_date(payload.get("Time"))


def _stdlib_release_date(payload: dict[str, Any] | None) -> date | None:
    if not payload:
        return None
    # committer time is the release commit on the release branch
    committer = payload.get("committer") or payload.get("author") or {}
    if not isinstance(committer, dict):
        return None
    return _parse_gitiles_time(committer.get("time"))


def _stdlib_version_to_tag(version: str) -> str | None:
    """Map a go vuln db stdlib version to its golang/go release tag, or None.

    Prereleases use the toolchain's compact form (`1.27.0-rc.3` -> `go1.27rc3`);
    the go vuln db lists them because an upcoming minor's RC is often the first
    artifact carrying a fix. Releases drop the `.0` only below 1.21 -- Go tagged
    the 1.20 series `go1.20`, `go1.20.1`, ... and only started tagging `goX.Y.0`
    at `go1.21.0`.

    Returns None for a version that names no released artifact. Go only tags
    `rc` and `beta` prereleases, so govulndb's semver floor `1.21.0-0` -- which
    means "every 1.21 prerelease and later", used to say the `toolchain` module
    did not exist before 1.21 -- has no tag. Building one anyway produced
    `go1.210`, a plausible-looking tag that will never exist and that cost a
    request to go.googlesource.com on every single run.
    """
    v = version.removeprefix("go")
    if "-" in v:
        base, _, pre = v.partition("-")
        pre = pre.replace(".", "")
        if not _PRERELEASE_RE.fullmatch(pre):
            return None
        tag = f"go{base.removesuffix('.0')}{pre}"
    else:
        tag = f"go{_release_tag_body(v)}"
    return tag if _RELEASE_TAG_RE.fullmatch(tag) else None


def _release_tag_body(version: str) -> str:
    """`1.20.0` -> `1.20`, but leave `1.21.0` and later alone (see _stdlib_version_to_tag)."""
    base = version.removesuffix(".0")
    if base == version:
        return version
    try:
        major, minor = (int(part) for part in base.split(".", 1))
    except ValueError:
        return version
    return base if (major, minor) < (1, 21) else version


def _escape_module_path(module: str) -> str:
    """Module proxy path escaping: uppercase becomes `!` + lowercase.

    Applies to the version as well as the module path -- the proxy's case-encoding
    rule covers every path element it serves.
    """
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in module)


def _parse_table_date(tag: str, released: str, logger: logging.Logger) -> date | None:
    try:
        return date.fromisoformat(released)
    except ValueError:
        # the table is generated, so this means it was hand-edited into something invalid
        logger.warning(f"committed go release-date table has an invalid date for {tag}: {released!r}")
        return None


def _parse_iso_date(s: str | None) -> date | None:
    """Parse a module-proxy ISO-8601 timestamp (e.g. `2023-08-01T17:46:51Z`) as a UTC date."""
    if not isinstance(s, str) or not s:
        return None
    try:
        parsed = datetime.fromisoformat(s)
    except ValueError:
        return None
    return _as_utc_date(parsed)


def _parse_gitiles_time(s: str | None) -> date | None:
    """Parse a gitiles git-time string, e.g. `Tue Dec 05 18:12:56 2023 +0000`, as a UTC date."""
    if not isinstance(s, str) or not s:
        return None
    try:
        parsed = datetime.strptime(s, "%a %b %d %H:%M:%S %Y %z")
    except ValueError:
        return None
    return _as_utc_date(parsed)


def _as_utc_date(value: datetime) -> date:
    """The UTC calendar date of a timestamp.

    Release commits are tagged from whatever timezone the release runner sits in
    (`-0800` for most go releases), so the local date and the UTC date disagree
    for late-in-the-day releases. Normalizing means one release has one date
    whichever source answered, and matches how every other date in vunnel reads.
    """
    if value.tzinfo is None:
        return value.date()
    return value.astimezone(UTC).date()


def go_extra_candidates(
    overlay: GoReleaseDateOverlay,
    aliases: Iterable[str] | None = None,
) -> Callable[[str, str, str, str | None], list[_fixdate.Result]]:
    """Build the extra-candidates callable for osv.patch_fix_date.

    Built per advisory, because whether a third-party module's date is worth
    resolving depends on that advisory's aliases (see `should_resolve`).

    accurate=True so the release date wins against first-observed and the
    advisory's low-confidence published date.
    """
    # Local import - fixdate package isn't always loaded at module-init time.
    from vunnel.tool import fixdate  # noqa: PLC0415

    alias_list = list(aliases or [])

    def candidates(vuln_id: str, package_name: str, fix_version: str, ecosystem: str | None) -> list[fixdate.Result]:
        if not should_resolve(package_name, alias_list):
            return []
        d = overlay.lookup(package_name, fix_version)
        if d is None:
            return []
        return [fixdate.Result(date=d, kind="release", accurate=True)]

    return candidates
