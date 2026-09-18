"""Release dates for the Go versions the go.dev OSV records name as fixed.

go.dev's records carry no per-fix date, and their `published` field is a
disclosure timestamp rather than a fix-ship date. But for Go the fix *version*
names a published artifact whose release date is knowable:

- stdlib/toolchain: golang/go release tags. When a release shipped never
  changes, so everything already out is served from the committed
  `go_release_dates_data` table; only newer releases reach go.googlesource.com.
- extended stdlib (`golang.org/x/...`): the module proxy's `.info` -> `.Time`,
  the tag time of the release.

Third-party modules are deliberately not resolved. Grype's
`db/v6/build/govulndb_merge.go` drops any GO affected package that an aliased
GHSA also names, and lets the GHSA's ranges win on the rest, so their dates get
computed and then discarded -- 3,275 of 3,375 proxy lookups, ~9 minutes a run.
They fall back to the advisory's published date instead. `stdlib` is the one
module no GHSA names, so it always survives the merge.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.providers.govulndb.go_release_dates_data import GO_RELEASE_DATES
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Callable

    import requests

    from vunnel.tool import fixdate as _fixdate

MODULE_PROXY_URL = "https://proxy.golang.org"
GO_GIT_URL = "https://go.googlesource.com/go"

# these map to Go toolchain release tags, not proxy module versions
STDLIB_MODULES = {"stdlib", "toolchain"}

# the extended stdlib; unlike the toolchain these are ordinary proxy modules
EXTENDED_STDLIB_PREFIX = "golang.org/x/"

USER_AGENT = "vunnel/1.0 (govulndb-provider; +https://github.com/anchore/vunnel)"


class GoReleaseDateLookupError(RuntimeError):
    """Raised when an authoritative Go release-date source cannot be queried."""


class GoReleaseDateOverlay:
    """`(module, version) -> release date`, memoized by request URL.

    Keying on the URL rather than `(module, version)` collapses `stdlib` and
    `toolchain`, which share a release tag. Negatives are cached too.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        timeout: int = http.DEFAULT_TIMEOUT,
        retries: int = 3,
        backoff_in_seconds: int = 3,
    ):
        self._cache: dict[str, date | None] = {}
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        self.timeout = timeout
        self.retries = retries
        self.backoff_in_seconds = backoff_in_seconds

    def lookup(self, module: str, version: str) -> date | None:
        """Return the release date for a Go (module, version), or None on miss."""
        if not module or not version or not is_go_maintained(module):
            return None

        stdlib = module in STDLIB_MODULES

        if stdlib:
            tag = _stdlib_version_to_tag(version)
            released = GO_RELEASE_DATES.get(tag)
            if released:
                return date.fromisoformat(released)
            self.logger.debug(f"{tag} is not in the committed go release-date table, falling back to {GO_GIT_URL}")
            url = _stdlib_tag_url(tag)
        else:
            url = _module_info_url(module, version)

        if url in self._cache:
            return self._cache[url]

        payload = self._get_gitiles_json(url) if stdlib else self._get_json(url)
        result = _stdlib_release_date(payload) if stdlib else _module_release_date(payload)

        self._cache[url] = result
        return result

    def _get_json(self, url: str) -> dict[str, Any] | None:
        resp = self._get(url)
        if resp is None or resp.status_code != 200:
            return None
        try:
            return orjson.loads(resp.content)
        except orjson.JSONDecodeError:
            raise GoReleaseDateLookupError(f"failed to parse JSON from {url}") from None

    def _get_gitiles_json(self, url: str) -> dict[str, Any] | None:
        # gitiles prefixes JSON with a `)]}'` XSS-guard line that must be stripped
        resp = self._get(url)
        if resp is None or resp.status_code != 200:
            return None
        body = resp.content
        if body.startswith(b")]}'"):
            body = body.split(b"\n", 1)[1]
        try:
            return orjson.loads(body)
        except orjson.JSONDecodeError:
            raise GoReleaseDateLookupError(f"failed to parse gitiles JSON from {url}") from None

    def _get(self, url: str) -> requests.Response | None:
        try:
            # 404/410 mean unknown version, not a failure worth retrying
            return http.get(
                url,
                self.logger,
                retries=self.retries,
                backoff_in_seconds=self.backoff_in_seconds,
                timeout=self.timeout,
                status_handler=lambda r: None if r.status_code in (200, 404, 410) else r.raise_for_status(),
                user_agent=USER_AGENT,
            )
        except Exception as e:
            raise GoReleaseDateLookupError(f"go release-date lookup failed for {url}: {e}") from e


def is_go_maintained(module: str) -> bool:
    """The toolchain/stdlib and extended stdlib -- the modules whose dates survive the merge downstream."""
    return module in STDLIB_MODULES or module.startswith(EXTENDED_STDLIB_PREFIX)


def _module_info_url(module: str, version: str) -> str:
    v = version if version.startswith("v") else f"v{version}"
    return f"{MODULE_PROXY_URL}/{_escape_module_path(module)}/@v/{v}.info"


def _stdlib_tag_url(tag: str) -> str:
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
    return _parse_gitiles_time(committer.get("time"))


def _stdlib_version_to_tag(version: str) -> str:
    """Map a go vuln db stdlib version to its golang/go release tag.

    Prereleases use the toolchain's compact form (`1.27.0-rc.3` -> `go1.27rc3`);
    the go vuln db lists them because an upcoming minor's RC is often the first
    artifact carrying a fix. Releases drop the `.0` only below 1.21 -- Go tagged
    the 1.20 series `go1.20`, `go1.20.1`, ... and only started tagging `goX.Y.0`
    at `go1.21.0`.
    """
    v = version[2:] if version.startswith("go") else version
    if "-" in v:
        base, pre = v.split("-", 1)
        return f"go{base.removesuffix('.0')}{pre.replace('.', '')}"
    return f"go{_release_tag_body(v)}"


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
    """Module proxy path escaping: uppercase becomes `!` + lowercase."""
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in module)


def _parse_iso_date(s: str | None) -> date | None:
    """Parse a module-proxy ISO-8601 timestamp (e.g. `2023-08-01T17:46:51Z`)."""
    if not s:
        return None
    try:
        normalized = s.rstrip("Z").rstrip()
        if "T" in normalized:
            return datetime.fromisoformat(normalized).date()
        return date.fromisoformat(normalized)
    except (ValueError, TypeError):
        return None


def _parse_gitiles_time(s: str | None) -> date | None:
    """Parse a gitiles git-time string, e.g. `Tue Dec 05 18:12:56 2023 +0000`."""
    if not s:
        return None
    try:
        return datetime.strptime(s, "%a %b %d %H:%M:%S %Y %z").date()
    except (ValueError, TypeError):
        return None


def go_extra_candidates(
    overlay: GoReleaseDateOverlay | None,
) -> Callable[[str, str, str, str | None], list[_fixdate.Result]] | None:
    """Build the extra-candidates callable for osv.patch_fix_date.

    accurate=True so the release date wins against first-observed and the
    advisory's low-confidence published date.
    """
    if overlay is None:
        return None

    # Local import - fixdate package isn't always loaded at module-init time.
    from vunnel.tool import fixdate  # noqa: PLC0415

    def candidates(vuln_id: str, package_name: str, fix_version: str, ecosystem: str | None) -> list[fixdate.Result]:
        d = overlay.lookup(package_name, fix_version)
        if d is None:
            return []
        return [fixdate.Result(date=d, kind="go-release", accurate=True)]

    return candidates
