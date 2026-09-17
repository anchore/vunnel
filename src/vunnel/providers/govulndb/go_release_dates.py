"""Resolve authoritative release dates for Go module/stdlib versions, used as
an accurate fix-availability date source for the go.dev OSV records.

go.dev's OSV records carry no per-fix date, and the advisory's own `published`
field is a disclosure timestamp, not a fix-ship date. But for Go the fix
*version* is enough to recover the real fix date, because every published Go
artifact has a knowable release date:

- **Modules** (incl. the extended stdlib `golang.org/x/...` and third-party
  modules like `google.golang.org/protobuf`): the Go module proxy exposes the
  tag date per version at `.../@v/v<version>.info` -> `.Time`. This is the git
  tag time of the release, which is the moment the fixed version became
  available. It is authoritative and covers every module version.

- **stdlib / toolchain** (module name `stdlib` or `toolchain`, fixed versions
  like `1.21.5`): the toolchain isn't a proxy module in a useful form, so we
  read the `go<version>` tag commit date from the golang/go git mirror at
  go.googlesource.com. Spot-check: `go1.21.5` -> 2023-12-05, the real release
  day.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Callable

    import requests

    from vunnel.tool import fixdate as _fixdate

MODULE_PROXY_URL = "https://proxy.golang.org"
GO_GIT_URL = "https://go.googlesource.com/go"

# module names in the go vuln db that map to Go toolchain release tags rather
# than proxy module versions
STDLIB_MODULES = {"stdlib", "toolchain"}
USER_AGENT = "vunnel/1.0 (govulndb-provider; +https://github.com/anchore/vunnel)"


class GoReleaseDateLookupError(RuntimeError):
    """Raised when an authoritative Go release-date source cannot be queried."""


class GoReleaseDateOverlay:
    """`(module, version) -> release date` resolver backed by the Go module
    proxy (modules) and the golang/go git mirror (stdlib/toolchain).

    Results are memoized, negatives included, so repeated lookups for the same
    tuple never re-hit the network.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        timeout: int = http.DEFAULT_TIMEOUT,
        retries: int = 3,
        backoff_in_seconds: int = 3,
    ):
        self._cache: dict[tuple[str, str], date | None] = {}
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        self.timeout = timeout
        self.retries = retries
        self.backoff_in_seconds = backoff_in_seconds

    def lookup(self, module: str, version: str) -> date | None:
        """Return the release date for a Go (module, version), or None on miss."""
        if not module or not version:
            return None

        key = (module, version)
        if key in self._cache:
            return self._cache[key]

        result = self._lookup_stdlib(version) if module in STDLIB_MODULES else self._lookup_module(module, version)

        self._cache[key] = result
        return result

    def _lookup_module(self, module: str, version: str) -> date | None:
        escaped = _escape_module_path(module)
        v = version if version.startswith("v") else f"v{version}"
        url = f"{MODULE_PROXY_URL}/{escaped}/@v/{v}.info"
        payload = self._get_json(url)
        if not payload:
            return None
        return _parse_iso_date(payload.get("Time"))

    def _lookup_stdlib(self, version: str) -> date | None:
        tag = _stdlib_version_to_tag(version)
        url = f"{GO_GIT_URL}/+/refs/tags/{tag}?format=JSON"
        payload = self._get_gitiles_json(url)
        if not payload:
            return None
        # committer time is the release commit on the release branch
        committer = payload.get("committer") or payload.get("author") or {}
        return _parse_gitiles_time(committer.get("time"))

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
            # treat 404/410 as an ordinary miss (unknown version) rather than an
            # error to retry on; only real failures should retry/raise
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


def _stdlib_version_to_tag(version: str) -> str:
    """Map a go vuln db stdlib version to its golang/go release tag.

    Point releases map straight across (`1.25.13` -> `go1.25.13`,
    `1.27.0` -> `go1.27.0`). Prereleases use the toolchain's compact tag form:
    the trailing `.0` patch is dropped and the prerelease loses its dots, so
    `1.27.0-rc.3` -> `go1.27rc3` and `1.20.0-beta.1` -> `go1.20beta1`. The go
    vuln db lists these RCs as fixed versions because an upcoming minor's RC is
    often the first shipped artifact carrying a fix.
    """
    v = version[2:] if version.startswith("go") else version
    if "-" in v:
        base, pre = v.split("-", 1)
        base = base.removesuffix(".0")
        pre = pre.replace(".", "")
        return f"go{base}{pre}"
    return f"go{v}"


def _escape_module_path(module: str) -> str:
    """Escape a module path for the module proxy: uppercase letters become
    `!` + lowercase (e.g. `github.com/Azure/...` -> `github.com/!azure/...`).
    """
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

    Returns a function with the signature patch_fix_date expects
    (vuln_id, package_name, fix_version, ecosystem) -> list[Result]. The
    release-date candidate is marked accurate=True so it wins against
    first-observed and the advisory's low-confidence published date.
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
