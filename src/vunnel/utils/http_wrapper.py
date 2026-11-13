from __future__ import annotations

import contextlib
import glob
import os
import random
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from importlib import metadata
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import requests

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable

DEFAULT_TIMEOUT = 30

# Default wait time when Retry-After header is missing or unparseable
# NVD uses a 30-second rolling window, so this is tuned for that use case
DEFAULT_RATE_LIMIT_WAIT = 30.0
# Maximum wait time for rate limiting to prevent DoS via malicious Retry-After header
MAX_RATE_LIMIT_WAIT = 300.0  # 5 minutes


def default_user_agent() -> str:
    """
    Return the default User-Agent string used when a caller does not supply one.

    Format follows the same convention as the per-provider helpers
    (chainguard_libraries, secureos, fedora) so vunnel always identifies
    itself when fetching upstream data sources.
    """
    try:
        version = metadata.version("vunnel")
    except metadata.PackageNotFoundError:
        version = "unknown"
    return f"anchore/vunnel-{version}"


def _is_rate_limited(response: requests.Response) -> bool:
    """
    Check if response indicates rate limiting.

    Rate limiting is detected for:
    - 429 (Too Many Requests) - always
    - 503 (Service Unavailable) - only if Retry-After header is present
    - 403 (Forbidden) - only if Retry-After header is present
      (GitHub returns 403 + Retry-After for secondary rate limits;
      see https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
    """
    if response.status_code == 429:
        return True
    if response.status_code in (403, 503):
        return bool(response.headers.get("Retry-After"))
    return False


def parse_retry_after(header_value: str | None) -> float | None:
    """
    Parse Retry-After header value.

    Supports two formats per RFC 7231:
    - Seconds: "120" (delay in seconds)
    - HTTP-date: "Wed, 21 Oct 2015 07:28:00 GMT"

    Returns:
        Number of seconds to wait, or None if header is missing/unparseable.
    """
    if not header_value:
        return None

    header_value = header_value.strip()

    # Try parsing as integer (seconds)
    try:
        seconds = int(header_value)
        # Return None for zero/negative values - caller should use default
        return float(seconds) if seconds > 0 else None
    except ValueError:
        pass

    # Try parsing as HTTP-date
    try:
        dt = parsedate_to_datetime(header_value)
        delay = dt.timestamp() - time.time()
        # Return None if the time has already passed - caller should use default
        return delay if delay > 0 else None
    except (ValueError, TypeError):
        pass

    return None


@dataclass
class HostState:
    """Per-host state for connection pooling and rate limiting."""

    hostname: str
    # Session provides connection pooling - TCP connections are reused via urllib3
    session: requests.Session = field(default_factory=requests.Session)
    blocked_until: float = 0.0  # timestamp when rate limit expires
    lock: threading.Lock = field(default_factory=threading.Lock)
    # Semaphore with 1 permit - used to serialize requests when rate-limited
    semaphore: threading.Semaphore = field(default_factory=lambda: threading.Semaphore(1))


class HostRegistry:
    """Registry managing per-host state for HTTP requests."""

    def __init__(self) -> None:
        self._hosts: dict[str, HostState] = {}
        self._lock = threading.Lock()

    def get_state(self, hostname: str) -> HostState:
        """Get or create state for a hostname."""
        with self._lock:
            if hostname not in self._hosts:
                self._hosts[hostname] = HostState(hostname=hostname)
            return self._hosts[hostname]

    def acquire_slot(self, hostname: str, logger: logging.Logger | None = None) -> HostState:
        """
        Acquire a slot to make a request to the given host.

        Waits if the host is rate-limited.
        Returns the HostState to use for the request.
        """
        state = self.get_state(hostname)

        with state.lock:
            now = time.time()
            # Check rate limiting (just log, actual wait happens after semaphore)
            if state.blocked_until > now:
                wait_time = state.blocked_until - now
                if logger:
                    logger.info(f"Rate limited for {hostname}, waiting {wait_time:.1f}s")

        # Acquire semaphore to serialize requests when rate-limited
        # This prevents thundering herd when rate limit expires
        state.semaphore.acquire()

        # Re-check after acquiring semaphore (another thread may have updated state)
        with state.lock:
            now = time.time()
            if state.blocked_until > now:
                wait_time = state.blocked_until - now
                if logger:
                    logger.debug(f"Waiting {wait_time:.1f}s for rate limit on {hostname}")
                time.sleep(wait_time)

        return state

    def release_slot(self, state: HostState) -> None:
        """Release the slot after a request completes."""
        state.semaphore.release()

    def record_rate_limit(self, hostname: str, retry_after: float | None = None) -> None:
        """
        Record that we received a rate limit response.

        Args:
            hostname: The host that rate-limited us
            retry_after: Seconds to wait (from Retry-After header), or None for default
        """
        state = self.get_state(hostname)
        with state.lock:
            wait_time = retry_after if retry_after is not None else DEFAULT_RATE_LIMIT_WAIT
            wait_time = min(wait_time, MAX_RATE_LIMIT_WAIT)  # Cap to prevent DoS
            state.blocked_until = time.time() + wait_time


# Module-level singleton registry
_registry: HostRegistry | None = None


def _get_registry() -> HostRegistry:
    """Get the global HostRegistry, creating it if necessary."""
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = HostRegistry()
    return _registry


def _reset_for_testing() -> None:
    """Reset the global registry. For testing only."""
    global _registry  # noqa: PLW0603
    _registry = None


def _extract_hostname(url: str) -> str:
    """Extract hostname from a URL.

    Returns the hostname (netloc) from the URL. For URLs without a scheme,
    falls back to extracting from the path. Returns 'unknown' if hostname
    cannot be determined.
    """
    parsed = urlparse(url)
    hostname = parsed.netloc
    if not hostname:
        # Handle URLs without scheme like "example.com/path"
        hostname = parsed.path.split("/")[0]
    # Return 'unknown' for empty/invalid hostnames to ensure HostRegistry works
    return hostname if hostname else "unknown"


def get(  # noqa: PLR0913, PLR0915, C901
    url: str,
    logger: logging.Logger,
    retries: int = 5,
    backoff_in_seconds: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
    status_handler: Callable[[requests.Response], None] | None = None,
    max_interval: int = 600,
    user_agent: str | None = None,
    **kwargs: Any,
) -> requests.Response:
    """
    Perform requests.get on the url with configurable retries. Retried failures are logged as warnings.

    Features:
        - Per-host connection pooling (TCP connection reuse)
        - Rate limit handling with Retry-After support (429 always; 403 / 503 with header)
        - Exponential backoff on errors

    Response handling follows a 3-step fallback:
        1. Rate limit check (always enforced) - 429, or 403 / 503 with Retry-After
        2. status_handler (if provided) - caller controls validation
        3. raise_for_status() - default validation with retry on HTTPError

    Args:
        url (string): the url to get
        logger: a logging.Logger that info about the request should be logged to
        retries: how many times should the call be re-attempted if it fails. A maximum of retries+1 calls are made.
        backoff_in_seconds: passed to time.sleep between retries
        timeout: passed to requests.get. defaults to 30 seconds.
        status_handler: a Callable to call to validate the response.
            If the Callable raises an exception, the exception will be logged, and retried if any retries remain.
            If the Callable does not raise, the response will be returned, and the caller is responsible for any
            further validation.
            If no Callable is provided, `raise_for_status` is called on the response instead.
        user_agent: the User-Agent header value. If None (the default), the wrapper sets
            a vunnel-identifying User-Agent so we always identify ourselves to upstream
            servers; pass an empty string to skip the header entirely.
        **kwargs: additional args are passed to requests.get unchanged.
    Raises:
        If retries are exhausted, re-raises the exception from the last requests.get attempt.

    Example:
        http.get("http://example.com/some-url", self.logger, retries=3, backoff_in_seconds=30,
                 status_handler= lambda response: None if response.status_code in [200, 201, 405] else response.raise_for_status())

    """
    headers = kwargs.pop("headers", {})
    if user_agent is None:
        # Default: always identify ourselves so providers and upstreams can attribute traffic.
        # Callers that need to opt out can pass user_agent="".
        headers.setdefault("User-Agent", default_user_agent())
    elif user_agent:
        headers["User-Agent"] = user_agent

    hostname = _extract_hostname(url)
    registry = _get_registry()

    last_exception: Exception | None = None
    skip_backoff = False  # Set when rate-limited (acquire_slot handles the wait)

    for attempt in range(retries + 1):
        # Apply backoff delay if this is a retry (but not for rate-limit retries)
        if last_exception and not skip_backoff:
            sleep_interval = backoff_sleep_interval(backoff_in_seconds, attempt - 1, max_value=max_interval)
            logger.warning(f"will retry in {int(sleep_interval)} seconds...")
            time.sleep(sleep_interval)

        # Reset for this attempt
        skip_backoff = False
        last_exception = None
        state = None

        try:
            # Acquire slot (handles rate limiting wait)
            state = registry.acquire_slot(hostname, logger)

            logger.debug(f"http GET {url} timeout={timeout} retries={retries} backoff={backoff_in_seconds}")
            response = state.session.get(url, timeout=timeout, headers=headers, **kwargs)

            # Step 1: Rate limit check (always enforced, caller cannot bypass)
            if _is_rate_limited(response):
                # record the rate limit before checking whether we have retries left, so that a
                # caller with retries=0 (e.g. download_to_file, which owns its own retry loop)
                # still leaves the host marked as blocked for whoever asks next
                retry_after = parse_retry_after(response.headers.get("Retry-After"))
                registry.record_rate_limit(hostname, retry_after)

                # Check if we've exhausted retries - if so, fail now instead of waiting
                if attempt >= retries:
                    logger.warning(f"Rate limited by {hostname}, no retries remaining")
                    response.raise_for_status()

                wait_time = retry_after if retry_after is not None else DEFAULT_RATE_LIMIT_WAIT
                wait_time = min(wait_time, MAX_RATE_LIMIT_WAIT)
                logger.warning(f"Rate limited by {hostname}, will retry after {wait_time:.1f}s")

                # Skip backoff on next iteration (acquire_slot handles the wait)
                skip_backoff = True
                # Release slot before continuing so acquire_slot can re-acquire after wait
                registry.release_slot(state)
                state = None
                continue

            # Step 2: status_handler (caller override)
            if status_handler:
                status_handler(response)  # May raise, caught below for retry
                return response

            # Step 3: Default validation
            response.raise_for_status()
            return response

        except requests.exceptions.HTTPError as e:
            last_exception = e
            logger.warning(f"attempt {attempt + 1} of {retries + 1} failed: {e}")
        except Exception as e:
            last_exception = e
            # Include the URL in case the exception message doesn't
            logger.warning(f"attempt {attempt + 1} of {retries + 1}: unexpected exception during GET {url}: {e}")
        finally:
            if state is not None:
                registry.release_slot(state)

    if last_exception:
        logger.error(f"last retry of GET {url} failed with {last_exception}")
        raise last_exception
    raise Exception("unreachable")


def backoff_sleep_interval(interval: int, attempt: int, max_value: None | int = None, jitter: bool = True) -> float:
    # this is an exponential backoff
    val = interval * 2**attempt
    if max_value and val > max_value:
        val = max_value
    if jitter:
        val += random.uniform(0, 1)  # noqa: S311
        # explanation of S311 disable: rng is not used cryptographically
    return val


# ---------------------------------------------------------------------------
# file downloads
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_SIZE = 65536  # 64k

# suffix of the staging file download_to_file writes into before publishing to dest;
# exposed so callers that sweep their workspace for orphaned downloads (left behind by a
# killed process, rather than cleaned up by download_to_file's own retry-exhaustion path)
# don't have to re-derive this convention themselves
PARTIAL_SUFFIX = ".part"


def download_to_file(  # noqa: PLR0913
    url: str,
    dest: str | os.PathLike[str],
    logger: logging.Logger,
    *,
    retries: int = 5,
    backoff_in_seconds: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
    max_interval: int = 600,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    **kwargs: Any,
) -> requests.Response:
    """Download `url` to `dest`, retrying the whole transfer.

    `get(..., stream=True)` returns once the response headers arrive, so its retry loop
    only ever covered connect, TLS and status: the body was drained by the caller,
    outside the loop, and a connection dropped mid-body got no retries at all. Here the
    body is drained *inside* the loop, which is the difference between `retries=5` being
    a guarantee and being decoration.

    Bytes land in a sibling `.part` file and are renamed onto `dest` only once the
    transfer finishes, so a failed run cannot leave a partial file where the next run
    expects a whole one. The rename is within one directory, and so never crosses a
    filesystem. Not safe to call concurrently for the same `dest`: two callers would
    stage into, and race to rename, the same `.part` file.

    Args:
        url: the url to download.
        dest: the local path to publish the finished download to.
        logger: a logging.Logger that info about the download should be logged to.
        retries: how many times the whole transfer is re-attempted if it fails.
        backoff_in_seconds: passed to time.sleep between retries.
        timeout: passed to requests.get. defaults to 30 seconds.
        max_interval: caps the exponential backoff between retries.
        chunk_size: bytes read from the response per iteration while streaming to disk.
        **kwargs: forwarded to `get()`, except `stream` (always True here) and
            `status_handler`, which this function does not accept - see Raises.

    Returns:
        The response, whose body has already been drained to `dest`; it is useful only
        for its headers and status.

    Raises:
        TypeError: if `status_handler` is passed. A permissive handler could accept a
            non-2xx response and this function would then write and publish that
            response's body to `dest` as if it were a valid download.
        Re-raises the last attempt's exception once retries are exhausted.
    """
    if "status_handler" in kwargs:
        raise TypeError(
            "download_to_file does not support status_handler: a response it accepts would still be "
            "written to dest and published, bypassing the validation atomic publish depends on",
        )
    dest = os.fspath(dest)
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)
    partial = dest + PARTIAL_SUFFIX

    last_exception: Exception | None = None

    for attempt in range(retries + 1):
        if last_exception:
            sleep_interval = backoff_sleep_interval(backoff_in_seconds, attempt - 1, max_value=max_interval)
            logger.warning(f"will retry in {int(sleep_interval)} seconds...")
            time.sleep(sleep_interval)

        try:
            # retries=0: this loop owns retrying, so that a failure while reading the
            # body is retried just like a failure while connecting
            with (
                get(url, logger, retries=0, timeout=timeout, stream=True, **kwargs) as response,
                open(partial, "wb") as fh,
            ):
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        fh.write(chunk)
                # the rename must not publish a file the OS still holds in a write buffer
                fh.flush()
                os.fsync(fh.fileno())

            os.replace(partial, dest)
            logger.info(f"downloaded {url} to {dest}")
            return response

        except Exception as e:
            last_exception = e
            logger.warning(f"attempt {attempt + 1} of {retries + 1} failed downloading {url}: {e}")

    with contextlib.suppress(OSError):
        os.remove(partial)

    if last_exception:
        logger.error(f"giving up on {url}: {last_exception}")
        raise last_exception
    raise Exception("unreachable")


def remove_stale_partial_downloads(directory: str, logger: logging.Logger) -> None:
    """Remove any `.part` staging files left under `directory` by an interrupted download.

    download_to_file only cleans up its own staging file when its own retry loop
    exhausts; a killed process (OOM, SIGKILL) skips that, so a caller whose downloads
    aren't reliably retried on every run (e.g. one file per item, only re-fetched if
    that item changes) should sweep for leftovers on startup.
    """
    for part_file in glob.glob(os.path.join(directory, "**", "*" + PARTIAL_SUFFIX), recursive=True):
        logger.warning(f"removing stray partial download: {part_file}")
        with contextlib.suppress(OSError):
            os.remove(part_file)
