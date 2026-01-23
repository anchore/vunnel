from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
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


def _is_rate_limited(response: requests.Response) -> bool:
    """
    Check if response indicates rate limiting.

    Rate limiting is detected for:
    - 429 (Too Many Requests) - always
    - 503 (Service Unavailable) - only if Retry-After header is present
    """
    if response.status_code == 429:
        return True
    return response.status_code == 503 and bool(response.headers.get("Retry-After"))


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


def get(  # noqa: PLR0913, C901
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
        - Rate limit handling with Retry-After support (429, 503 with header)
        - Exponential backoff on errors

    Response handling follows a 3-step fallback:
        1. Rate limit check (always enforced) - 429 or 503 with Retry-After
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
        user_agent: the User-Agent header value. If None or empty, no User-Agent header is set.
        **kwargs: additional args are passed to requests.get unchanged.
    Raises:
        If retries are exhausted, re-raises the exception from the last requests.get attempt.

    Example:
        http.get("http://example.com/some-url", self.logger, retries=3, backoff_in_seconds=30,
                 status_handler= lambda response: None if response.status_code in [200, 201, 405] else response.raise_for_status())

    """
    headers = kwargs.pop("headers", {})
    if user_agent:
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
                # Check if we've exhausted retries - if so, fail now instead of waiting
                if attempt >= retries:
                    logger.warning(f"Rate limited by {hostname}, no retries remaining")
                    response.raise_for_status()

                # Parse Retry-After and record rate limit
                retry_after = parse_retry_after(response.headers.get("Retry-After"))
                registry.record_rate_limit(hostname, retry_after)
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
