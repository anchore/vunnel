from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import requests

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable

DEFAULT_TIMEOUT = 30

# Status code classifications for retry logic
RETRY_ONCE_CODES = {400, 401, 403, 404, 405, 410}  # Client errors, retry once
RATE_LIMIT_CODES = {429, 503}  # Respect Retry-After header
RETRY_WITH_BACKOFF_CODES = {408, 500, 502, 504}  # Server errors, exponential backoff

# Default wait time when Retry-After header is missing or unparseable
DEFAULT_RATE_LIMIT_WAIT = 60.0
# Maximum wait time for rate limiting to prevent DoS via malicious Retry-After header
MAX_RATE_LIMIT_WAIT = 300.0  # 5 minutes


class RetryStrategy(Enum):
    """Strategy for retrying HTTP requests based on status code."""

    SUCCESS = auto()  # 2xx - request succeeded
    RETRY_ONCE = auto()  # Client errors - retry once, then raise
    RATE_LIMITED = auto()  # 429/503 - respect Retry-After, coordinate threads
    RETRY_WITH_BACKOFF = auto()  # Server errors - exponential backoff
    NO_RETRY = auto()  # Other errors - don't retry


def classify_status_code(status_code: int) -> RetryStrategy:
    """
    Classify an HTTP status code into a retry strategy.

    Args:
        status_code: The HTTP response status code

    Returns:
        The appropriate RetryStrategy for this status code
    """
    if 200 <= status_code < 300:
        return RetryStrategy.SUCCESS
    if status_code in RETRY_ONCE_CODES:
        return RetryStrategy.RETRY_ONCE
    if status_code in RATE_LIMIT_CODES:
        return RetryStrategy.RATE_LIMITED
    if status_code in RETRY_WITH_BACKOFF_CODES:
        return RetryStrategy.RETRY_WITH_BACKOFF
    # Other 4xx errors (like 422, 451) - don't retry, they're permanent
    # Other 5xx errors (like 501, 505) - don't retry, they're likely permanent
    return RetryStrategy.NO_RETRY


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
        return max(0.0, float(seconds))
    except ValueError:
        pass

    # Try parsing as HTTP-date
    try:
        dt = parsedate_to_datetime(header_value)
        delay = dt.timestamp() - time.time()
        return max(0.0, delay)
    except (ValueError, TypeError):
        pass

    return None


@dataclass
class HttpConfig:
    """Configuration for HTTP request behavior."""

    circuit_breaker_threshold: int = 5  # Failures before circuit opens
    circuit_breaker_recovery: float = 60.0  # Seconds before half-open
    respect_retry_after: bool = True  # Honor Retry-After header
    retry_once_on_client_error: bool = True  # Retry RETRY_ONCE_CODES once


# Module-level configuration
_config: HttpConfig | None = None


def configure(config: HttpConfig | None = None) -> None:
    """
    Configure HTTP wrapper behavior.

    Args:
        config: HttpConfig instance, or None to reset to defaults.
    """
    global _config, _registry  # noqa: PLW0603
    _config = config
    # Reset registry so it picks up new config
    _registry = None


def _get_config() -> HttpConfig:
    """Get the global config, creating default if necessary."""
    global _config  # noqa: PLW0603
    if _config is None:
        _config = HttpConfig()
    return _config


class CircuitOpenError(Exception):
    """Raised when circuit breaker is open for a host."""

    def __init__(self, host: str, recovery_time: float) -> None:
        self.host = host
        self.recovery_time = recovery_time
        super().__init__(f"Circuit breaker open for {host}, recovery in {recovery_time:.1f}s")


@dataclass
class HostState:
    """Per-host state for connection pooling, rate limiting, and circuit breaker."""

    hostname: str
    # Session provides connection pooling - TCP connections are reused via urllib3
    session: requests.Session = field(default_factory=requests.Session)
    blocked_until: float = 0.0  # timestamp when rate limit expires
    consecutive_failures: int = 0
    circuit_open_until: float = 0.0  # timestamp when circuit breaker allows requests
    half_open: bool = False  # True when testing if host has recovered
    lock: threading.Lock = field(default_factory=threading.Lock)
    # Semaphore with 1 permit - used to serialize requests when rate-limited
    semaphore: threading.Semaphore = field(default_factory=lambda: threading.Semaphore(1))


class HostRegistry:
    """Registry managing per-host state for HTTP requests."""

    def __init__(
        self,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_recovery: float = 60.0,
    ) -> None:
        self._hosts: dict[str, HostState] = {}
        self._lock = threading.Lock()
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_recovery = circuit_breaker_recovery

    def get_state(self, hostname: str) -> HostState:
        """Get or create state for a hostname."""
        with self._lock:
            if hostname not in self._hosts:
                self._hosts[hostname] = HostState(hostname=hostname)
            return self._hosts[hostname]

    def acquire_slot(self, hostname: str, logger: logging.Logger | None = None) -> HostState:
        """
        Acquire a slot to make a request to the given host.

        Waits if the host is rate-limited, raises CircuitOpenError if circuit is open.
        Returns the HostState to use for the request.
        """
        state = self.get_state(hostname)

        with state.lock:
            now = time.time()

            # Check circuit breaker
            if state.circuit_open_until > now:
                raise CircuitOpenError(hostname, state.circuit_open_until - now)

            # Check if we're transitioning from open to half-open
            # This happens when the recovery time has passed but we had failures
            if state.consecutive_failures >= self.circuit_breaker_threshold and state.circuit_open_until <= now:
                if state.half_open:
                    # Already in half-open with a probe in flight - reject new requests
                    # (The semaphore will eventually serialize, but this gives immediate feedback)
                    raise CircuitOpenError(hostname, self.circuit_breaker_recovery)
                # Enter half-open mode - allow this one request as a probe
                state.half_open = True
                if logger:
                    logger.info(f"Circuit breaker half-open for {hostname}, allowing probe request")

            # Check rate limiting
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

    def record_success(self, hostname: str) -> None:
        """Record a successful request, resetting circuit breaker state."""
        state = self.get_state(hostname)
        with state.lock:
            state.consecutive_failures = 0
            state.circuit_open_until = 0.0
            state.half_open = False

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

    def record_failure(self, hostname: str) -> None:
        """Record a failed request, potentially tripping the circuit breaker."""
        state = self.get_state(hostname)
        with state.lock:
            state.consecutive_failures += 1

            # If in half-open mode, probe failed - immediately re-trip the circuit
            if state.half_open:
                state.circuit_open_until = time.time() + self.circuit_breaker_recovery
                state.half_open = False
            elif state.consecutive_failures >= self.circuit_breaker_threshold:
                state.circuit_open_until = time.time() + self.circuit_breaker_recovery


# Module-level singleton registry
_registry: HostRegistry | None = None


def _get_registry() -> HostRegistry:
    """Get the global HostRegistry, creating it if necessary."""
    global _registry  # noqa: PLW0603
    if _registry is None:
        config = _get_config()
        _registry = HostRegistry(
            circuit_breaker_threshold=config.circuit_breaker_threshold,
            circuit_breaker_recovery=config.circuit_breaker_recovery,
        )
    return _registry


def _reset_for_testing() -> None:
    """Reset the global registry and config. For testing only."""
    global _registry, _config  # noqa: PLW0603
    _registry = None
    _config = None


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


def get(  # noqa: PLR0913, PLR0912, PLR0915, C901
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
        - Rate limit handling with Retry-After support
        - Circuit breaker for repeated failures
        - Smart retry logic based on status code category

    Args:
        url (string): the url to get
        logger: a logging.Logger that info about the request should be logged to
        retries: how many times should the call be re-attempted if it fails. A maximum of retries+1 calls are made.
        backoff_in_seconds: passed to time.sleep between retries
        timeout: passed to requests.get. defaults to 30 seconds.
        status_handler: a Callable to call to validate the response.
            If the Callable raises and exception, the exception will be logged, and retried if any retries remain.
            If the Callable does not raise, the response will be returned, and the caller is responsible for any
            further validation.
            If no Callable is provided, `raise_for_status` is called on the response instead.
        user_agent: the User-Agent header value. If None or empty, no User-Agent header is set.
        **kwargs: additional args are passed to requests.get unchanged.
    Raises:
        If retries are exhausted, re-raises the exception from the last requests.get attempt.
        CircuitOpenError: If the circuit breaker is open for the target host.

    Example:
        http.get("http://example.com/some-url", self.logger, retries=3, backoff_in_seconds=30,
                 status_handler= lambda response: None if response.status_code in [200, 201, 405] else response.raise_for_status())

    """
    headers = kwargs.pop("headers", {})
    if user_agent:
        headers["User-Agent"] = user_agent

    hostname = _extract_hostname(url)
    registry = _get_registry()
    config = _get_config()

    last_exception: Exception | None = None
    retry_once_attempted = False  # Track if we've used our one retry for RETRY_ONCE codes

    for attempt in range(retries + 1):
        # Apply backoff delay if this is a retry (but not for rate-limit retries, which handle their own delay)
        if last_exception and not isinstance(last_exception, _RateLimitRetry):
            sleep_interval = backoff_sleep_interval(backoff_in_seconds, attempt - 1, max_value=max_interval)
            logger.warning(f"will retry in {int(sleep_interval)} seconds...")
            time.sleep(sleep_interval)

        # Reset rate limit marker
        if isinstance(last_exception, _RateLimitRetry):
            last_exception = None

        state = None
        try:
            # Acquire slot (handles rate limiting wait and circuit breaker check)
            state = registry.acquire_slot(hostname, logger)

            logger.debug(f"http GET {url} timeout={timeout} retries={retries} backoff={backoff_in_seconds}")
            response = state.session.get(url, timeout=timeout, headers=headers, **kwargs)

            # Classify status code for smart retry
            strategy = classify_status_code(response.status_code)

            # If a status_handler is provided, call it first for ALL responses.
            # If it doesn't raise, return the response (caller takes responsibility).
            # This allows callers to gracefully handle specific error codes (e.g., 403).
            if status_handler:
                try:
                    status_handler(response)
                    # status_handler didn't raise - return the response
                    if strategy == RetryStrategy.SUCCESS:
                        registry.record_success(hostname)
                    return response
                except Exception:
                    # status_handler raised - re-raise to trigger retry logic
                    raise

            if strategy == RetryStrategy.SUCCESS:
                # Success - validate response (no status_handler, so use raise_for_status)
                registry.record_success(hostname)
                response.raise_for_status()
                return response

            if strategy == RetryStrategy.RATE_LIMITED:
                if config.respect_retry_after:
                    # Check if we've exhausted retries - if so, fail now instead of waiting
                    if attempt >= retries:
                        logger.warning(f"Rate limited by {hostname}, no retries remaining")
                        registry.record_failure(hostname)
                        response.raise_for_status()

                    # Parse Retry-After and record rate limit
                    retry_after = parse_retry_after(response.headers.get("Retry-After"))
                    registry.record_rate_limit(hostname, retry_after)
                    wait_time = retry_after if retry_after is not None else DEFAULT_RATE_LIMIT_WAIT
                    wait_time = min(wait_time, MAX_RATE_LIMIT_WAIT)  # Cap to prevent DoS
                    logger.warning(f"Rate limited by {hostname}, will retry after {wait_time:.1f}s")
                    # Set marker to skip backoff delay on next iteration (acquire_slot handles the wait)
                    last_exception = _RateLimitRetry()
                    # Release slot before continuing so acquire_slot can re-acquire after wait
                    registry.release_slot(state)
                    state = None
                    continue
                # Treat as server error with backoff
                registry.record_failure(hostname)
                response.raise_for_status()

            elif strategy == RetryStrategy.RETRY_ONCE:
                # Client error - retry once if configured, then raise
                if config.retry_once_on_client_error and not retry_once_attempted:
                    retry_once_attempted = True
                    logger.warning(f"Client error {response.status_code}, will retry once")
                    response.raise_for_status()  # This raises HTTPError, caught below for retry
                else:
                    # Already retried once (or retry disabled), raise immediately without further retries
                    registry.record_failure(hostname)
                    # Wrap in _NoMoreRetries to escape the retry loop
                    try:
                        response.raise_for_status()
                    except requests.exceptions.HTTPError as e:
                        raise _NoMoreRetries(e) from e

            elif strategy == RetryStrategy.RETRY_WITH_BACKOFF:
                # Server error - use exponential backoff (handled by the loop)
                registry.record_failure(hostname)
                response.raise_for_status()

            else:  # NO_RETRY
                # Other error - don't retry
                registry.record_failure(hostname)
                response.raise_for_status()

        except CircuitOpenError:
            # Re-raise circuit breaker errors without retry
            raise
        except _NoMoreRetries as e:
            # Stop retrying and re-raise the original exception
            logger.error(f"last retry of GET {url} failed with {e.original}")
            raise e.original from None
        except requests.exceptions.HTTPError as e:
            last_exception = e
            # Note: record_failure is called in the strategy handling above, not here,
            # to avoid double-counting when raise_for_status() is called after record_failure()
            logger.warning(f"attempt {attempt + 1} of {retries + 1} failed: {e}")
        except Exception as e:
            last_exception = e
            # Record failure for unexpected exceptions
            registry.record_failure(hostname)
            # this is an unexpected exception type, so include the attempted request in case the
            # message from the unexpected exception doesn't.
            logger.warning(f"attempt {attempt + 1} of {retries + 1}: unexpected exception during GET {url}: {e}")
        finally:
            if state is not None:
                registry.release_slot(state)

    if last_exception:
        logger.error(f"last retry of GET {url} failed with {last_exception}")
        raise last_exception
    raise Exception("unreachable")


class _RateLimitRetry(Exception):
    """Internal marker exception for rate limit retries."""


class _NoMoreRetries(Exception):
    """Internal marker to stop retry loop and re-raise original exception."""

    def __init__(self, original: Exception) -> None:
        self.original = original
        super().__init__(str(original))


def backoff_sleep_interval(interval: int, attempt: int, max_value: None | int = None, jitter: bool = True) -> float:
    # this is an exponential backoff
    val = interval * 2**attempt
    if max_value and val > max_value:
        val = max_value
    if jitter:
        val += random.uniform(0, 1)  # noqa: S311
        # explanation of S311 disable: rng is not used cryptographically
    return val
