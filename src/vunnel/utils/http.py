from __future__ import annotations

import random
import time
from typing import TYPE_CHECKING, Any, Optional

import requests

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable

DEFAULT_TIMEOUT = 30


def get(  # noqa: PLR0913
    url: str,
    logger: logging.Logger,
    retries: int = 5,
    backoff_in_seconds: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
    status_handler: Optional[Callable[[requests.Response], None]] = None,  # noqa: UP007 - python 3.9
    max_interval: int = 600,
    **kwargs: Any,
) -> requests.Response:
    """
    Perform requests.get on the url with configurable retries. Retried failures are logged as warnings.

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
        **kwargs: additional args are passed to requests.get unchanged.
    Raises:
        If retries are exhausted, re-raises the exception from the last requests.get attempt.

    Example:
        http.get("http://example.com/some-url", self.logger, retries=3, backoff_in_seconds=30,
                 status_handler= lambda response: None if response.status_code in [200, 201, 405] else response.raise_for_status())

    """
    last_exception: Exception | None = None
    for attempt in range(retries + 1):
        if last_exception:
            sleep_interval = backoff_sleep_interval(backoff_in_seconds, attempt - 1, max_value=max_interval)
            logger.warning(f"will retry in {int(sleep_interval)} seconds...")
            time.sleep(sleep_interval)

        try:
            logger.debug(f"http GET {url} timeout={timeout} retries={retries} backoff={backoff_in_seconds}")
            response = requests.get(url, timeout=timeout, **kwargs)
            if status_handler:
                status_handler(response)
            else:
                response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            last_exception = e
            # HTTPError includes the attempted request, so don't include it redundantly here
            logger.warning(f"attempt {attempt + 1} of {retries + 1} failed: {e}")
        except Exception as e:
            last_exception = e
            # this is an unexpected exception type, so include the attempted request in case the
            # message from the unexpected exception doesn't.
            logger.warning(f"attempt {attempt + 1} of {retries + 1}: unexpected exception during GET {url}: {e}")
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
