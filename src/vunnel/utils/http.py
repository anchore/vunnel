import logging
import random
import time
from collections.abc import Callable
from typing import Any, Optional

import requests

DEFAULT_TIMEOUT = 30


def get(  # noqa: PLR0913
    url: str,
    logger: logging.Logger,
    retries: int = 5,
    backoff_in_seconds: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
    status_handler: Optional[Callable[[requests.Response], None]] = None,
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
    logger.debug(f"http GET {url}")
    last_exception: Exception | None = None
    sleep_interval = backoff_in_seconds
    for attempt in range(retries + 1):
        if last_exception:
            time.sleep(sleep_interval)
            sleep_interval = backoff_in_seconds * 2**attempt + random.uniform(0, 1)  # noqa: S311
            # explanation of S311 disable: rng is not used cryptographically
        try:
            response = requests.get(url, timeout=timeout, **kwargs)
            if status_handler:
                status_handler(response)
            else:
                response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            last_exception = e
            will_retry = ""
            if attempt < retries:
                will_retry = f" (will retry in {int(backoff_in_seconds)} seconds) "
            # HTTPError includes the attempted request, so don't include it redundantly here
            logger.warning(f"attempt {attempt + 1} of {retries + 1} failed:{will_retry}{e}")
        except Exception as e:
            last_exception = e
            will_retry = ""
            if attempt < retries:
                will_retry = f" (will retry in {int(sleep_interval)} seconds) "
            # this is an unexpected exception type, so include the attempted request in case the
            # message from the unexpected exception doesn't.
            logger.warning(f"attempt {attempt + 1} of {retries + 1}{will_retry}: unexpected exception during GET {url}: {e}")
    if last_exception:
        logger.error(f"last retry of GET {url} failed with {last_exception}")
        raise last_exception
    raise Exception("unreachable")
