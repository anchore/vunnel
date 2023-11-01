import logging
import time
from typing import Any

import requests

DEFAULT_TIMEOUT = 30


def get(
    url: str,
    logger: logging.Logger,
    retries: int = 5,
    backoff_in_seconds: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    logger.debug(f"http GET {url}")
    last_exception: Exception | None = None
    for attempt in range(retries + 1):
        if last_exception:
            time.sleep(backoff_in_seconds)
        try:
            response = requests.get(url, timeout=timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            last_exception = e
            will_retry = ""
            if attempt < retries:
                will_retry = f" (will retry in {backoff_in_seconds} seconds) "
            # HTTPError includes the attempted request, so don't include it redundantly here
            logger.warning(f"attempt {attempt + 1} of {retries} failed:{will_retry}{e}")
        except Exception as e:
            last_exception = e
            will_retry = ""
            if attempt < retries:
                will_retry = f" (will retry in {backoff_in_seconds} seconds) "
            # this is an unexpected exception type, so include the attempted request in case the
            # message from the unexpected exception doesn't.
            logger.warning(f"attempt {attempt + 1} of {retries}{will_retry}: unexpected exception during GET {url}: {e}")
    if last_exception:
        logger.error(f"last retry of GET {url} failed with {last_exception}")
        raise last_exception
    raise Exception("unreachable")
