from __future__ import annotations

import datetime
import errno
import json
import logging
import os
import random
import shutil
import time
from typing import TYPE_CHECKING, Any

import rfc3339

if TYPE_CHECKING:
    from collections.abc import Callable


def retry_with_backoff(retries: int = 5, backoff_in_seconds: int = 3) -> Callable[[Any], Any]:
    def rwb(f: Callable[[Any], Any]) -> Callable[[Any], Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger = logging.getLogger("utils:retry-with-backoff")
            attempt = 0
            while attempt < retries:
                try:
                    return f(*args, **kwargs)
                except KeyboardInterrupt:
                    logger.warning("keyboard interrupt, cancelling request...")
                    raise
                except:  # noqa: E722
                    if attempt >= retries:
                        logger.exception(f"failed after {retries} retries")
                        raise

                sleep = backoff_in_seconds * 2**attempt + random.uniform(0, 1)  # nosec
                logger.warning(f"{f} failed. Retrying in {int(sleep)} seconds (attempt {attempt+1} of {retries})")
                time.sleep(sleep)
                attempt += 1

            raise RuntimeError("max retries reached, failed to execute function")

        return wrapper

    return rwb


def silent_remove(path: str, tree: bool = False) -> None:
    try:
        if tree:
            shutil.rmtree(path)
        else:
            os.remove(path)
    except OSError as e:
        # note: errno.ENOENT = no such file or directory
        if e.errno != errno.ENOENT:
            raise


class DTEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        # if passed in object is datetime object
        # convert it to a string
        if isinstance(o, datetime.datetime):
            return rfc3339.rfc3339(o)
        # otherwise use the default behavior
        return json.JSONEncoder.default(self, o)
