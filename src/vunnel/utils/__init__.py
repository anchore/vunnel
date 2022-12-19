import errno
import logging
import os
import random
import shutil
import time
from typing import Any, Callable


def retry_with_backoff(retries: int = 10, backoff_in_seconds: int = 1) -> Callable[[Any], Any]:
    def rwb(f: Callable[[Any], Any]) -> Callable[[Any], Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger = logging.getLogger("utils:retry-with-backoff")
            attempt = 0
            while attempt < retries:
                try:
                    return f(*args, **kwargs)
                except:  # noqa: E722
                    if attempt >= retries:
                        logger.exception(f"failed after {retries} retries")
                        raise

                sleep = backoff_in_seconds * 2**attempt + random.uniform(0, 1)  # nosec
                logger.debug(f"retrying in {sleep} seconds (attempt {attempt+1} of {retries})")
                time.sleep(sleep)
                attempt += 1

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
