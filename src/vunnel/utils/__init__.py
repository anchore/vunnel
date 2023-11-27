from __future__ import annotations

import errno
import logging
import os
import random
import shutil
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


def retry_with_backoff(retries: int = 5, backoff_in_seconds: int = 3) -> Callable[[Any], Any]:
    def rwb(f: Callable[[Any], Any]) -> Callable[[Any], Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger = logging.getLogger("utils:retry-with-backoff")
            attempt = 0
            while attempt < retries:
                err = None
                try:
                    return f(*args, **kwargs)
                except KeyboardInterrupt:
                    logger.warning("keyboard interrupt, cancelling request...")
                    raise
                except Exception as e:
                    err = e
                    if attempt >= retries:
                        logger.exception(f"failed after {retries} retries")
                        raise

                # explanation of S311 disable: random number is not used for cryptography
                sleep = backoff_in_seconds * 2**attempt + random.uniform(0, 1)  # noqa: S311
                logger.warning(f"{f} failed with {err}. Retrying in {int(sleep)} seconds (attempt {attempt+1} of {retries})")
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
