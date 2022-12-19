import errno
import logging
import os
import random
import shutil
import time


def retry_with_backoff(retries=10, backoff_in_seconds=1):
    def rwb(f):
        def wrapper(*args, **kwargs):
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


def silent_remove(path, tree=False):
    try:
        if tree:
            shutil.rmtree(path)
        else:
            os.remove(path)
    except OSError as e:
        # note: errno.ENOENT = no such file or directory
        if e.errno != errno.ENOENT:
            raise
