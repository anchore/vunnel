import logging
import random
import time
from dataclasses import fields


def dataclass_from_dict(cls, d):
    try:
        fieldtypes = {f.name: f.type for f in fields(cls)}
        return cls(**{f: dataclass_from_dict(fieldtypes[f], d[f]) for f in d})
    except TypeError:
        pass
    return d


def retry_with_backoff(retries=10, backoff_in_seconds=1):
    def rwb(f):
        def wrapper(*args, **kwargs):
            logger = logging.getLogger("utils:retry-with-backoff")
            attempt = 0
            while attempt < retries:
                try:
                    return f(*args, **kwargs)
                except:  # pylint: disable=bare-except
                    if attempt >= retries:
                        logger.exception(f"failed after {retries} retries")
                        raise

                sleep = backoff_in_seconds * 2**attempt + random.uniform(0, 1)
                logger.debug(f"retrying in {sleep} seconds (attempt {attempt+1} of {retries})")
                time.sleep(sleep)
                attempt += 1

        return wrapper

    return rwb
