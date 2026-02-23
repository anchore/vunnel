from __future__ import annotations

import errno
import logging
import os
import random
import shutil
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


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
                logger.warning(f"{f} failed with {err}. Retrying in {int(sleep)} seconds (attempt {attempt + 1} of {retries})")
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


def move_dir(src: str, dst: str) -> None:
    """Move a directory from src to dst, ensuring the destination directory is empty."""
    if os.path.exists(dst):
        silent_remove(dst, tree=True)
    shutil.move(src, dst)


@contextmanager
def timer(name: str, logger: logging.Logger) -> Iterator[None]:
    # Iterator[None] because @contextmanager transforms a generator into a context manager,
    # but type checkers see the raw generator function
    start_time = time.time()
    try:
        yield
    finally:
        elapsed_time = time.time() - start_time
        logger.info(f"updating {name} took {elapsed_time:.2f} seconds")


class PerfTimer:
    """context manager for timing code blocks in milliseconds.

    Example:
        with PerfTimer() as t:
            do_something()
        print(f"elapsed: {t.ms:.2f}ms")

        # or for accumulation:
        total_ms = 0.0
        with PerfTimer() as t:
            do_something()
        total_ms += t.ms
    """

    __slots__ = ("_start", "ms")

    def __enter__(self) -> PerfTimer:
        self._start = time.perf_counter()
        self.ms = 0.0
        return self

    def __exit__(self, *args: object) -> None:
        self.ms = (time.perf_counter() - self._start) * 1000
