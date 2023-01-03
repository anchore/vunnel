import logging
import os
import time
from dataclasses import asdict, dataclass
from types import TracebackType
from typing import Any

import orjson

from .schema import Schema
from .workspace import Workspace


@dataclass
class Envelope:
    schema: str
    identifier: str
    item: Any


class Writer:
    written: list[str]

    def __init__(  # noqa
        self,
        workspace: Workspace,
        logger: Any = None,
        skip_duplicates: bool = False,
        clear_results_before_writing: bool = False,
    ):
        self.workspace = workspace
        self.skip_duplicates = skip_duplicates
        self.clear_results_before_writing = clear_results_before_writing

        if not logger:
            logger = logging.getLogger("results-writer")
        self.logger = logger
        self.wrote = 0
        self.start = time.time()

    def __enter__(self) -> "Writer":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.logger.info(f"wrote {len(self)} entries")

    def __len__(self) -> int:
        return self.wrote

    def write(self, identifier: str, schema: Schema, payload: Any) -> None:
        self._clear_existing_results()

        envelope = Envelope(identifier=identifier, schema=schema.url, item=payload)

        filename = f"{identifier}.json"
        filepath = os.path.join(self.workspace.results_path, filename)

        # allow for nested directories controlled by the provider (for large sets of results)
        if os.sep in identifier:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

        if os.path.exists(filepath):
            if self.skip_duplicates and os.path.getmtime(filepath) >= self.start:
                self.logger.warning(f"{identifier!r} already written (skipping)")
                return
            self.logger.trace(f"overwriting existing file: {filepath!r}")

        with open(filepath, "wb") as f:
            self.logger.trace(f"writing record to {filepath!r}")
            f.write(orjson.dumps(asdict(envelope), f))  # type: ignore
            self.wrote += 1

    def _clear_existing_results(self) -> None:
        if len(self) == 0 and self.clear_results_before_writing:
            self.workspace.clear_results()
