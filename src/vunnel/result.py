import collections
import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass
from typing import Any

from .schema import Schema


@dataclass
class Envelope:
    schema: str
    items: list[Any]


@dataclass
class Entry:
    identifier: str
    schema: str
    payload: Any


class Writer:
    state: dict[str, Entry]
    written: list[str]
    batch: int

    def __init__(  # noqa
        self,
        prefix: str,
        result_dir: str,
        batch_size: int = 100,
        logger: Any = None,
        skip_duplicates: bool = False,
        clear_results_before_writing: bool = False,
    ):
        self.prefix = prefix
        self.result_dir = result_dir
        self.batch_size = batch_size
        self.skip_duplicates = skip_duplicates
        self.clear_results_before_writing = clear_results_before_writing
        self.state = collections.defaultdict(list)

        if not logger:
            logger = logging.getLogger("results-writer")
        self.logger = logger
        self.written = []
        self.batch = 0

    def __enter__(self):
        return self

    def __exit__(self, ty, value, traceback):
        self._write_remaining()
        self.logger.info(f"wrote {len(self)} entries")

    def __len__(self):
        return len(self.written)

    def write(self, identifier: str, schema: Schema, payload: Any):
        if not self.skip_duplicates and identifier in self.written:
            self.logger.warning(f"{identifier!r} already written (skipping)")
            return

        # self.logger.trace(f"queued {identifier!r} for writing")

        entry = Entry(identifier=identifier, schema=schema.url, payload=payload)

        self.state[entry.schema].append(entry)

        for entries in self.state.values():
            if len(entries) >= self.batch_size:
                self._write_batch()

    def _write_batch(self):
        for schema, entries in self.state.items():
            batch, self.state[schema] = entries[: self.batch_size], entries[self.batch_size :]  # noqa: E203
            self._write_entries(schema, batch)

    def _write_remaining(self):
        for schema, entries in self.state.items():
            self._write_entries(schema, entries)
        self.state.clear()

    def _write_entries(self, schema: str, entries: list[Entry]):
        self._clear_existing_results()

        if len(entries) == 0:
            return

        envelope = Envelope(schema=schema, items=[entry.payload for entry in entries])
        identifiers = [entry.identifier for entry in entries]
        filename = f"{self.prefix}-{self.batch:05}.json"
        filepath = os.path.join(self.result_dir, filename)

        if os.path.exists(filepath):
            self.logger.trace(f"overwriting existing file: {filepath!r}")

        with open(filepath, "w", encoding="utf-8") as f:
            self.logger.trace(f"writing {len(entries)} entries to {filepath!r}")
            payload = asdict(envelope)
            json.dump(payload, f, indent=1)
            self.written.extend(identifiers)

        self.batch += 1

    def _clear_existing_results(self):
        if len(self) == 0 and self.clear_results_before_writing:
            self.logger.debug("clearing existing results")
            shutil.rmtree(self.result_dir)
            os.makedirs(self.result_dir)
