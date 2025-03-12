from __future__ import annotations

import datetime  # noqa: TC003
import logging
import os
import shutil
import sqlite3
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Optional

import orjson
import xxhash
from mashumaro.mixins.dict import DataClassDictMixin

from vunnel import schema as schema_def
from vunnel import utils
from vunnel.utils import hasher

if TYPE_CHECKING:
    import types
    from collections.abc import Generator

METADATA_FILENAME = "metadata.json"
CHECKSUM_LISTING_FILENAME = "checksums"


@dataclass
class File:
    digest: str
    path: str
    algorithm: str = "xxh64"


@dataclass
class State(DataClassDictMixin):
    provider: str
    urls: list[str]
    store: str
    timestamp: datetime.datetime
    version: int = 1
    distribution_version: int = 1
    processor: str | None = None
    listing: Optional[File] = None  # noqa:UP007  # why use Optional? mashumaro does not support this on python 3.9
    schema: schema_def.Schema = field(default_factory=schema_def.ProviderStateSchema)
    stale: bool = False

    def __post_init__(self) -> None:
        if not self.processor:
            metadata: types.ModuleType
            package_name = "vunnel"
            version = "dev"
            try:
                from importlib import metadata
            except ImportError:
                # Python < 3.8
                import importlib_metadata as metadata

            try:
                if not metadata:
                    raise metadata.PackageNotFoundError
                version = metadata.version(package_name)
            except metadata.PackageNotFoundError:
                version = "unknown"

            self.processor = f"{package_name}@{version}"

    @staticmethod
    def read(root: str) -> State:
        metadata_path = os.path.join(root, METADATA_FILENAME)
        with open(metadata_path, encoding="utf-8") as f:
            return State.from_dict(orjson.loads(f.read()))

    def write(self, root: str, results: str, update_listing: bool = True) -> str:
        metadata_path = os.path.join(root, METADATA_FILENAME)

        if update_listing:
            listing_path = os.path.join(root, CHECKSUM_LISTING_FILENAME)
            if self.listing:
                listing_path = os.path.join(root, self.listing.path)

            if os.path.exists(listing_path):
                os.remove(listing_path)

            # why not include the file listing in the metadata file?
            # because in some cases there is a lot of data and it's easier to stream
            # the results to a tab-delimited file than include in the metadata file
            self.listing = File(
                digest=write_file_listing(listing_path, results),
                algorithm="xxh64",
                path=os.path.basename(listing_path),  # may have been overridden, keep value
            )

        with open(metadata_path, "wb") as f:
            f.write(orjson.dumps(asdict(self), option=orjson.OPT_INDENT_2))

        return metadata_path

    def result_files(self, root: str) -> Generator[File, File, None]:
        if self.listing:
            full_path = os.path.join(root, self.listing.path)
            with open(full_path) as f:
                for digest, filepath in (line.split() for line in f.readlines()):
                    yield File(digest=digest, path=filepath, algorithm=self.listing.algorithm)

    def result_count(self, root: str) -> int:
        count = 0
        if self.listing:
            full_path = os.path.join(root, self.listing.path)
            with open(full_path) as f:
                for _digest, filepath in (line.split() for line in f.readlines()):
                    if filepath.endswith(".db"):
                        # open up the sqlite db and count the records in the "results" table
                        with sqlite3.connect(os.path.join(root, filepath)) as db:
                            count += db.execute("SELECT COUNT(*) FROM results").fetchone()[0]
                    else:
                        count += 1

        return count


class Workspace:
    def __init__(self, root: str, name: str, create: bool = False, logger: logging.Logger | None = None):
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self._root = root
        self.name = name

        if create:
            self.create()

    @property
    def path(self) -> str:
        return os.path.join(self._root, self.name)

    @property
    def results_path(self) -> str:
        return os.path.join(self.path, "results")

    @property
    def metadata_path(self) -> str:
        return os.path.join(self.path, METADATA_FILENAME)

    @property
    def checksums_path(self) -> str:
        return os.path.join(self.path, CHECKSUM_LISTING_FILENAME)

    @property
    def input_path(self) -> str:
        return os.path.join(self.path, "input")

    def create(self) -> None:
        if not os.path.exists(self.input_path):
            self.logger.debug(f"creating input workspace {self.input_path!r}")
            os.makedirs(self.input_path)
        else:
            self.logger.debug(f"using existing input workspace {self.input_path!r}")

        if not os.path.exists(self.results_path):
            self.logger.debug(f"creating results workspace {self.results_path!r}")
            os.makedirs(self.results_path)
        else:
            self.logger.debug(f"using existing results workspace {self.results_path!r}")

    def clear(self) -> None:
        self.clear_input()
        self.clear_results()
        self._clear_metadata()

    def _clear_metadata(self) -> None:
        utils.silent_remove(os.path.join(self.path, METADATA_FILENAME))
        utils.silent_remove(os.path.join(self.path, CHECKSUM_LISTING_FILENAME))

    def clear_results(self, recreate_results_dir: bool = True) -> None:
        if os.path.exists(self.results_path):
            self.logger.debug("clearing existing results")
            shutil.rmtree(self.results_path)
            if recreate_results_dir:
                os.makedirs(self.results_path, exist_ok=True)

        try:
            current_state = State.read(root=self.path)
            current_listing = None
            if current_state.listing:
                current_listing = current_state.listing.path
            current_state.listing = None
            current_state.write(self.path, self.results_path)
            if current_listing:
                utils.silent_remove(current_listing)
        except FileNotFoundError:
            pass

    def clear_input(self) -> None:
        if os.path.exists(self.input_path):
            self.logger.debug("clearing existing input")
            shutil.rmtree(self.input_path)
            os.makedirs(self.input_path, exist_ok=True)

    def record_state(  # noqa: PLR0913
        self,
        version: int,
        distribution_version: int,
        timestamp: datetime.datetime,
        urls: list[str],
        store: str,
        stale: bool = False,
    ) -> None:
        try:
            current_state = State.read(root=self.path)
        except FileNotFoundError:
            current_state = None

        if current_state:
            if not urls:
                urls = current_state.urls
            if not timestamp:
                timestamp = current_state.timestamp

        self.logger.info("recording workspace state")

        state = State(
            provider=self.name,
            version=version,
            distribution_version=distribution_version,
            urls=urls,
            store=store,
            timestamp=timestamp,
            stale=stale,
        )
        metadata_path = state.write(self.path, self.results_path)

        self.logger.debug(f"wrote workspace state to {metadata_path}")

    def state(self) -> State:
        return State.read(self.path)

    def validate_checksums(self) -> None:
        state = State.read(self.path)
        if not state.listing:
            raise RuntimeError("no file listing found in workspace state")

        full_path = os.path.join(self.path, state.listing.path)

        # ensure the checksums file itself is not modified
        if state.listing.digest != hasher.Method.XXH64.digest(full_path, label=False):
            raise RuntimeError(f"file {full_path!r} has been modified")

        # validate the checksums in the listing file
        with open(full_path) as f:
            for line in f.readlines():
                digest, path = line.split()
                full_path = os.path.join(self.path, path)
                if not os.path.exists(full_path):
                    raise RuntimeError(f"file {full_path!r} does not exist")

                if digest != hasher.Method.XXH64.digest(full_path, label=False):
                    raise RuntimeError(f"file {full_path!r} has been modified")

    def replace_results(self, temp_workspace: Workspace) -> None:
        self.logger.info(f"replacing results in {self.path!r} with results from {temp_workspace.path!r}")
        self.clear_results(recreate_results_dir=False)
        shutil.move(temp_workspace.results_path, self.path)
        self._clear_metadata()
        shutil.move(temp_workspace.metadata_path, self.metadata_path)
        shutil.move(temp_workspace.checksums_path, self.checksums_path)
        state = self.state()
        state.stale = True
        self.record_state(state.version, state.distribution_version, state.timestamp, state.urls, state.store, True)


def write_file_listing(output_file: str, path: str) -> str:
    listing_hasher = xxhash.xxh64()

    with open(output_file, "w", encoding="utf-8") as f:
        for root, dirs, files in os.walk(path):
            dirs.sort()  # sort the existing list that os.walk generator continues to reference
            for file in sorted(files):
                full_path = os.path.join(root, file)
                path_relative_to_results = os.path.relpath(full_path, path)
                path_relative_to_workspace = os.path.join(os.path.basename(path), path_relative_to_results)

                contents = f"{hasher.Method.XXH64.digest(full_path, label=False)}  {path_relative_to_workspace}\n"
                listing_hasher.update(contents.encode("utf-8"))

                f.write(contents)

    return listing_hasher.hexdigest()
