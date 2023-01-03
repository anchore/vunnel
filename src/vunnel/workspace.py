import datetime
import logging
import os
import shutil
from dataclasses import asdict, dataclass, field
from typing import Any, Generator

import orjson
import xxhash
from dataclass_wizard import fromdict

from vunnel import schema as schemaDef

METADATA_FILENAME = "metadata.json"
CHECKSUM_LISTING_FILENAME = "checksums"


@dataclass
class File:
    digest: str
    path: str
    algorithm: str = "xxh64"


@dataclass
class State:
    provider: str
    urls: list[str]
    listing: File | None = None
    timestamp: datetime.datetime | None = field(default_factory=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    schema: schemaDef.Schema = field(default_factory=schemaDef.ProviderStateSchema)

    @staticmethod
    def read(root: str) -> "State":
        metadata_path = os.path.join(root, METADATA_FILENAME)
        with open(metadata_path, encoding="utf-8") as f:
            return fromdict(
                State,
                orjson.loads(f.read()),
            )

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
            f.write(orjson.dumps(asdict(self), f))  # type: ignore

        return metadata_path

    def result_files(self) -> Generator[File, File, None]:
        if self.listing:
            with open(self.listing.path) as f:
                for digest, filepath in (line.split() for line in f.readlines()):
                    yield File(digest=digest, path=filepath, algorithm=self.listing.algorithm)


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
    def scratch_path(self) -> str:
        return os.path.join(self.path, "scratch")

    @property
    def results_path(self) -> str:
        return os.path.join(self.path, "results")

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

        os.makedirs(self.scratch_path, exist_ok=True)

    def clear(self) -> None:
        self.clear_input()
        self.clear_results()
        self.clear_scratch()

    def clear_scratch(self) -> None:
        shutil.rmtree(self.results_path, ignore_errors=True)
        os.makedirs(self.results_path, exist_ok=True)

    def clear_results(self) -> None:
        if os.path.exists(self.results_path):
            self.logger.debug("clearing existing results")
            shutil.rmtree(self.results_path)
            os.makedirs(self.results_path, exist_ok=True)

        try:
            current_state = State.read(root=self.path)
            current_state.listing
            current_state.write(self.path, self.results_path)
        except FileNotFoundError:
            pass

    def clear_input(self) -> None:
        if os.path.exists(self.input_path):
            self.logger.debug("clearing existing input")
            shutil.rmtree(self.input_path)
            os.makedirs(self.input_path, exist_ok=True)

    def record_state(self, urls: list[str]) -> None:
        if not urls:
            try:
                current_state = State.read(root=self.path)
                urls = current_state.urls
            except FileNotFoundError:
                urls = []

        self.logger.info("recording workspace state")

        state = State(provider=self.name, urls=urls)
        metadata_path = state.write(self.path, self.results_path)

        self.logger.debug(f"wrote workspace state to {metadata_path}")

    def state(self) -> State | None:
        return State.read(self.path)


def digest_path_with_hasher(path: str, hasher: Any, label: str | None, size: int = 65536) -> str:
    with open(path, "rb") as f:
        while b := f.read(size):
            hasher.update(b)

    if label:
        return label + ":" + hasher.hexdigest()
    return hasher.hexdigest()


# def sha256_digest(path: str, label: bool = True) -> str:
#     return digest_path_with_hasher(path, hashlib.sha256(), "sha256" if label else None)


def xxhash64_digest(path: str, label: bool = True) -> str:
    return digest_path_with_hasher(path, xxhash.xxh64(), "xxh64" if label else None)


def write_file_listing(output_file: str, path: str) -> str:
    listing_hasher = xxhash.xxh64()

    with open(output_file, "w", encoding="utf-8") as f:
        for root, dirs, files in os.walk(path):  # noqa
            dirs.sort()  # sort the existing list that os.walk generator continues to reference
            for file in sorted(files):
                full_path = os.path.join(root, file)
                path_relative_to_results = os.path.relpath(full_path, path)
                path_relative_to_workspace = os.path.join(os.path.basename(path), path_relative_to_results)

                contents = f"{xxhash64_digest(full_path, label=False)}  {path_relative_to_workspace}\n"
                listing_hasher.update(contents.encode("utf-8"))

                f.write(contents)

    return listing_hasher.hexdigest()
