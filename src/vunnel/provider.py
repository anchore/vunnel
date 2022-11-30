import abc
import datetime
import hashlib
import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass

import rfc3339

METADATA_FILENAME = "metadata.json"


class DTEncoder(json.JSONEncoder):
    def default(self, o):
        # if passed in object is datetime object
        # convert it to a string
        if isinstance(o, datetime.datetime):
            return rfc3339.rfc3339(o)
        # otherwise use the default behavior
        return json.JSONEncoder.default(self, o)


@dataclass(frozen=True)
class FileState:
    path: str
    digest: str
    # timestamp: datetime.datetime


@dataclass(frozen=True)
class State:
    root: str
    # the list of files should be:
    # - relative to the root
    # - be sorted by path
    urls: list[str]
    workspace: list[FileState]
    results: list[FileState]


class Provider(abc.ABC):
    def __init__(self, root: str):
        self._root = root
        self.logger = logging.getLogger(self.name)
        self.urls = []

    @property
    @abc.abstractstaticmethod
    def name():
        pass

    @abc.abstractmethod
    def update(self):
        """Populates the input directory from external sources, processes the data, places results into the output directory."""

    def populate(self):
        self.logger.info(f"using {self.workspace} as workspace")
        self.clear_results()
        self.create_workspace()
        urls = self.update()
        self._catalog_workspace(urls=urls)

    def create_workspace(self):
        if not os.path.exists(self.workspace):
            self.logger.debug(f"creating workspace for {self.name!r}")
            os.makedirs(self.workspace)
        else:
            self.logger.debug(f"using existing workspace for {self.name!r}")
        if not os.path.exists(self.results):
            os.makedirs(self.results)

    def clear(self):
        self.clear_workspace()
        self.clear_results()

    def clear_results(self):
        if os.path.exists(self.results):
            self.logger.debug("clearing existing results")
            shutil.rmtree(self.results)

    def clear_workspace(self):
        if os.path.exists(self.workspace):
            self.logger.debug("clearing existing workspace")
            shutil.rmtree(self.workspace)

    def _catalog_workspace(self, urls: list[str]):
        metadata_path = os.path.join(self.root, METADATA_FILENAME)

        state = State(root=self.root, urls=urls, workspace=file_listing(self.workspace), results=file_listing(self.results))

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, cls=DTEncoder, indent=2)

        self.logger.debug(msg=f"wrote workspace state to {metadata_path}")

    @property
    def root(self):
        return f"{self._root}/{self.name}"

    @property
    def workspace(self):
        return f"{self.root}/input"

    @property
    def results(self):
        return f"{self.root}/results"

    def __repr__(self):
        extra = []
        prefix = ""
        if getattr(self, "config"):
            extra.append(f"config={self.config}")  # pylint: disable=no-member
        if extra:
            prefix = ", "
        return f"Provider(name={self.name}, workspace={self.workspace}{prefix}{', '.join(extra)})"


def file_digest(path: str):
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return "sha256:" + sha256_hash.hexdigest()


def file_listing(path: str):
    listing = []
    for root, dirs, files in os.walk(path):  # pylint: disable=unused-variable
        for file in files:
            full_path = os.path.join(root, file)
            listing.append(
                FileState(
                    path=file,
                    digest=file_digest(full_path),
                    # timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(full_path))
                )
            )
    return listing
