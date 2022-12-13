import datetime
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any

import rfc3339
import xxhash

from vunnel import schema as schemaDef

STATE_FILENAME = "state.json"


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
    digests: list[str]
    modified: datetime.datetime


@dataclass(frozen=True)
class Input:
    files: list[FileState]
    timestamp: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(tz=datetime.timezone.utc))


@dataclass(frozen=True)
class Results:
    files: list[FileState]
    timestamp: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(tz=datetime.timezone.utc))


@dataclass(frozen=True)
class WorkspaceState:
    provider: str
    # the list of files should be:
    # - relative to the root
    # - be sorted by path
    urls: list[str]
    input: Input
    results: Results
    schema: schemaDef.Schema = field(default_factory=schemaDef.ProviderWorkspaceStateSchema)

    @staticmethod
    def from_fs(
        provider: str, input: str, results: str, urls: list[str]  # pylint: disable=redefined-builtin
    ) -> "WorkspaceState":
        return WorkspaceState(
            provider=provider,
            urls=urls,
            input=Input(files=file_state_listing(input)),
            results=Results(files=file_state_listing(results)),
        )

    def write(self, root: str) -> str:
        metadata_path = os.path.join(root, STATE_FILENAME)

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, cls=DTEncoder, indent=2)
        return metadata_path


def digest_path_with_hasher(path: str, hasher: Any, label: str) -> str:
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hasher.update(byte_block)
    return label + ":" + hasher.hexdigest()


def sha256_digest(path: str) -> str:
    return digest_path_with_hasher(path, hashlib.sha256(), "sha256")


def xxhash64_digest(path: str) -> str:
    return digest_path_with_hasher(path, xxhash.xxh64(), "xxh64")


def file_digests(path: str) -> list[str]:
    return [
        xxhash64_digest(path),
        sha256_digest(path),
    ]


def file_state_listing(path: str):
    listing = []
    for root, dirs, files in os.walk(path):  # pylint: disable=unused-variable
        for file in sorted(files):
            full_path = os.path.join(root, file)
            listing.append(
                FileState(
                    path=file,
                    digests=file_digests(full_path),
                    modified=datetime.datetime.fromtimestamp(os.path.getmtime(full_path)).astimezone(datetime.timezone.utc),
                )
            )
    return listing
