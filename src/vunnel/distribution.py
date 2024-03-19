from __future__ import annotations

import os
import datetime
import json
from dataclasses import dataclass
from urllib.parse import urlparse
from mashumaro.mixins.dict import DataClassDictMixin

import iso8601


DB_SUFFIXES = {".tar.gz", ".tar.zst"}


@dataclass
class ListingEntry(DataClassDictMixin):
    built: str
    version: int
    url: str
    # e.g. sha256:1234567890abcdef1234567890abcdef
    archive_checksum: str
    # e.g. xxhash64:1234567890abcdef
    results_checksum: str

    def basename(self) -> str:
        basename = os.path.basename(urlparse(self.url, allow_fragments=False).path)
        if not _has_suffix(basename, suffixes=DB_SUFFIXES):
            msg = f"entry url is not a db archive: {basename}"
            raise RuntimeError(msg)

        return basename

    def age_in_days(self, now: datetime.datetime | None = None) -> int:
        if not now:
            now = datetime.datetime.now(tz=datetime.timezone.utc)
        return (now - iso8601.parse_date(self.built)).days


@dataclass
class ListingDocument(DataClassDictMixin):
    available: dict[int, list[ListingEntry]]

    # @classmethod
    # def from_json(cls, contents: str) -> ListingDocument:
    #     return cls.from_dict(json.loads(contents))

    def latest_entry(self, schema_version: int) -> ListingEntry | None:
        if schema_version not in self.available:
            return None
        
        if not self.available[schema_version]:
            return None

        return self.available[schema_version][0]

    

def _has_suffix(el: str, suffixes: set[str] | None) -> bool:
    if not suffixes:
        return True
    return any(el.endswith(s) for s in suffixes)
