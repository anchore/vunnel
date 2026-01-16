from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

import iso8601
from mashumaro.mixins.dict import DataClassDictMixin

from vunnel import schema as schema_def

DB_SUFFIXES = {".tar.gz", ".tar.zst"}


@dataclass
class ListingEntry(DataClassDictMixin):
    # the date this archive was built relative to the data enclosed in the archive
    built: str

    # the URL where the vunnel provider archive is located
    url: str

    # the digest of the archive referenced at the URL.
    # Note: all checksums are labeled with "algorithm:value" ( e.g. sha256:1234567890abcdef1234567890abcdef)
    distribution_checksum: str

    # the digest of the checksums file within the archive referenced at the URL
    # Note: all checksums are labeled with "algorithm:value" ( e.g. xxhash64:1234567890abcdef)
    enclosed_checksum: str

    # the provider distribution version this archive was built with (different than the provider version)
    distribution_version: int = 1

    def basename(self) -> str:
        basename = os.path.basename(urlparse(self.url, allow_fragments=False).path)
        if not _has_suffix(basename, suffixes=DB_SUFFIXES):
            msg = f"entry url is not a db archive: {basename}"
            raise RuntimeError(msg)

        return basename

    def age_in_days(self, now: datetime.datetime | None = None) -> int:
        if not now:
            now = datetime.datetime.now(tz=datetime.UTC)
        return (now - iso8601.parse_date(self.built)).days


@dataclass
class ListingDocument(DataClassDictMixin):
    # mapping of provider versions to a list of ListingEntry objects denoting archives available for download
    available: dict[int, list[ListingEntry]]

    # the provider name this document is associated with
    provider: str

    # the schema information for this document
    schema: schema_def.Schema = field(default_factory=schema_def.ProviderListingSchema)

    @classmethod
    def new(cls, provider: str) -> ListingDocument:
        return cls(available={}, provider=provider)

    def latest_entry(self, schema_version: int) -> ListingEntry | None:
        if schema_version not in self.available:
            return None

        if not self.available[schema_version]:
            return None

        return self.available[schema_version][0]

    def add(self, entry: ListingEntry) -> None:
        if not self.available.get(entry.distribution_version):
            self.available[entry.distribution_version] = []

        self.available[entry.distribution_version].append(entry)

        # keep listing entries sorted by date (rfc3339 formatted entries, which iso8601 is a superset of)
        self.available[entry.distribution_version].sort(
            key=lambda x: iso8601.parse_date(x.built),
            reverse=True,
        )


def _has_suffix(el: str, suffixes: set[str] | None) -> bool:
    if not suffixes:
        return True
    return any(el.endswith(s) for s in suffixes)
