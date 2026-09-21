r"""Distil each source archive into one compact row per CVE, addressable by offset.

Why a scratch file and not a store
----------------------------------
Every source this provider reads is keyed by CVE: the OSV feed is one record
per CVE, the OpenVEX feed one document per CVE, and the frozen tracker snapshot
one file per CVE. Assembling what a release says about a CVE means holding all
three of them for that CVE at once, so the emit pass walks CVEs and not
releases.

Both archives are single-block xz streams whose members are not in path order.
That rules out two obvious shapes: reaching a member by name decompresses
everything before it, so a per-lookup `extractfile` is a full pass each time,
and a merge join over the two streams as they arrive is impossible because the
OSV record and the VEX document for one CVE sit at unrelated positions.
Extracting the JSON to disk would give the filesystem as an index, at 33 GiB
for the two feeds, which is worse than the problem it solves.

So each archive is streamed exactly once and each document reduced to the
fields the output needs, written here as `<cve>\t<json>` with the byte range of
the JSON kept in memory. There are tens of thousands of CVEs per feed, so the
index is small and the union of the two key sets is sorted in memory; no
external sort and no second store.

What is deliberately not carried
--------------------------------
`withdrawn`: nothing reads it. Canonical sets it to mark a record it will not
regenerate rather than to retract a finding, and the one class of real
retraction — the CVE program's own rejection — is read out of `details` here
and carried as a boolean, so the prose does not have to travel.

`details` itself, `references` and `modified`: an emitted record carries an
empty description and a link built from the CVE id, so none of the three has a
reader downstream of this.

A `fixed` VEX statement: the version on its product URL is the package's
current version in that pocket and not the version that fixed the CVE, so it
has nothing to state that the OSV record or the snapshot beside it does not
state better. It was already read nowhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:
    from collections.abc import Iterator

_SEPARATOR = b"\t"
_TERMINATOR = b"\n"


class RowStore:
    """One line per CVE in a scratch file, with an in-memory `cve -> (offset, length)` index.

    Written in one pass as the archive streams past and read back in CVE order
    afterwards, which is why the file is never sorted: the index is what makes
    the order of the lines irrelevant.

    The file is truncated on open, so a run always reads the rows it wrote and
    never a previous run's. It lives under the workspace input directory, which
    the provider keeps between runs, so a crashed run leaves the rows behind and
    the next one overwrites them.
    """

    def __init__(self, path: str):
        self.path = path
        self._offsets: dict[str, tuple[int, int]] = {}
        self._write_handle: Any = None
        self._read_handle: Any = None
        self._position = 0

    def __enter__(self) -> RowStore:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.close()
        self._offsets = {}
        self._position = 0
        self._write_handle = open(self.path, "wb")
        return self

    def __exit__(self, *_: object) -> None:
        if self._write_handle is not None:
            self._write_handle.close()
            self._write_handle = None

    def write(self, cve: str, payload: dict[str, Any]) -> None:
        """Append one CVE's row. A repeated CVE replaces the row written for it earlier."""
        if self._write_handle is None:
            raise RuntimeError("RowStore.write outside the writing context")
        key = cve.encode()
        body = orjson.dumps(payload)
        self._write_handle.write(key + _SEPARATOR + body + _TERMINATOR)
        self._offsets[cve] = (self._position + len(key) + len(_SEPARATOR), len(body))
        self._position += len(key) + len(_SEPARATOR) + len(body) + len(_TERMINATOR)

    def keys(self) -> set[str]:
        return set(self._offsets)

    def __len__(self) -> int:
        return len(self._offsets)

    def __contains__(self, cve: str) -> bool:
        return cve in self._offsets

    def get(self, cve: str) -> dict[str, Any] | None:
        """The row for one CVE, or None if the archive did not carry it."""
        location = self._offsets.get(cve)
        if location is None:
            return None
        if self._read_handle is None:
            if self._write_handle is not None:
                self._write_handle.flush()
            self._read_handle = open(self.path, "rb")  # noqa: SIM115
        offset, length = location
        self._read_handle.seek(offset)
        return orjson.loads(self._read_handle.read(length))

    def close(self) -> None:
        for name in ("_write_handle", "_read_handle"):
            handle = getattr(self, name)
            if handle is not None:
                handle.close()
                setattr(self, name, None)


@dataclass(frozen=True)
class OsvEntry:
    """One `affected[]` element, reduced to what a record made from it needs.

    `ecosystem` is the string the feed wrote rather than the canonical spelling
    of the release, because it is also the key the fix-date lookup and the USN
    overlay are indexed by: folding `Ubuntu:26.04` onto `Ubuntu:26.04:LTS` here
    would silently miss every date published under the pre-GA spelling.
    """

    ecosystem: str
    package: str
    purl: str
    fixed: tuple[str, ...]


@dataclass(frozen=True)
class OsvRow:
    """What one CVE's OSV record says, across every release it names."""

    cve: str
    published: str | None
    severity: list[dict[str, Any]]
    rejected: bool
    entries: tuple[OsvEntry, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "published": self.published,
            "severity": self.severity,
            "rejected": self.rejected,
            "entries": [[e.ecosystem, e.package, e.purl, list(e.fixed)] for e in self.entries],
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> OsvRow:
        return cls(
            cve=payload["cve"],
            published=payload.get("published"),
            severity=payload.get("severity") or [],
            rejected=bool(payload.get("rejected")),
            entries=tuple(OsvEntry(ecosystem=e[0], package=e[1], purl=e[2], fixed=tuple(e[3])) for e in payload.get("entries", [])),
        )


def _fixed_versions(affected: dict[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    for r in affected.get("ranges") or []:
        for event in r.get("events") or []:
            version = event.get("fixed")
            if version:
                out.append(version)
    return tuple(out)


def distil_osv(record: dict[str, Any], rejected: bool) -> OsvRow | None:
    """Reduce one OSV record to its row, or None when nothing could be emitted from it.

    A record with no upstream CVE alias returns None. Canonical's own id is
    internal and the emitted record is named by the upstream CVE, so a record
    without one has no name to be emitted under, no key to join the other two
    sources on, and no way for a rejection read out of it to be attributed.

    `rejected` is decided by the caller and carried as a boolean so that the
    prose it was read from does not have to travel with the row. It is a fact
    about the CVE rather than about any release it names, which is why it sits
    on the row and not on an entry.
    """
    upstream = record.get("upstream") or []
    if not upstream or not upstream[0]:
        return None

    entries: list[OsvEntry] = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not ecosystem or not name:
            continue
        entries.append(
            OsvEntry(
                ecosystem=ecosystem,
                package=name,
                purl=package.get("purl") or "",
                fixed=_fixed_versions(affected),
            ),
        )
    if not entries and not rejected:
        # nothing to say about any release, and no rejection to remember
        return None

    return OsvRow(
        cve=str(upstream[0]),
        published=record.get("published"),
        severity=record.get("severity") or [],
        rejected=rejected,
        entries=tuple(entries),
    )


def iter_tar_members(tar: Any, prefix: str) -> Iterator[tuple[str, bytes]]:
    """Yield (member name, bytes) for every regular `.json` file under `prefix`.

    Iterating the TarFile object itself is what keeps the read sequential; the
    archive is one xz block, so anything that seeks pays for a full
    decompression.
    """
    for member in tar:
        if not member.isfile():
            continue
        if not (member.name.startswith(prefix) and member.name.endswith(".json")):
            continue
        handle = tar.extractfile(member)
        if handle is None:
            continue
        yield member.name, handle.read()
