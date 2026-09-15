"""Ubuntu's published release calendar, fetched each run.

Canonical's OSV and VEX feeds carry no signal that a release has died. A few
days to a few weeks after a release reaches end of life, its records are swept
out of both feeds and replaced by a husk of never-regenerated stragglers, and
nothing in the data distinguishes that husk from a release that is genuinely
down to a handful of open issues. The date is the signal: no sweep has ever
landed before midnight UTC on the release's published `eol` date.

The dates are read from `ubuntu.csv` as shipped by the `distro-info-data`
package, which is the source `distro-info(1)` itself reads. It is fetched every
run rather than vendored because the dates change: the changelog records at
least a dozen end-of-life corrections, including one made to a live release two
days before it was due to expire. A vendored copy that nobody refreshes is the
one shape that can be silently wrong for years.

Only the `eol` column is ever read. The `eol-server`, `eol-esm` and
`eol-legacy` columns describe support tiers that keep publishing long after the
base release stops, and an LTS release is never frozen at any of them.
"""

from __future__ import annotations

import csv
import datetime
import io
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable

# The Debian salsa mirror of distro-info-data. Launchpad publishes the same file
# but did not answer when this was written.
CALENDAR_URL = "https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv"

SUBDIR = "distro-info"
FILENAME = "ubuntu.csv"

# The `version` column reads "26.04 LTS" for a long-term-support release and
# "25.10" for an interim one. That suffix is the published statement of which
# releases never expire from this provider's point of view.
_LTS_SUFFIX = " LTS"

# How far ahead of an interim release's end-of-life instant to start saying so
# in the log. Nothing reads this but the log line; it exists so an operator
# sees a freeze coming rather than discovering it after the fact.
WARNING_WINDOW = datetime.timedelta(days=14)

_REQUIRED_COLUMNS = ("version", "series", "eol")


class CalendarError(Exception):
    """The release calendar could not be obtained or could not be read."""


@dataclass(frozen=True)
class Release:
    """One row of the calendar."""

    version: str
    series: str
    lts: bool
    eol: datetime.date | None

    @property
    def eol_instant(self) -> datetime.datetime | None:
        """Midnight UTC on the end-of-life date, the instant the release freezes."""
        if self.eol is None:
            return None
        return datetime.datetime(self.eol.year, self.eol.month, self.eol.day, tzinfo=datetime.UTC)


class ReleaseCalendar:
    """Ubuntu releases, looked up by version (`25.04`) or by series (`plucky`).

    Both lookups are needed: OSV names a release by version and VEX names it by
    codename.
    """

    def __init__(self, releases: list[Release]):
        self.releases = releases
        self._by_version = {r.version: r for r in releases}
        self._by_series = {r.series: r for r in releases}

    def get(self, key: str) -> Release | None:
        return self._by_version.get(key) or self._by_series.get(key)

    def frozen(self, key: str, now: datetime.datetime) -> bool:
        """Has this release stopped being written, as of `now`?

        True only for an interim release whose end-of-life instant is at or
        before `now`. An LTS release, a release with no published end-of-life
        date, and a release the calendar does not list are all live: a release
        cannot be at end of life before it exists in the calendar, and treating
        an unknown release as dead would freeze it on a stale copy of the file.
        """
        release = self.get(key)
        if release is None or release.lts:
            return False
        instant = release.eol_instant
        if instant is None:
            return False
        return now >= instant

    def frozen_versions(self, now: datetime.datetime) -> set[str]:
        """Every release version frozen as of `now`, computed once per run."""
        return {r.version for r in self.releases if self.frozen(r.version, now)}

    def approaching_eol(self, now: datetime.datetime, window: datetime.timedelta = WARNING_WINDOW) -> list[Release]:
        """Live interim releases whose end-of-life instant falls inside `window`."""
        out = []
        for release in self.releases:
            instant = release.eol_instant
            if release.lts or instant is None:
                continue
            if now < instant <= now + window:
                out.append(release)
        return out

    def __len__(self) -> int:
        return len(self.releases)


def parse(text: str) -> ReleaseCalendar:
    """Read the CSV. Raises CalendarError on anything that isn't one."""
    reader = csv.DictReader(io.StringIO(text))
    fieldnames = reader.fieldnames or []
    missing = [c for c in _REQUIRED_COLUMNS if c not in fieldnames]
    if missing:
        raise CalendarError(f"release calendar is missing column(s) {', '.join(missing)}")

    releases: list[Release] = []
    for row in reader:
        version = (row.get("version") or "").strip()
        series = (row.get("series") or "").strip()
        if not version or not series:
            continue
        lts = version.endswith(_LTS_SUFFIX)
        releases.append(
            Release(
                version=version[: -len(_LTS_SUFFIX)].strip() if lts else version,
                series=series,
                lts=lts,
                eol=_parse_date(row.get("eol")),
            ),
        )

    if not releases:
        raise CalendarError("release calendar has no usable rows")
    return ReleaseCalendar(releases)


def _parse_date(value: str | None) -> datetime.date | None:
    """An empty date column means the date isn't set yet, not that it is unknown-bad."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as e:
        raise CalendarError(f"release calendar has an unreadable date {value!r}") from e


def cached_path(input_path: str) -> str:
    return os.path.join(input_path, SUBDIR, FILENAME)


def load(input_path: str, download: Callable[[str, str], None], logger: logging.Logger, url: str = CALENDAR_URL) -> ReleaseCalendar:
    """Fetch the calendar into `input/distro-info/`, falling back to the cached copy.

    The download lands beside the cached file and only replaces it once it has
    parsed, so a truncated response cannot pass itself off as a calendar or
    destroy the copy that was good yesterday.

    With no cached copy and no download the run fails. The alternative — carry
    on with every release treated as live — is the one direction that can
    ingest a sweep, and a sweep ingested is not recoverable.
    """
    path = cached_path(input_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    staged = path + ".tmp"

    try:
        download(url, staged)
        with open(staged, encoding="utf-8") as fh:
            calendar = parse(fh.read())
    except Exception as e:
        _discard(staged)
        return _fall_back(path, url, logger, e)

    os.replace(staged, path)
    logger.info(f"release calendar: {len(calendar)} releases from {url}")
    return calendar


def _fall_back(path: str, url: str, logger: logging.Logger, cause: Exception) -> ReleaseCalendar:
    if not os.path.isfile(path):
        raise CalendarError(f"could not fetch the release calendar from {url} and no cached copy exists at {path}") from cause
    logger.warning(f"could not fetch the release calendar from {url} ({cause}); falling back to the cached copy at {path}")
    with open(path, encoding="utf-8") as fh:
        return parse(fh.read())


def _discard(path: str) -> None:
    if os.path.exists(path):
        os.remove(path)
