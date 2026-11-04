import abc
import contextlib
import datetime
import logging
import re
from dataclasses import dataclass

from vunnel.utils import date

logger = logging.getLogger(__name__)

# the "timestamp" pattern from schema/vulnerability/osv/schema-1.7.0.json, anchored at the end, as the standard library
# has none. For speed, Result.__post_init__ parses each OSV record's published date with datetime.fromisoformat (about
# 1 microsecond) instead of dateutil (about 34). It checks this pattern first because fromisoformat also accepts forms
# that dateutil rejects, such as the week date 2024-W18-5.
_RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z\Z")

# mapping from GHSA ecosystems (or similar candidates) to syft package types
ecosystem_mapping = {
    "composer": "php-composer",
    "php": "php-composer",
    "rust": "rust-crate",
    "cargo": "rust-crate",
    "dart": "dart-pub",
    "nuget": "dotnet",
    ".net": "dotnet",
    "go": "go-module",
    "golang": "go-module",
    "maven": "java-archive",
    "java": "java-archive",
    "javascript": "npm",
    "pypi": "python",
    "pip": "python",
    "rubygems": "gem",
    "ruby": "gem",
}


@dataclass
class Result:
    date: datetime.date | None
    kind: str
    version: str | None = None
    accurate: bool | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.date, datetime.datetime):
            self.date = self.date.date()
        elif isinstance(self.date, str):
            if _RFC3339_UTC.match(self.date):
                # parse OSV timestamps with fromisoformat, for speed (see the comment on _RFC3339_UTC). A
                # string that matches the pattern but is not a real date, such as one with month 13, makes
                # fromisoformat raise, and dateutil then handles it as before.
                with contextlib.suppress(ValueError):
                    self.date = datetime.datetime.fromisoformat(self.date).date()
                    return
            try:
                self.date = datetime.date.fromisoformat(date.normalize_date(self.date))
            except Exception:
                # shouldn't happen due to date normalization, but just in case
                logger.warning(f"failed to parse fixdater date candidate string '{self.date}', ignoring candidate")
                self.date = None


class Strategy(abc.ABC):
    def __enter__(self) -> "Strategy":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        return None

    @abc.abstractmethod
    def download(self) -> None:
        raise NotImplementedError(
            "Strategy subclasses must implement the download method to fetch data.",
        )

    def skip_download(self) -> None:  # noqa: B027  # deliberately optional, not every strategy needs the bookkeeping
        """Record that the caller deliberately skipped the download.

        Callers that honor a skip-download flag must call this instead of download(): it makes
        no network request, but leaves the strategy willing to serve lookups from whatever data
        is already on disk. Strategies that need no such bookkeeping can leave this as a no-op.
        """

    @abc.abstractmethod
    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[Result]:
        raise NotImplementedError(
            "Finder subclasses must implement the get method to retrieve date strings.",
        )

    @abc.abstractmethod
    def get_changed_vuln_ids_since(self, since_date: datetime.datetime) -> set[str]:
        raise NotImplementedError(
            "Finder subclasses must implement the get_changed_vuln_ids_since method.",
        )


class Finder:
    def __init__(self, strategies: list[Strategy], first_observed: Strategy, skip_download: bool = False):
        self.strategies = strategies
        self._skip_download = skip_download
        self.first_observed = first_observed
        # note: lookups are deliberately not memoized. A key looked up a second time in the
        # same run goes back to the strategies and sees the first-observed row the first call
        # recorded, which is what every later run sees. That can change the answer: a candidate
        # dated after that first-observed date is returned by the first call but filtered out
        # by the second (see test_repeated_lookup_with_future_dated_candidate).

    def __enter__(self) -> "Finder":
        for s in self.strategies:
            s.__enter__()
        self.first_observed.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        for s in self.strategies:
            s.__exit__(exc_type, exc_val, exc_tb)
        self.first_observed.__exit__(exc_type, exc_val, exc_tb)

    def download(self) -> None:
        if self._skip_download:
            self.first_observed.skip_download()
            for s in self.strategies:
                s.skip_download()
            return
        self.first_observed.download()
        for s in self.strategies:
            s.download()

    def _normalize_ecosystem(self, ecosystem: str | None) -> str | None:
        if not ecosystem:
            return ecosystem

        ecosystem = ecosystem.lower()

        return ecosystem_mapping.get(ecosystem, ecosystem)

    def _find_from_strategies(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None,
    ) -> tuple[list[Result], list[Result]]:
        """Perform database lookups.

        Returns:
            Tuple of (strategy_results, first_observed_results)
        """
        results = []
        for s in self.strategies:
            results.extend(s.find(vuln_id, cpe_or_package, fix_version, ecosystem))

        first_observed_results = self.first_observed.find(vuln_id, cpe_or_package, fix_version, ecosystem)

        return (results, first_observed_results)

    def best(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str | None,
        ecosystem: str | None = None,
        candidates: list[Result] | None = None,
    ) -> Result | None:
        results = []

        ecosystem = self._normalize_ecosystem(ecosystem)

        if not fix_version or fix_version in ("None", "0"):
            # if we don't have a fix version, we can't determine a fix date
            return None

        # add high quality candidates first
        if candidates:
            results.extend([c for c in candidates if c.accurate and c.date])

        strategy_results, first_observed_results = self._find_from_strategies(
            vuln_id,
            cpe_or_package,
            fix_version,
            ecosystem,
        )
        results.extend(strategy_results)

        # add low quality candidates last
        if candidates:
            results.extend([c for c in candidates if not c.accurate and c.date])

        # we should select the date from the set of finders that is the highest quality (earlier in the s
        # results list) but should never be after the first observed date. However, first observed dates are not always
        # accurate, so we should only enforce this if we have an accurate first observed date (not part of the
        # first group of observed fixes).
        #
        # ...If the first observed date is accurate, then follow these rules:
        # - If a s date is after the first observed date, we should discard it.
        # - If no s candidates are before the first observed date, we should return the first observed dates.
        # - If there is no first observed dates, we should return the best s candidates we have.

        accurate_first_observed = [r for r in first_observed_results if r.accurate]

        if accurate_first_observed:
            # select the best first observed date as a point of reference
            first_accurate_observed_date = accurate_first_observed[0].date

            if first_accurate_observed_date is not None:
                filtered_results = [r for r in results if r.date is not None and r.date <= first_accurate_observed_date]
            else:
                filtered_results = []
            if filtered_results:
                # return the best/first valid candidates relative to the best first observed date
                return filtered_results[0]
            # return the first observed date instead of any other candidate
            return accurate_first_observed[0]

        # ... If we don't have an accurate first observed date, then treat that as a last resort option
        results.extend(first_observed_results)

        if results:
            # return the best/first candidate we have
            return results[0]

        return None

    def get_changed_vuln_ids_since(self, since_date: datetime.datetime) -> set[str]:
        changed_ids = set()
        for s in self.strategies:
            changed_ids.update(s.get_changed_vuln_ids_since(since_date))
        return changed_ids
