import abc
import datetime
import functools
import logging
from dataclasses import dataclass

from vunnel.utils import date

logger = logging.getLogger(__name__)

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
    def __init__(self, strategies: list[Strategy], first_observed: Strategy, cache_size: int = 10000):
        self.strategies = strategies
        self.first_observed = first_observed
        # Create cached version of database lookups
        self._cached_find_from_strategies = functools.lru_cache(maxsize=cache_size)(self._find_from_strategies_uncached)

    def __enter__(self) -> "Finder":
        for s in self.strategies:
            s.__enter__()
        self.first_observed.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        for s in self.strategies:
            s.__exit__(exc_type, exc_val, exc_tb)
        self.first_observed.__exit__(exc_type, exc_val, exc_tb)
        # Clear cache on exit
        self._cached_find_from_strategies.cache_clear()

    def download(self) -> None:
        self.first_observed.download()
        for s in self.strategies:
            s.download()

    def _normalize_ecosystem(self, ecosystem: str | None) -> str | None:
        if not ecosystem:
            return ecosystem

        ecosystem = ecosystem.lower()

        return ecosystem_mapping.get(ecosystem, ecosystem)

    def _find_from_strategies_uncached(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None,
    ) -> tuple[list[Result], list[Result]]:
        """Perform database lookups - uncached version for LRU wrapper.

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
        ecosystem = self._normalize_ecosystem(ecosystem)

        if not fix_version or fix_version in ("None", "0"):
            # if we don't have a fix version, we can't determine a fix date
            return None

        # split candidates by confidence. accurate candidates (e.g. a provider's real ship date)
        # are trusted alongside strategy results; inaccurate candidates (e.g. an advisory's own
        # `published` date, which routinely predates the fix) are a last resort only, ranked below
        # any first-observed date.
        accurate_candidates: list[Result] = []
        inaccurate_candidates: list[Result] = []
        if candidates:
            accurate_candidates = [c for c in candidates if c.accurate and c.date]
            inaccurate_candidates = [c for c in candidates if not c.accurate and c.date]

        # Use cached database lookups
        strategy_results, first_observed_results = self._cached_find_from_strategies(
            vuln_id,
            cpe_or_package,
            fix_version,
            ecosystem,
        )

        # high-quality results, in priority order: accurate candidates, then strategies.
        high_quality = accurate_candidates + list(strategy_results)

        # we should select the highest-quality date (earliest in high_quality) but never one after
        # the first observed date. First observed dates are not always accurate, so we only enforce
        # that ceiling when we have an accurate first observed date (not part of the first group of
        # observed fixes).
        #
        # ...If the first observed date is accurate, then follow these rules:
        # - If a high-quality date is after the first observed date, we should discard it.
        # - If none are before the first observed date, we should return the first observed date.
        # An inaccurate candidate is never preferred over first-observed data; it is only used when
        # there is no first-observed date at all.

        accurate_first_observed = [r for r in first_observed_results if r.accurate]

        if accurate_first_observed:
            # select the best first observed date as a point of reference
            first_accurate_observed_date = accurate_first_observed[0].date

            if first_accurate_observed_date is not None:
                filtered_results = [r for r in high_quality if r.date is not None and r.date <= first_accurate_observed_date]
            else:
                filtered_results = []
            if filtered_results:
                # return the best/first valid candidate relative to the best first observed date
                return filtered_results[0]
            # return the first observed date instead of any lower-confidence candidate
            return accurate_first_observed[0]

        # no accurate first observed date: prefer high-quality results, then any first-observed date,
        # and only then fall back to inaccurate candidates (e.g. the advisory published date).
        results = high_quality + list(first_observed_results) + inaccurate_candidates

        if results:
            # return the best/first candidate we have
            return results[0]

        return None

    def get_changed_vuln_ids_since(self, since_date: datetime.datetime) -> set[str]:
        changed_ids = set()
        for s in self.strategies:
            changed_ids.update(s.get_changed_vuln_ids_since(since_date))
        return changed_ids
