import abc
import datetime
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
        fix_version: str | None,
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
    def __init__(self, strategies: list[Strategy], first_observed: Strategy):
        self.strategies = strategies
        self.first_observed = first_observed

    def download(self) -> None:
        self.first_observed.download()
        for s in self.strategies:
            s.download()

    def _normalize_ecosystem(self, ecosystem: str | None) -> str | None:
        if not ecosystem:
            return ecosystem

        ecosystem = ecosystem.lower()

        return ecosystem_mapping.get(ecosystem, ecosystem)

    def best(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str | None,
        ecosystem: str | None = None,
        candidates: list[Result] | None = None,
    ) -> Result | None:
        results = []

        if not fix_version or fix_version in ("None", "0"):
            # if we don't have a fix version, we can't determine a fix date
            return None

        # add high quality candidates first
        if candidates:
            results.extend([c for c in candidates if c.accurate and c.date])

        # add results from finders in order of priority (set by the constructor)
        for s in self.strategies:
            results.extend(s.find(vuln_id, cpe_or_package, fix_version, ecosystem))

        # add low quality candidates last
        if candidates:
            results.extend([c for c in candidates if not c.accurate and c.date])

        first_observed_results = self.first_observed.find(vuln_id, cpe_or_package, fix_version, ecosystem)

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
