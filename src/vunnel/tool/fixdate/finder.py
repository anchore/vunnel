import abc
import datetime
from dataclasses import dataclass


@dataclass
class Result:
    date: datetime.date
    kind: str


class Finder(abc.ABC):
    @abc.abstractmethod
    def download(self) -> None:
        raise NotImplementedError(
            "Finder subclasses must implement the download method to fetch data.",
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


class CombinedFinder(Finder):
    def __init__(self, finders: list[Finder]):
        self.finders = finders

    def download(self) -> None:
        for finder in self.finders:
            finder.download()

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str | None,
        ecosystem: str | None = None,
    ) -> list[Result]:
        results = []
        for finder in self.finders:
            results.extend(finder.find(vuln_id, cpe_or_package, fix_version, ecosystem))
        return results
