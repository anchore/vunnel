import logging
from datetime import UTC, datetime

from vunnel import workspace

from .finder import Result, Strategy
from .grype_db_first_observed import Store as GrypeDBStore
from .vunnel_first_observed import Store as VunnelStore


def _observed_earlier(results: list[Result], than: list[Result]) -> bool:
    """Report whether the earliest date in results is strictly before the earliest date in than."""
    dates = [r.date for r in results if r.date]
    than_dates = [r.date for r in than if r.date]
    return bool(dates) and bool(than_dates) and min(dates) < min(than_dates)


class Store(Strategy):
    def __init__(self, ws: workspace.Workspace) -> None:
        self.workspace = ws
        self.logger = logging.getLogger("grype-db-fixes-" + ws.name)
        self.grype_db_store = GrypeDBStore(ws)
        self.vunnel_store = VunnelStore(ws)

    def __enter__(self) -> "Store":
        """context manager entry - ensure connection is ready"""
        self.grype_db_store.__enter__()
        self.vunnel_store.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """context manager exit - cleanup thread connections"""
        self.grype_db_store.__exit__(exc_type, exc_val, exc_tb)
        self.vunnel_store.__exit__(exc_type, exc_val, exc_tb)

    def download(self) -> None:
        self.grype_db_store.download()

    def skip_download(self) -> None:
        self.grype_db_store.skip_download()

    def get_changed_vuln_ids_since(self, since_date: datetime) -> set[str]:
        return self.grype_db_store.get_changed_vuln_ids_since(since_date)

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[Result]:
        vunnel_results = self.vunnel_store.find(vuln_id, cpe_or_package, fix_version, ecosystem)
        grype_db_results = self.grype_db_store.find(vuln_id, cpe_or_package, fix_version, ecosystem)

        # vunnel's own record wins unless grype db observed the fix strictly earlier. A vunnel row can be dated
        # later than the fix was first observed (e.g. it was written by a run that could not match the grype db
        # row), and is never rewritten, so the earlier grype db date has to be preferred on every lookup.
        if vunnel_results and not _observed_earlier(grype_db_results, vunnel_results):
            return vunnel_results

        if grype_db_results:
            return grype_db_results

        # if no results, add a new entry into vunnel (this is a new observed fix date) and return that
        today = datetime.now(UTC).date()
        self.vunnel_store.add(today, vuln_id, cpe_or_package, fix_version, ecosystem)

        return [
            Result(
                date=today,
                kind="first-observed",
                version=fix_version,
                source="vunnel",
            ),
        ]
