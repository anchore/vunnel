import logging
from datetime import UTC, datetime
from pathlib import Path

from vunnel import workspace

from .finder import Result, Strategy
from .grype_db_first_observed import Store as GrypeDBStore
from .vunnel_first_observed import Store as VunnelStore


class Store(Strategy):
    def __init__(self, ws: workspace.Workspace, use_grype_db: bool = False) -> None:
        self.workspace = ws
        self.logger = logging.getLogger("grype-db-fixes-" + ws.name)
        self.use_grype_db = use_grype_db

        if use_grype_db:
            self.grype_db_store: GrypeDBStore | None = GrypeDBStore(ws)
        else:
            self.grype_db_store = None

        self.vunnel_store = VunnelStore(ws)

    def _cleanup_grype_db_files(self) -> None:
        """remove existing grype-db fix date files to reclaim disk space"""
        input_path = Path(self.workspace.input_path)
        db_path = input_path / "grype-db-observed-fix-dates.db"
        digest_path = db_path.with_suffix(".db.digest")

        for path in [db_path, digest_path]:
            if path.exists():
                self.logger.debug(f"removing disabled grype-db fixdates file: {path}")
                path.unlink()

    def __enter__(self) -> "Store":
        """context manager entry - ensure connection is ready"""
        if self.grype_db_store:
            self.grype_db_store.__enter__()
        else:
            self._cleanup_grype_db_files()
        self.vunnel_store.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """context manager exit - cleanup thread connections"""
        if self.grype_db_store:
            self.grype_db_store.__exit__(exc_type, exc_val, exc_tb)
        self.vunnel_store.__exit__(exc_type, exc_val, exc_tb)

    def download(self) -> None:
        if self.grype_db_store:
            self.grype_db_store.download()

    def get_changed_vuln_ids_since(self, since_date: datetime) -> set[str]:
        if self.grype_db_store:
            return self.grype_db_store.get_changed_vuln_ids_since(since_date)
        return set()

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[Result]:
        # always look for results from vunnel first, returning any results
        results = self.vunnel_store.find(vuln_id, cpe_or_package, fix_version, ecosystem)
        if results:
            return results

        # if no results from vunnel, look in grype db (if enabled)
        if self.grype_db_store:
            results = self.grype_db_store.find(vuln_id, cpe_or_package, fix_version, ecosystem)
            if results:
                return results

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
