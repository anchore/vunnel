import logging
import os
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

import oras.client
import sqlalchemy as db
from sqlalchemy import event

from vunnel import workspace

from .finder import Finder, Result


@dataclass
class FixDate:
    """
    This is the model representing the fixdate table in the underlying sqlite database.
    """

    vuln_id: str
    provider: str
    package_name: str
    full_cpe: str
    ecosystem: str
    fix_version: str | None
    first_observed_date: date
    resolution: str
    source: str


class Store(Finder):
    def __init__(self, ws: workspace.Workspace, provider: str) -> None:
        self.workspace = ws
        self.provider = provider
        self.db_path = Path(ws.input_path) / "fix-dates" / f"{provider}.db"
        self.logger = logging.getLogger("fixes-" + provider)
        self.engine: db.engine.Engine | None = None
        self.conn: db.engine.Connection | None = None
        self.table: db.Table | None = None

    def download(self) -> None:
        """fetch the fix date database from the OCI registry using ORAS"""
        # construct the image reference
        image_ref = f"ghcr.io/anchore/grype-db-observed-fix-date/{self.provider}:latest"

        # ensure the parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # download the database file using ORAS
        client = oras.client.OrasClient()

        # authenticate with GitHub Container Registry if token is available
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            try:
                client.login(
                    hostname="ghcr.io",
                    username="token",
                    password=github_token,
                )
                self.logger.debug("authenticated with GitHub Container Registry using GITHUB_TOKEN")
            except Exception as e:
                self.logger.warning(f"failed to authenticate with GitHub Container Registry: {e}")

        try:
            # pull the artifact to the target directory
            # the database file should be pulled directly as the db_path
            client.pull(target=image_ref, outdir=str(self.db_path.parent))
            self.logger.info(f"successfully fetched fix date database for {self.provider}")
        except Exception as e:
            self.logger.error(f"failed to fetch fix date database for {self.provider}: {e}")
            raise

    def get(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str | None,
        ecosystem: str | None = None,
    ) -> list[FixDate]:
        """synchronous get existing vulnerability operation"""
        conn, table = self._get_connection()

        # build query - if cpe_or_package looks like a CPE, search by full_cpe, otherwise by package_name
        query = table.select().where(
            (table.c.vuln_id == vuln_id) & (table.c.provider == self.provider),
        )

        if cpe_or_package.startswith("cpe:"):
            query = query.where(table.c.full_cpe == cpe_or_package)
        else:
            query = query.where(
                (table.c.package_name == cpe_or_package) & (table.c.full_cpe == ""),
            )
            if ecosystem:
                query = query.where(table.c.ecosystem == ecosystem)

        if fix_version:
            query = query.where(table.c.fix_version == fix_version)

        results = conn.execute(query).fetchall()

        return [
            FixDate(
                vuln_id=row.vuln_id,
                provider=row.provider,
                package_name=row.package_name,
                full_cpe=row.full_cpe,
                ecosystem=row.ecosystem,
                fix_version=row.fix_version,
                first_observed_date=date.fromisoformat(row.first_observed_date),
                resolution=row.resolution,
                source=row.source,
            )
            for row in results
        ]

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str | None,
        ecosystem: str | None = None,
    ) -> list[Result]:
        return [
            Result(date=fd.first_observed_date, kind="first-observed", version=fd.fix_version)
            for fd in self.get(
                vuln_id=vuln_id,
                cpe_or_package=cpe_or_package,
                fix_version=fix_version,
                ecosystem=ecosystem,
            )
        ]

    def get_changed_vuln_ids_since(self, since_date: datetime) -> set[str]:
        """get all vulnerability IDs that have been created or modified after the given date.

        This queries the runs table to find applicable runs, then returns all unique
        vuln_ids from fixdate entries with those run_ids. These vulnerabilities will
        need to be fully reprocessed.

        Args:
            since_date: Only return vuln IDs from runs after this datetime

        Returns:
            Set of unique vulnerability IDs that have changed
        """
        conn, _ = self._get_connection()

        # reflect the runs table structure
        metadata = db.MetaData()
        runs_table = db.Table("runs", metadata, autoload_with=self.engine)
        fixdates_table = db.Table("fixdates", metadata, autoload_with=self.engine)

        # get run IDs for runs after the given date
        run_query = runs_table.select().where(runs_table.c.run_timestamp >= since_date)
        run_results = conn.execute(run_query).fetchall()

        if not run_results:
            return set()

        run_ids = [row.id for row in run_results]

        # get distinct vuln_ids from fixdates with those run_ids
        vuln_query = (
            db.select(fixdates_table.c.vuln_id)
            .distinct()
            .where(
                fixdates_table.c.run_id.in_(run_ids),
            )
        )
        vuln_results = conn.execute(vuln_query).fetchall()

        return {row.vuln_id for row in vuln_results}

    def _get_connection(self) -> tuple[db.engine.Connection, db.Table]:
        """get or create SQLAlchemy connection and table"""
        if not self.conn:
            self.engine = db.create_engine(f"sqlite:///{self.db_path}")

            # configure SQLAlchemy engine with SQLite pragmas
            @event.listens_for(self.engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA query_only = ON")
                cursor.execute("PRAGMA cache_size=1000")
                cursor.execute("PRAGMA temp_store=memory")
                cursor.close()

            self.conn = self.engine.connect()

            # reflect the existing table structure
            metadata = db.MetaData()
            self.table = db.Table("fixdates", metadata, autoload_with=self.engine)

        return self.conn, self.table  # type: ignore[return-value]
