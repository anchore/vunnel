import contextlib
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

import sqlalchemy as db
from sqlalchemy import Index, event, exc

from vunnel import workspace

from .ecosystem import normalize_package_name
from .finder import Result


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
    updated_at: datetime | None = None


class Store:
    def __init__(self, ws: workspace.Workspace, batch_size: int = 2000) -> None:
        self.workspace = ws
        self.provider = ws.name
        self.db_path = Path(ws.results_path) / "observed-fix-dates.db"
        self.logger = logging.getLogger("fixes-" + self.provider)
        self.engine: db.engine.Engine | None = None
        self._thread_local = threading.local()
        self.batch_size = batch_size

    @property
    def _pending_operations(self) -> int:
        """Get pending operation count for the current thread."""
        return getattr(self._thread_local, "pending_operations", 0)

    @_pending_operations.setter
    def _pending_operations(self, value: int) -> None:
        """Set pending operation count for the current thread."""
        self._thread_local.pending_operations = value

    def add(
        self,
        first_observed_date: date,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> None:
        """synchronous add new vulnerability operation"""
        self.logger.debug(
            f"adding first observed fix date: {first_observed_date} for {vuln_id} {cpe_or_package}@{fix_version} (ecosystem={ecosystem!r})",
        )

        conn, table = self._get_connection()

        if cpe_or_package.lower().startswith("cpe:"):
            full_cpe = cpe_or_package
            package_name = ""
        else:
            full_cpe = ""
            package_name = normalize_package_name(cpe_or_package, ecosystem)

        insert_stmt = table.insert().values(
            vuln_id=vuln_id,
            provider=self.provider,
            package_name=package_name,
            full_cpe=full_cpe,
            ecosystem=ecosystem or "",
            fix_version=fix_version,
            first_observed_date=first_observed_date.isoformat(),
            updated_at=datetime.now(UTC),
        )

        conn.execute(insert_stmt)
        self._pending_operations += 1

        # auto-flush every batch_size operations to limit memory usage
        if self._pending_operations >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        """Commit any pending database operations for the current thread."""
        if self._pending_operations > 0:
            conn, _ = self._get_connection()
            conn.commit()
            self.logger.debug(f"flushed {self._pending_operations} operations to database")
            self._pending_operations = 0

    def get(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[FixDate]:
        """synchronous get existing vulnerability operation"""
        conn, table = self._get_connection()

        # build query - if cpe_or_package looks like a CPE, search by full_cpe, otherwise by package_name
        query = table.select().where(
            (table.c.vuln_id == vuln_id) & (table.c.provider == self.provider),
        )

        if cpe_or_package.lower().startswith("cpe:"):
            query = query.where(table.c.full_cpe == cpe_or_package)
        else:
            query = query.where(
                (table.c.package_name == normalize_package_name(cpe_or_package, ecosystem)) & (table.c.full_cpe == ""),
            )
            if ecosystem:
                query = query.where(table.c.ecosystem == ecosystem)

        if fix_version:
            query = query.where(table.c.fix_version == fix_version)

        results = conn.execute(query).fetchall()

        if not results:
            return []

        return [
            FixDate(
                vuln_id=row.vuln_id,
                provider=row.provider,
                package_name=row.package_name,
                full_cpe=row.full_cpe,
                ecosystem=row.ecosystem,
                fix_version=row.fix_version,
                first_observed_date=date.fromisoformat(row.first_observed_date),
                updated_at=row.updated_at,
            )
            for row in results
            if row and row.first_observed_date
        ]

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[Result]:
        return [
            Result(
                date=fd.first_observed_date,
                kind="first-observed",
                version=fd.fix_version,
                accurate=True,
                source="vunnel",
            )
            for fd in self.get(
                vuln_id=vuln_id,
                cpe_or_package=cpe_or_package,
                fix_version=fix_version,
                ecosystem=ecosystem,
            )
        ]

    def _create_tables(self) -> db.Table:
        """create database tables and indexes using SQLAlchemy"""
        metadata = db.MetaData()

        # define the fixdates table schema
        fixdates_table = db.Table(
            "fixdates",
            metadata,
            db.Column("vuln_id", db.Text, nullable=False),
            db.Column("provider", db.Text, nullable=False),
            db.Column("package_name", db.Text, nullable=False),
            db.Column("full_cpe", db.Text, default=""),
            db.Column("ecosystem", db.Text, default=""),
            db.Column("fix_version", db.Text),
            db.Column("first_observed_date", db.Text, nullable=False),
            db.Column("updated_at", db.Text),
            # composite primary key
            db.PrimaryKeyConstraint(
                "vuln_id",
                "provider",
                "package_name",
                "full_cpe",
                "ecosystem",
                "fix_version",
            ),
        )

        # create the table if it doesn't exist
        if self.engine:
            metadata.create_all(self.engine)

            # create indexes for performance
            indexes = [
                Index("idx_vuln_provider", fixdates_table.c.vuln_id, fixdates_table.c.provider),
                Index("idx_package_name_nocase", fixdates_table.c.package_name),
                Index("idx_vuln_cpe", fixdates_table.c.vuln_id, fixdates_table.c.full_cpe),
                Index("idx_updated_at", fixdates_table.c.updated_at),
            ]

            # create indexes if they don't exist
            for index in indexes:
                with contextlib.suppress(Exception):
                    # ignore index creation errors (they might already exist)
                    index.create(self.engine, checkfirst=True)

        return fixdates_table

    def _get_connection(self) -> tuple[db.engine.Connection, db.Table]:
        """get or create thread-local SQLAlchemy connection and table"""

        if not hasattr(self._thread_local, "conn") or not hasattr(self._thread_local, "table"):
            # create engine once if it doesn't exist
            if not self.engine:
                self.engine = db.create_engine(f"sqlite:///{self.db_path}")

                # configure SQLAlchemy engine with SQLite pragmas
                @event.listens_for(self.engine, "connect")
                def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA cache_size=1000")
                    cursor.execute("PRAGMA temp_store=memory")
                    cursor.execute("PRAGMA journal_mode=DELETE")  # we don't want wal and shm files lingering around in the result workspace
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.execute("PRAGMA busy_timeout=30000")
                    cursor.close()

            # create thread-local connection
            self._thread_local.conn = self.engine.connect()

            # try to reflect the existing table structure, create if it doesn't exist
            try:
                metadata = db.MetaData()
                self._thread_local.table = db.Table("fixdates", metadata, autoload_with=self.engine)
            except exc.NoSuchTableError:
                # table doesn't exist, create it
                self.logger.debug("fixdates table does not exist, creating it")
                self._thread_local.table = self._create_tables()

        return self._thread_local.conn, self._thread_local.table

    def cleanup_thread_connections(self) -> None:
        """clean up thread-local connections for the current thread"""
        if hasattr(self._thread_local, "conn"):
            try:
                self.logger.debug("closing vunnel fixdates database")
                self._thread_local.conn.execute(db.text("VACUUM"))
                self._thread_local.conn.close()
            except Exception:
                # ignore errors during cleanup
                self.logger.exception("error closing vunnel fixdates database connection")
            finally:
                # clear the thread-local storage
                if hasattr(self._thread_local, "conn"):
                    delattr(self._thread_local, "conn")
                if hasattr(self._thread_local, "table"):
                    delattr(self._thread_local, "table")

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        # Flush any remaining operations before cleanup
        self.flush()
        self.cleanup_thread_connections()
