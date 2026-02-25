from __future__ import annotations

import abc
import enum
import logging
import os
import shutil
import threading
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

import orjson
import sqlalchemy as db

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from .schema import Schema
    from .workspace import Workspace


class ResultStatePolicy(str, enum.Enum):
    KEEP = "keep"
    DELETE = "delete"
    DELETE_BEFORE_WRITE = "delete-before-write"  # treat like "KEEP" in error cases

    def __repr__(self) -> str:
        return self.value


@dataclass
class Envelope:
    schema: str
    identifier: str
    item: Any


class Store:
    def __init__(
        self,
        workspace: Workspace,
        result_state_policy: ResultStatePolicy,
        skip_duplicates: bool = False,
        logger: logging.Logger | None = None,
        **kwargs: dict[str, Any],
    ):
        self.workspace = workspace
        self.result_state_policy = result_state_policy
        self.skip_duplicates = skip_duplicates
        self.start = time.time()

        if not logger:
            logger = logging.getLogger("results-writer")
        self.logger = logger

    @abc.abstractmethod
    def store(self, identifier: str, record: Envelope) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def prepare(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def close(self, successful: bool) -> None:
        raise NotImplementedError


class StoreStrategy(str, enum.Enum):
    FLAT_FILE = "flat-file"
    SQLITE = "sqlite"

    def __repr__(self) -> str:
        return self.value

    def store(self, *args: Any, **kwargs: Any) -> Store:
        if self == StoreStrategy.FLAT_FILE:
            return FlatFileStore(*args, **kwargs)
        if self == StoreStrategy.SQLITE:
            return SQLiteStore(*args, **kwargs)
        raise ValueError(f"unsupported result store strategy: {self!r}")


class FlatFileStore(Store):
    def store(self, identifier: str, record: Envelope) -> None:
        filename = f"{identifier}.json"
        filepath = os.path.join(self.workspace.results_path, filename)

        # allow for nested directories controlled by the provider (for large sets of results)
        if os.sep in identifier:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

        if os.path.exists(filepath):
            if self.skip_duplicates and os.path.getmtime(filepath) >= self.start:
                self.logger.warning(f"{identifier!r} entry already written (skipping)")
                return
            self.logger.trace(f"overwriting existing file: {filepath!r}")  # type: ignore[attr-defined]

        with open(filepath, "wb") as f:
            self.logger.trace(f"writing record to {filepath!r}")  # type: ignore[attr-defined]
            f.write(orjson.dumps(asdict(record), f))  # type: ignore[arg-type]

    def prepare(self) -> None:
        if self.result_state_policy == ResultStatePolicy.DELETE_BEFORE_WRITE:
            self.workspace.clear_results()

    def close(self, successful: bool) -> None:
        pass


class _SQLiteStoreThreadLocal(threading.local):
    """thread-local storage for per-thread SQLAlchemy connections."""

    conn: db.engine.Connection | None = None


class SQLiteStore(Store):
    filename = "results.db"
    temp_filename = "results.db.tmp"
    table_name = "results"

    def __init__(self, *args: Any, write_location: str | None = None, batch_size: int = 5000, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.engine: db.engine.Engine | None = None
        self.write_location = write_location
        self.batch_size = batch_size
        self._thread_local = _SQLiteStoreThreadLocal()
        self._pending_records: list[dict[str, Any]] = []
        self._total_submitted = 0
        self._closed = False
        self._lock = threading.Lock()
        self._engine_lock = threading.Lock()
        # not thread-local: Table objects are immutable metadata descriptors safe to share across threads,
        # and access is serialized by _engine_lock in _ensure_engine_and_table().
        self._table: db.Table | None = None
        if self.write_location:
            self.filename = os.path.basename(self.write_location)
            self.temp_filename = f"{self.filename}.tmp"

    def _ensure_engine_and_table(self) -> tuple[db.engine.Engine, db.Table]:
        """get or create the shared engine and table definition (thread-safe)."""
        with self._engine_lock:
            if self.engine is None:
                self.engine = db.create_engine(f"sqlite:///{self.temp_db_file_path}")

                @db.event.listens_for(self.engine, "connect")
                def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.execute("PRAGMA cache_size=10000")
                    cursor.execute("PRAGMA temp_store=MEMORY")
                    cursor.execute("PRAGMA wal_autocheckpoint=10000")
                    cursor.close()

            if self._table is None:
                self._table = self._create_table(self.engine)

        return self.engine, self._table

    def connection(self) -> tuple[db.engine.Connection, db.Table]:
        """get or create a thread-local connection and shared table."""
        engine, table = self._ensure_engine_and_table()
        if self._thread_local.conn is None:
            self._thread_local.conn = engine.connect()
        return self._thread_local.conn, table

    @property
    def write_dir(self) -> str:
        if self.write_location:
            return os.path.dirname(self.write_location)
        return self.workspace.results_path

    @property
    def db_file_path(self) -> str:
        if self.write_location:
            return self.write_location
        return os.path.join(self.write_dir, self.filename)

    @property
    def temp_db_file_path(self) -> str:
        return os.path.join(self.write_dir, self.temp_filename)

    def _create_table(self, engine: db.engine.Engine) -> db.Table:
        metadata = db.MetaData()
        table = db.Table(
            self.table_name,
            metadata,
            db.Column("id", db.String(), primary_key=True, index=True),
            db.Column("record", db.LargeBinary()),
        )
        metadata.create_all(engine)
        return table

    def store(self, identifier: str, record: Envelope) -> None:
        record_bytes = orjson.dumps(asdict(record))

        with self._lock:
            if self._closed:
                raise RuntimeError("store() called after close()")

            self._pending_records.append({"id": identifier, "record": record_bytes})

            # auto-flush every batch_size records to limit memory usage
            if len(self._pending_records) >= self.batch_size:
                self._flush_unlocked()

    def flush(self) -> None:
        """Commit any pending database operations (thread-safe)."""
        with self._lock:
            self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        """Internal flush helper - caller must hold lock.

        Note: any thread may trigger a flush, writing all pending records through its own
        thread-local connection. This is safe because the lock serializes all access to
        _pending_records."""
        if not self._pending_records:
            return

        conn, table = self.connection()
        count = len(self._pending_records)

        prefix = "OR IGNORE" if self.skip_duplicates else "OR REPLACE"
        stmt = table.insert().prefix_with(prefix)

        with conn.begin():
            result = conn.execute(stmt, self._pending_records)
            rows_written = result.rowcount

        self._total_submitted += count

        if self.skip_duplicates and rows_written < count:
            skipped = count - rows_written
            self.logger.warning(f"skipped {skipped} duplicate records in batch of {count}")

        self.logger.debug(f"flushed {count} records to results database (total={self._total_submitted:,d})")
        self._pending_records = []

    def read(self, identifier: str) -> Envelope:
        conn, table = self.connection()
        with conn.begin():
            result = conn.execute(table.select().where(table.c.id == identifier)).first()
            if not result:
                raise KeyError(f"no result found for identifier: {identifier!r}")

            return Envelope(**orjson.loads(result.record))

    def _remove_wal_sidecar_files(self, db_path: str) -> None:
        """remove WAL sidecar files (-wal and -shm) for the given database path."""
        for suffix in ("-wal", "-shm"):
            sidecar = db_path + suffix
            if os.path.exists(sidecar):
                os.remove(sidecar)

    def prepare(self) -> None:
        if os.path.exists(self.temp_db_file_path):
            self.logger.warning("removing unexpected partial result state")
            os.remove(self.temp_db_file_path)
            # clean up any stale WAL sidecar files from a previous interrupted run
            self._remove_wal_sidecar_files(self.temp_db_file_path)

        if self.result_state_policy == ResultStatePolicy.KEEP and os.path.exists(self.db_file_path):
            shutil.copy2(self.db_file_path, self.temp_db_file_path)

    def close(self, successful: bool) -> None:
        """close the store, checkpointing WAL and moving the database into place."""
        # mark as closed and flush under lock so no new store() calls can interleave
        with self._lock:
            self._closed = True
            self._flush_unlocked()

        # checkpoint WAL to fold all data into the main DB file, then close.
        # This ensures no data is left only in the -wal file before we move the .db.
        # Run via the raw DBAPI connection to avoid SQLAlchemy's transaction management --
        # a checkpoint inside a BEGIN block will report "busy" and silently fail to truncate.
        if self._thread_local.conn is not None:
            raw_conn = self._thread_local.conn.connection.dbapi_connection
            if raw_conn is None:
                raise RuntimeError("expected a DBAPI connection but got None")
            cursor = raw_conn.cursor()
            cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            cursor.close()
            self._thread_local.conn.close()
            self._thread_local.conn = None

        # dispose the engine to close all pooled connections from any thread
        if self.engine:
            self.engine.dispose()
            self.engine = None
            self._table = None

        # remove any lingering WAL sidecar files after engine disposal
        self._remove_wal_sidecar_files(self.temp_db_file_path)

        if successful and os.path.exists(self.temp_db_file_path):
            shutil.move(self.temp_db_file_path, self.db_file_path)
        elif os.path.exists(self.temp_db_file_path):
            os.remove(self.temp_db_file_path)


class Writer:
    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        result_state_policy: ResultStatePolicy,
        logger: logging.Logger | None = None,
        skip_duplicates: bool = False,
        store_strategy: StoreStrategy = StoreStrategy.FLAT_FILE,
        write_location: str | None = None,
    ):
        self.workspace = workspace
        self.skip_duplicates = skip_duplicates

        if not logger:
            logger = logging.getLogger("results-writer")
        self.logger = logger

        self.wrote = 0
        self.store = store_strategy.store(
            workspace=workspace,
            result_state_policy=result_state_policy,
            skip_duplicates=skip_duplicates,
            logger=logger,
            write_location=write_location,
        )

    def __enter__(self) -> Writer:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.store.close(successful=exc_val is None)
        self.logger.info(f"wrote {len(self)} entries")

    def __len__(self) -> int:
        return self.wrote

    def write(self, identifier: str, schema: Schema, payload: Any) -> None:
        if self.wrote == 0:
            self.store.prepare()

        envelope = Envelope(identifier=identifier, schema=schema.url, item=payload)

        self.store.store(identifier, envelope)

        self.wrote += 1


class SQLiteReader:
    def __init__(self, sqlite_db_path: str, table_name: str = "results"):
        self.db_path = sqlite_db_path
        self.table_name = table_name
        self.conn: db.engine.Connection | None = None
        self.engine: db.engine.Engine | None = None
        self.table: db.Table | None = None

    def read(self, identifier: str) -> dict[str, Any] | None:
        conn, table = self.connection()
        with conn.begin():
            result = conn.execute(table.select().where(table.c.id == identifier.lower())).first()
            if not result:
                return None

            return orjson.loads(result.record)

    def each(self) -> Generator[Envelope]:
        conn, table = self.connection()
        with conn.begin():
            # query all results, returning one at a time (do not fetch all into memory)
            results = conn.execute(table.select())
            for r in results:
                yield Envelope(**orjson.loads(r.record))

    def read_all(self) -> list[Envelope]:
        conn, table = self.connection()
        with conn.begin():
            results = conn.execute(table.select()).fetchall()
            return [Envelope(**orjson.loads(r.record)) for r in results]

    def connection(self) -> tuple[db.engine.Connection, db.Table]:
        if not self.conn:
            self.engine = db.create_engine(f"sqlite:///{self.db_path}?mode=ro")
            self.conn = self.engine.connect()
            metadata = db.MetaData()
            self.table = db.Table(self.table_name, metadata, autoload_with=self.engine)
        return self.conn, self.table  # type: ignore[return-value]

    def __enter__(self) -> SQLiteReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self.conn:
            self.conn.close()
            if self.engine:
                self.engine.dispose()

            self.conn = None
            self.engine = None
            self.table = None
