from __future__ import annotations

import abc
import enum
import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

import orjson
import sqlalchemy as db

if TYPE_CHECKING:
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


class SQLiteStore(Store):
    filename = "results.db"
    temp_filename = "results.db.tmp"
    table_name = "results"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.conn = None
        self.engine = None
        self.table = None

        @db.event.listens_for(db.engine.Engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            # cursor.execute("pragma journal_mode=OFF")
            cursor.execute("PRAGMA synchronous=NORMAL")
            # cursor.execute("PRAGMA cache_size=100000")
            cursor.close()

    def connection(self) -> tuple[db.engine.Connection, db.Table]:
        if not self.conn:
            self.engine = db.create_engine(f"sqlite:///{self.temp_db_file_path}")
            self.conn = self.engine.connect()  # type: ignore[attr-defined]
            self.table = self._create_table()
        return self.conn, self.table

    @property
    def db_file_path(self) -> str:
        return os.path.join(self.workspace.results_path, self.filename)

    @property
    def temp_db_file_path(self) -> str:
        return os.path.join(self.workspace.results_path, self.temp_filename)

    def _create_table(self) -> db.Table:
        metadata = db.MetaData()
        table = db.Table(
            self.table_name,
            metadata,
            db.Column("id", db.String(), primary_key=True, index=True),
            db.Column("record", db.LargeBinary()),
        )
        metadata.create_all(self.engine)
        return table

    def store(self, identifier: str, record: Envelope) -> None:
        record_str = orjson.dumps(asdict(record))
        conn, table = self.connection()

        with conn.begin():
            # upsert the record conditionally based on the skip_duplicates configuration
            existing = conn.execute(table.select().where(table.c.id == identifier)).first()
            if existing:
                if self.skip_duplicates:
                    self.logger.warning(f"{identifier!r} entry already written (skipping)")
                    return
                self.logger.trace(f"overwriting existing entry: {identifier!r}")  # type: ignore[attr-defined]
                statement = db.update(table).where(table.c.id == identifier).values(record=record_str)
            else:
                self.logger.trace(f"writing record to {identifier!r} key")  # type: ignore[attr-defined]
                statement = db.insert(table).values(id=identifier, record=record_str)

            conn.execute(statement)

    def prepare(self) -> None:
        if os.path.exists(self.temp_db_file_path):
            self.logger.warning("removing unexpected partial result state")
            os.remove(self.temp_db_file_path)

        if self.result_state_policy == ResultStatePolicy.KEEP and os.path.exists(self.db_file_path):
            shutil.copy2(self.db_file_path, self.temp_db_file_path)

    def close(self, successful: bool) -> None:
        if self.conn:
            self.conn.close()
            self.engine.dispose()

            self.conn = None
            self.engine = None
            self.table = None

        if successful:
            os.rename(self.temp_db_file_path, self.db_file_path)
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
