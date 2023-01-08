import abc
import enum
import logging
import os
import time
from dataclasses import asdict, dataclass
from types import TracebackType
from typing import Any

import orjson
import sqlalchemy as db

from .schema import Schema
from .workspace import Workspace


@dataclass
class Envelope:
    schema: str
    identifier: str
    item: Any


class Store:
    def __init__(
        self,
        workspace: Workspace,
        skip_duplicates: bool = False,
        logger: logging.Logger | None = None,
    ):
        self.workspace = workspace
        self.skip_duplicates = skip_duplicates
        self.start = time.time()

        if not logger:
            logger = logging.getLogger("results-writer")
        self.logger = logger

    @abc.abstractmethod
    def store(self, identifier: str, record: Envelope):
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError


class StoreStrategy(str, enum.Enum):
    FLAT_FILE = "flat-file"
    SQLITE = "sqlite"

    def __repr__(self) -> str:
        return self.value

    def store(self, *args, **kwargs) -> Store:
        if self == StoreStrategy.FLAT_FILE:
            return FlatFileStore(*args, **kwargs)
        elif self == StoreStrategy.SQLITE:
            return SQLiteStore(*args, **kwargs)
        else:
            raise ValueError(f"unsupported result store strategy: {self!r}")


class FlatFileStore(Store):
    def store(self, identifier: str, record: Envelope):
        filename = f"{identifier}.json"
        filepath = os.path.join(self.workspace.results_path, filename)

        # allow for nested directories controlled by the provider (for large sets of results)
        if os.sep in identifier:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

        if os.path.exists(filepath):
            if self.skip_duplicates and os.path.getmtime(filepath) >= self.start:
                self.logger.warning(f"{identifier!r} entry already written (skipping)")
                return
            self.logger.trace(f"overwriting existing file: {filepath!r}")

        with open(filepath, "wb") as f:
            self.logger.trace(f"writing record to {filepath!r}")
            f.write(orjson.dumps(asdict(record), f))  # type: ignore

    def close(self):
        pass


class SQLiteStore(Store):
    filename = "results.db"
    table_name = "results"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.conn = None
        self.engine = None
        self.table = None

        @db.event.listens_for(db.engine.Engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            # cursor.execute("pragma journal_mode=OFF")
            cursor.execute("PRAGMA synchronous=NORMAL")
            # cursor.execute("PRAGMA cache_size=100000")
            cursor.close()

    def connection(self):
        if not self.conn:
            self.engine = db.create_engine(f"sqlite:///{self.db_file_path}")
            self.conn = self.engine.connect()
            self.table = self._create_table()
        return self.conn, self.table

    @property
    def db_file_path(self):
        return os.path.join(self.workspace.results_path, self.filename)

    def _create_table(self):
        metadata = db.MetaData(self.engine)
        table = db.Table(
            self.table_name,
            metadata,
            db.Column("id", db.String(), primary_key=True, index=True),
            db.Column("record", db.LargeBinary()),
        )
        metadata.create_all()
        return table

    def store(self, identifier: str, record: Envelope):
        record_str = orjson.dumps(asdict(record))  # type: ignore
        conn, table = self.connection()

        # upsert the record conditionally based on the skip_duplicates configuration

        existing = conn.execute(table.select().where(table.c.id == identifier)).first()
        if existing:
            if self.skip_duplicates:
                self.logger.warning(f"{identifier!r} entry already written (skipping)")
                return
            self.logger.trace(f"overwriting existing entry: {identifier!r}")
            statement = db.update(table).where(table.c.id == identifier).values(record=record_str)
        else:
            statement = db.insert(table).values(id=identifier, record=record_str)

        conn.execute(statement)

    def close(self):
        if self.conn:
            self.conn.close()
            self.engine.dispose()

            self.conn = None
            self.engine = None
            self.table = None


class Writer:
    written: list[str]

    def __init__(  # noqa
        self,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        skip_duplicates: bool = False,
        clear_results_before_writing: bool = False,
        store_strategy: StoreStrategy = StoreStrategy.FLAT_FILE,
    ):
        self.workspace = workspace
        self.skip_duplicates = skip_duplicates
        self.clear_results_before_writing = clear_results_before_writing

        if not logger:
            logger = logging.getLogger("results-writer")
        self.logger = logger

        self.wrote = 0
        self.store = store_strategy.store(workspace=workspace, skip_duplicates=skip_duplicates, logger=logger)

    def __enter__(self) -> "Writer":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.store.close()
        self.logger.info(f"wrote {len(self)} entries")

    def __len__(self) -> int:
        return self.wrote

    def write(self, identifier: str, schema: Schema, payload: Any) -> None:
        self._clear_existing_results()

        envelope = Envelope(identifier=identifier, schema=schema.url, item=payload)

        self.store.store(identifier, envelope)

        self.wrote += 1

    def _clear_existing_results(self) -> None:
        if len(self) == 0 and self.clear_results_before_writing:
            self.workspace.clear_results()
