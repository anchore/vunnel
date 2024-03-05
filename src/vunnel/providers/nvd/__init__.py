from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from vunnel import provider, result, schema
from vunnel.providers.nvd.manager import Manager

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.KEEP,
        ),
    )
    request_timeout: int = 125
    api_key: Optional[str] = "env:NVD_API_KEY"  # noqa: UP007

    def __post_init__(self) -> None:
        if self.api_key and self.api_key.startswith("env:"):
            self.api_key = os.environ.get(self.api_key[4:], "")

    def __str__(self) -> str:
        # sanitize secrets from any output
        api_value = self.api_key
        str_value = super().__str__()
        if not api_value:
            return str_value
        return str_value.replace(api_value, "********")


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        if self.config.runtime.skip_if_exists and config.runtime.existing_results != result.ResultStatePolicy.KEEP:
            raise ValueError(
                "if 'skip_if_exists' is set then 'runtime.existing_results' must be 'keep' "
                "(otherwise incremental updates will fail)",
            )

        if self.config.runtime.result_store != result.StoreStrategy.SQLITE:
            raise ValueError(
                f"only 'SQLITE' is supported for 'runtime.result_store' but got '{self.config.runtime.result_store}'",
            )

        self.schema = schema.NVDSchema()
        self.manager = Manager(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            api_key=self.config.api_key,
            logger=self.logger,
            schema=self.schema,
        )

    @classmethod
    def name(cls) -> str:
        return "nvd"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        # with self.input_writer() as writer:
        #     for id, record in self.manager.download_nvd_input(
        #         last_updated=last_updated,
        #         skip_if_exists=self.config.runtime.skip_if_exists,
        #     ):
        #         writer.write(
        #             identifier=id.lower(),
        #             schema=self.schema,
        #             payload=record,
        #         )

        with self.results_writer() as writer, self.input_reader() as reader:
            # TODO: get the reader and connection from the input writer and pass that in
            # instead of the reader and connection from the results writer
            # reader: result.SQLiteStore = nvd_writer.store
            # conn, table = reader.connection()

            for identifier, record in self.manager.get(
                skip_if_exists=self.config.runtime.skip_if_exists,
                last_updated=last_updated,
            ):
                writer.write(
                    identifier=identifier.lower(),
                    schema=self.schema,
                    payload=record,
                )

        return self.manager.urls, len(writer)

    def input_writer(self) -> result.Writer:
        return result.Writer(
            workspace=self.workspace,
            result_state_policy=self.runtime_cfg.existing_results,
            logger=self.logger,
            store_strategy=self.runtime_cfg.result_store,
            write_location=os.path.join(self.workspace.input_path, 'nvd-input.db')
        )

    def input_reader(self) -> result.SQLiteReader:
        return result.SQLiteReader(
            sqlite_db_path=os.path.join(self.workspace.input_path, 'nvd-input.db')
        )
