from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .csaf_client import CSAFVEXClient
from .parser import Parser

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    parallelism: int = 16


class Provider(provider.Provider):
    __schema__ = schema.CSAFVEXSchema()
    __distribution_version__ = int(__schema__.major_version)

    _namespace = "hummingbird"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.urls = [CSAFVEXClient.default_url()]

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            logger=self.logger,
            max_workers=self.config.parallelism,
            skip_download=self.runtime_cfg.skip_download,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "hummingbird"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                for cve_id, record in self.parser.get():
                    writer.write(
                        identifier=os.path.join(self._namespace, cve_id),
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.urls, len(writer)
