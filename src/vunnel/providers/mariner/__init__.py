from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.providers.mariner.parser import Parser
from vunnel.utils import timer

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
    allow_versions: list[str] = field(default_factory=lambda: ["1.0", "2.0", "3.0"])


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            allow_versions=self.config.allow_versions,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "mariner"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                for namespace, vuln_id, record in self.parser.get():
                    writer.write(
                        identifier=os.path.join(namespace, vuln_id),
                        schema=self.__schema__,
                        payload=record,
                    )
            return self.parser.urls, len(writer)
