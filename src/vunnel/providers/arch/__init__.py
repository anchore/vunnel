from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

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
    api_url: str = "https://security.archlinux.org/all.json"
    request_timeout: int = 30


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {self.config}")

        self.parser = Parser(
            url=self.config.api_url,
            timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "arch"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        self.logger.info("Starting Arch Linux provider update")
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                count = 0
                for identifier, payload in self.parser.parse():
                    writer.write(
                        identifier=identifier,
                        schema=self.__schema__,
                        payload=payload,
                    )
                    count += 1

                self.logger.info(f"Update complete. Wrote {count} records")
                return [self.parser.url], count
