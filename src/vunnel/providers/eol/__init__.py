from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result
from vunnel.schema import EOLSchema

from .manager import Manager

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
    url: str = "https://endoflife.date/api/v1/products/full"


class Provider(provider.Provider):
    __schema__ = EOLSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.manager = Manager(
            url=self.config.url,
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "eol"

    @classmethod
    def tags(cls) -> list[str]:
        return ["auxiliary"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for product, cycle, record in self.manager.get():
                writer.write(
                    identifier=f"{product}:{cycle}".lower(),
                    schema=self.__schema__,
                    payload=record,
                )

        return self.manager.urls, len(writer)
