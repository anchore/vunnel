from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .manager import Manager

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_input=provider.InputStatePolicy.DELETE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    # there is historical data available organized by "YYYY-MM-DD", but we always default to "current" for the latest
    dataset: str = "current"
    url_template: str = "https://epss.cyentia.com/epss_scores-{}.csv.gz"
    request_timeout: int = 125


class Provider(provider.Provider):
    __schema__ = schema.EPSSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.manager = Manager(
            ws=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
            dataset=config.dataset,
            url_template=config.url_template,
        )

    @classmethod
    def name(cls) -> str:
        return "epss"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for vuln_id, record in self.manager.get():
                writer.write(
                    identifier=vuln_id.lower(),  # type: ignore[union-attr]
                    schema=self.__schema__,
                    payload=record,
                )

        return self.manager.urls, len(writer)
