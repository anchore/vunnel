from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import OSV_SCHEMA_VERSION, Parser

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
    url: str = Parser._source_url_


class Provider(provider.Provider):
    __schema__ = schema.OSVSchema(version=OSV_SCHEMA_VERSION)
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            ws=self.workspace,
            url=self.config.url,
            download_timeout=self.config.request_timeout,
            skip_download=self.runtime_cfg.skip_download,
            logger=self.logger,
        )

        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "cpan"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "language"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                # records are authored here rather than passed through from upstream, so they are
                # always at this provider's schema version
                for vuln_id, record in self.parser.get():
                    writer.write(
                        identifier=vuln_id.lower(),
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.parser.urls, len(writer)
