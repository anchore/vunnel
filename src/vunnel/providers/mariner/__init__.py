from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.providers.mariner.parser import Parser

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.KEEP,
        ),
    )
    request_timeout: int = 125
    allow_versions: list[str] = field(default_factory=lambda: ["2.0"])
    # api_key: str = "env:NVD_API_KEY"

    def __post_init__(self) -> None:
        pass
        # if self.api_key.startswith("env:"):
        #     self.api_key = os.environ.get(self.api_key[4:], "")

    def __str__(self) -> str:
        # sanitize secrets from any output
        # api_value = self.api_key
        # str_value = super().__str__()
        # if not api_value:
        #     return str_value
        # return str_value.replace(api_value, "********")
        return super().__str__()


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")
        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            allow_versions=self.config.allow_versions,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

        if self.config.runtime.skip_if_exists and config.runtime.existing_results != provider.ResultStatePolicy.KEEP:
            raise ValueError(
                "if 'skip_if_exists' is set then 'runtime.existing_results' must be 'keep' "
                "(otherwise incremental updates will fail)",
            )

    @classmethod
    def name(cls) -> str:
        return "mariner"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        self.logger.info("updating results in Mariner provider")
        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get():
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.schema,
                    payload=record,
                )
                pass
        return self.parser.urls, len(writer)
