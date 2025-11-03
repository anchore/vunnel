from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

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


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    _url = "https://api.root.io/external/cve_feed"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.parser = Parser(
            workspace=self.workspace,
            url=self._url,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "rootio"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        count = 0
        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get():
                writer.write(
                    identifier=os.path.join(namespace, vuln_id.lower()),
                    schema=self.__schema__,
                    payload=record,
                )
                count += 1

        return [self._url], count
