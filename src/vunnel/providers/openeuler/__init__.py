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
    rsync_base_url: str = "rsync://root@repo.openeuler.openatom.cn"


class Provider(provider.Provider):
    __schema__ = schema.CSAFVEXSchema()
    __distribution_version__ = int(__schema__.major_version)
    _url = "https://repo.openeuler.org/security/data/csaf/cve"
    _namespace = "openeuler"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            namespace=self._namespace,
            rsync_base_url=self.config.rsync_base_url,
            logger=self.logger,
            skip_download=self.config.runtime.skip_download,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "openeuler"

    @classmethod
    def supports_skip_download(cls) -> bool:
        return True

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for cve_id, csaf_doc in self.parser.get():
                writer.write(
                    identifier=os.path.join(self._namespace, cve_id),
                    schema=self.__schema__,
                    payload=csaf_doc,
                )
            if len(writer) == 0 and self.config.runtime.skip_download:
                raise RuntimeError("skip download used on empty workspace")
        return [self._url], len(writer)
