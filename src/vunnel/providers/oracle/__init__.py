from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import Parser, ol_config

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
    # Oracle advisories can ship a different fix per architecture (e.g. an x86_64 and aarch64 build
    # respun at different revisions), which this provider records via the optional FixedIn.Arch
    # field added in OS schema 1.1.1. Other OS providers never emit Arch and stay on the default
    # OS schema version, so only Oracle advertises 1.1.1.
    __schema__ = schema.OSSchema(version="1.1.1")
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            config=ol_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "oracle"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                for (vuln_id, namespace), (_, record) in self.parser.get():
                    namespace = namespace.lower()
                    vuln_id = vuln_id.lower()

                    writer.write(
                        identifier=os.path.join(namespace, vuln_id),
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.parser.urls, len(writer)
