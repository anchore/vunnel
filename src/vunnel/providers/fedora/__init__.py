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
    request_timeout: int = 125
    # Fedora releases to process (empty list = auto-discover via Bodhi API)
    releases: list[str] = field(default_factory=list)
    # Include updates-testing repository (packages not yet pushed to stable)
    include_testing: bool = False
    # Base mirror URL for Fedora repositories (active releases)
    mirror_url: str = "https://dl.fedoraproject.org/pub/fedora/linux"
    # Archive URL for EOL releases
    archive_url: str = "https://archives.fedoraproject.org/pub/archive/fedora/linux"
    # Bodhi API URL for release discovery
    bodhi_url: str = "https://bodhi.fedoraproject.org"


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
            config=config,
            logger=self.logger,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "fedora"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                for vuln_id, record in self.parser.get():
                    writer.write(
                        identifier=vuln_id.lower(),
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.parser.urls, len(writer)
