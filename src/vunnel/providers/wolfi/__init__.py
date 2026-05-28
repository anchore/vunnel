from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import SecDBParser

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
    # Override with VUNNEL_PROVIDERS_WOLFI_SECDB_URL
    secdb_url: str = "https://packages.wolfi.dev/os/security.json"
    # Override with VUNNEL_PROVIDERS_WOLFI_ENABLE
    # Enable allows us to switch to an OSV feed in the future if/when one becomes available
    enable: bool = True

class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    _namespace = "wolfi"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = SecDBParser(
            workspace=self.workspace,
            url=config.secdb_url,
            namespace=self._namespace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "wolfi"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        if not self.config.enable:
            self.logger.info("Provider is disabled via config, skipping update")
            return [], 0

        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                for release, vuln_dict in self.parser.get():
                    for vuln_id, record in vuln_dict.items():
                        writer.write(
                            identifier=os.path.join(f"{self._namespace.lower()}:{release.lower()}", vuln_id),
                            schema=self.__schema__,
                            payload=record,
                        )

            return [self.config.secdb_url], len(writer)
