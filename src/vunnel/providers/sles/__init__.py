from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vunnel import provider, result, schema
from vunnel.utils import timer

from .csaf_parser import CSAFParser
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
    allow_versions: list[Any] = field(default_factory=lambda: [11, 12, 15])  # corresponds to major versions
    source: str = "CSAF"  # "OVAL" or "CSAF"

    def __post_init__(self) -> None:
        self.allow_versions = [str(v).lower() for v in self.allow_versions]


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    parser: Parser | CSAFParser
    _active_schema: schema.Schema

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        if self.config.source.upper() == "CSAF":
            self.parser = CSAFParser(
                workspace=self.workspace,
                allow_versions=self.config.allow_versions,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )
            self._active_schema = schema.CsafVexSchema()
        else:
            self.parser = Parser(
                workspace=self.workspace,
                allow_versions=self.config.allow_versions,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )
            self._active_schema = schema.OSSchema()
            # this provider requires the previous state from former runs (OVAL mode only)
            provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "sles"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                for namespace, vuln_id, record in self.parser.get():
                    namespace = namespace.lower()
                    vuln_id = vuln_id.lower()
                    writer.write(
                        identifier=os.path.join(namespace, vuln_id),
                        schema=self._active_schema,
                        payload=record,
                    )

            return self.parser.urls, len(writer)
