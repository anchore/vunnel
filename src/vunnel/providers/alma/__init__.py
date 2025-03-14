from __future__ import annotations

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
    __schema__ = schema.OSVSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.schema = self.__schema__
        self.parser = Parser(
            ws=self.workspace,
            logger=self.logger,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "alma"

    @classmethod
    def compatible_schema(cls, schema_version: str) -> schema.Schema | None:
        candidate = schema.OSVSchema(schema_version)
        if candidate.major_version == cls.__schema__.major_version:
            return candidate
        return None

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        # TODO: use of last_updated as NVD provider does to avoid downloading all
        # vulnerability data from the source and make incremental updates instead
        with self.results_writer() as writer:
            for vuln_id, vuln_schema_version, record in self.parser.get():
                vuln_schema = self.compatible_schema(vuln_schema_version)
                if not vuln_schema:
                    self.logger.warning(
                        f"skipping vulnerability {vuln_id} with schema version {vuln_schema_version} ",
                        f"as is incompatible with provider schema version {self.schema.version}",
                    )
                    continue
                writer.write(
                    identifier=vuln_id.lower(),
                    schema=vuln_schema,
                    payload=record,
                )

        return self.parser.urls, len(writer)
