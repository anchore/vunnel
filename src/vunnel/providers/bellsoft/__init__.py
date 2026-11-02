from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import PINNED_OSV_SCHEMA_VERSION, Parser

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
    # Upstream added the Alpaquita and BellSoft Hardened Containers ecosystems in
    # OSV schema 1.7.4. vunnel does not vendor 1.7.4, so 1.7.5 is the oldest
    # vendored schema that accepts these records.
    __schema__ = schema.OSVSchema(version=PINNED_OSV_SCHEMA_VERSION)
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            ws=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "bellsoft"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    @classmethod
    def compatible_schema(cls, schema_version: str) -> schema.Schema | None:
        # schema_version comes from upstream JSON, so it may not be a string.
        if not isinstance(schema_version, str) or not schema_version:
            return None
        # The envelope URL must name a schema file vunnel vendors. No BellSoft
        # record declares such a version, so this returns the pinned schema
        # rather than the record's.
        if schema.OSVSchema(schema_version).major_version == cls.__schema__.major_version:
            return cls.__schema__
        return None

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                for vuln_id, vuln_schema_version, record in self.parser.get():
                    vuln_schema = self.compatible_schema(vuln_schema_version)
                    if not vuln_schema:
                        self.logger.warning(
                            f"skipping vulnerability {vuln_id} with schema version {vuln_schema_version} "
                            f"as it is incompatible with provider schema version {self.__schema__.version}",
                        )
                        continue
                    writer.write(
                        identifier=vuln_id.lower(),
                        schema=vuln_schema,
                        payload=record,
                    )

            return self.parser.urls, len(writer)
