from __future__ import annotations

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
    repository_url: str = "https://github.com/docker-hardened-images/advisories.git"
    repository_branch: str = "main"
    advisories_path: str = "osv/dhi"


class Provider(provider.Provider):
    __schema__ = schema.OSVSchema(version="1.6.1")
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if config is None:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.parser = Parser(
            ws=self.workspace,
            repository_url=config.repository_url,
            repository_branch=config.repository_branch,
            advisories_path=config.advisories_path,
            skip_download=config.runtime.skip_download,
            logger=self.logger,
        )
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "dhi"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    @classmethod
    def supports_skip_download(cls) -> bool:
        return True

    @classmethod
    def compatible_schema(cls, schema_version: str) -> schema.Schema | None:
        candidate = schema.OSVSchema(schema_version)
        if candidate.major_version == cls.__schema__.major_version:
            return candidate
        return None

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                for vuln_id, schema_version, record in self.parser.get():
                    vuln_schema = self.compatible_schema(schema_version)
                    if vuln_schema is None:
                        raise ValueError(
                            f"DHI advisory {vuln_id} uses unsupported OSV schema version {schema_version}",
                        )
                    writer.write(identifier=vuln_id.lower(), schema=vuln_schema, payload=record)
            return self.parser.urls, len(writer)
