import os
from dataclasses import dataclass, field
from typing import Any

from vunnel import provider, schema

from .parser import Parser


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE)
    )
    request_timeout: int = 125
    allow_versions: list[Any] = field(default_factory=lambda: [11, 12, 15])  # corresponds to major versions

    def __post_init__(self) -> None:
        self.allow_versions = [str(v).lower() for v in self.allow_versions]


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
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

    @classmethod
    def name(cls) -> str:
        return "sles"

    def update(self) -> tuple[list[str], int]:

        with self.results_writer() as writer:
            # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
            for namespace, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                namespace = namespace.lower()
                vuln_id = vuln_id.lower()
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls, len(writer)
