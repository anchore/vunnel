import os
from dataclasses import dataclass, field

from vunnel import provider, schema, result

from .parser import Parser


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_input=provider.InputStatePolicy.KEEP,
        )
    )
    request_timeout: int = 125
    additional_versions: dict[str, str] = field(default_factory=lambda: {})
    enable_rev_history: bool = True
    max_workers: int = 5


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            logger=self.logger,
            additional_versions=self.config.additional_versions,
            enable_rev_history=self.config.enable_rev_history,
            max_workers=self.config.max_workers,
        )

    @classmethod
    def name(cls) -> str:
        return "ubuntu"

    def update(self) -> tuple[list[str], int]:

        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                namespace = namespace.lower()
                vuln_id = vuln_id.lower()
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.schema,
                    payload={"Vulnerability": record},
                )

        return self.parser.urls, len(writer)
