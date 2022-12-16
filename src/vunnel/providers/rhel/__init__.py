from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125
    max_workers: int = 4
    full_sync_interval: int = 2
    skip_namespaces: list[str] = field(default_factory=lambda: ["rhel:3", "rhel:4"])


class Provider(provider.Provider):
    name = "rhel"

    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.input,
            download_timeout=self.config.request_timeout,
            max_workers=self.config.max_workers,
            full_sync_interval=self.config.full_sync_interval,
            skip_namespaces=self.config.skip_namespaces,
            logger=self.logger,
        )

    def update(self) -> list[str]:

        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                writer.write(
                    identifier=f"{namespace}-{vuln_id}".lower(),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls
