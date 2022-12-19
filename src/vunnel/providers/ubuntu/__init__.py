from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125
    additional_versions: dict[str, str] = field(default_factory=lambda: {})
    enable_rev_history: bool = True


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.input,
            logger=self.logger,
            additional_versions=self.config.additional_versions,
            enable_rev_history=self.config.enable_rev_history,
        )

    @classmethod
    def name(cls) -> str:
        return "ubuntu"

    def update(self) -> list[str]:

        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                writer.write(
                    identifier=f"{namespace}-{vuln_id}".lower(),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls
