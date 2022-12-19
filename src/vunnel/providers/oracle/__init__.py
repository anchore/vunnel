from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser, ol_config


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.input,
            config=ol_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "oracle"

    def update(self) -> list[str]:

        with self.results_writer() as writer:
            vuln_dict = self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists)

            for (vuln_id, namespace), (_, record) in vuln_dict.items():
                writer.write(
                    identifier=f"{namespace}-{vuln_id}".lower(),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls
