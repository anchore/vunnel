from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser, namespace


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    name = "wolfi"

    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.input,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    def update(self) -> list[str]:

        with self.results_writer() as writer:
            for release, vuln_dict in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                for vuln_id, record in vuln_dict.items():
                    writer.write(
                        identifier=f"{namespace}:{release}-{vuln_id}".lower(),
                        schema=self.schema,
                        payload=record,
                    )

        return self.parser.urls
