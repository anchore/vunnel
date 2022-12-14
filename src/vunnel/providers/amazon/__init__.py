from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser, amazon_security_advisories


@dataclass
class Config:
    security_advisories: dict[str, str] = field(default_factory=lambda: amazon_security_advisories)
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    name = "amazon"

    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.input,
            security_advisories=config.security_advisories,
            download_timeout=config.request_timeout,
            logger=self.logger,
        )

    def update(self) -> list[str]:
        with self.results_writer() as writer:
            for vuln in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                writer.write(
                    identifier=f"{vuln.NamespaceName}-{vuln.Name}".lower(),
                    schema=self.schema,
                    payload={"Vulnerability": vuln.json()},
                )

        return self.parser.urls
