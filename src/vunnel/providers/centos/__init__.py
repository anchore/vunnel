from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser, centos_config


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    skip_namespaces: list[str] = field(default_factory=lambda: ["centos:3", "centos:4"])
    request_timeout: int = 125


class Provider(provider.Provider):
    name = "centos"

    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {self.config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.input,
            config=centos_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    def update(self) -> list[str]:
        # { (CVE, namespace): {...data...}" }
        vuln_dict = self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists)

        self.logger.info(f"processed {len(vuln_dict)} entries")

        with self.results_writer() as writer:
            for (vuln_id, namespace), (_, record) in vuln_dict.items():

                is_valid = vuln_id.lower().startswith("rhsa")
                should_skip = namespace.lower() in self.config.skip_namespaces

                if is_valid and not should_skip:
                    writer.write(
                        identifier=f"{namespace}-{vuln_id}".lower(),
                        schema=self.schema,
                        payload=record,
                    )

        return self.parser.urls
