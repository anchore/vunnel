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

    def update(self) -> list[str]:
        parser = Parser(
            workspace=self.input,
            config=centos_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )
        # { (CVE, namespace): {...data...}" }
        vuln_dict = parser.get(skip_if_exists=self.config.runtime.existing_input == provider.InputStatePolicy.KEEP)

        self.logger.info(f"processed {len(vuln_dict)} entries")

        with self.results_writer() as writer:
            for (vuln_id, namespace), (_, record) in vuln_dict.items():
                if namespace.lower() not in self.config.skip_namespaces and vuln_id.lower().startswith("rhsa"):
                    writer.write(
                        identifier=f"{namespace}-{vuln_id}".lower(),
                        schema=schema.OSSchema(),
                        payload=record,
                    )

        return parser.urls
