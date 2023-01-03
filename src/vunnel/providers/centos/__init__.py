import os
from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser, centos_config


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE)
    )
    skip_namespaces: list[str] = field(default_factory=lambda: ["centos:3", "centos:4"])
    request_timeout: int = 125


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {self.config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            config=centos_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "centos"

    def update(self) -> tuple[list[str], int]:
        # { (CVE, namespace): {...data...}" }

        # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
        vuln_dict = self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists)

        self.logger.info(f"processed {len(vuln_dict)} entries")

        with self.results_writer() as writer:
            for (vuln_id, namespace), (_, record) in vuln_dict.items():

                namespace = namespace.lower()
                vuln_id = vuln_id.lower()

                is_valid = vuln_id.startswith("rhsa")
                should_skip = namespace in self.config.skip_namespaces

                if is_valid and not should_skip:
                    writer.write(
                        identifier=os.path.join(namespace, vuln_id),
                        schema=self.schema,
                        payload=record,
                    )

        return self.parser.urls, len(writer)
