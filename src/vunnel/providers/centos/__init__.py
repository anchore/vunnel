from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .parser import Parser, centos_config

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    skip_namespaces: list[str] = field(default_factory=lambda: ["centos:3", "centos:4"])
    request_timeout: int = 125


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
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

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "centos"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        # { (CVE, namespace): {...data...}" }

        # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
        vuln_dict = self.parser.get()

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
