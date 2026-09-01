"""RapidFort security advisories provider.

Ingests vulnerability data from the RapidFort security-advisories GitHub repo
for Ubuntu, Debian, Alpine, and Red Hat bases. Used when scanning RapidFort-curated
images (identified via maintainer metadata) to apply RapidFort-specific advisory
and version checks; release streams are emitted as OS channels (e.g.
rapidfort-redhat:9+fc43).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import Parser

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    repo_url: str = "https://github.com/rapidfort/security-advisories.git"


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug("config: %s", self.config)

        self.parser = Parser(
            workspace=self.workspace,
            logger=self.logger,
            repo_url=config.repo_url,
            timeout=config.request_timeout,
        )

        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "rapidfort"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                for namespace, vuln_dict in self.parser.get():
                    namespace = namespace.lower()
                    for vuln_id, record in vuln_dict.items():
                        vuln_id = vuln_id.lower()
                        writer.write(
                            identifier=os.path.join(namespace, vuln_id),
                            schema=self.__schema__,
                            payload=record,
                        )

            return self.parser.urls, len(writer)
