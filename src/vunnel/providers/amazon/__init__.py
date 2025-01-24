from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vunnel import provider, result, schema

from .parser import Parser, amazon_security_advisories

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    security_advisories: dict[Any, str] = field(default_factory=lambda: amazon_security_advisories.copy())
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    max_allowed_alas_http_403: int = 25

    def __post_init__(self) -> None:
        self.security_advisories = {str(k): str(v) for k, v in self.security_advisories.items()}


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            security_advisories=config.security_advisories,
            download_timeout=config.request_timeout,
            logger=self.logger,
            max_allowed_alas_http_403=config.max_allowed_alas_http_403,
        )

    @classmethod
    def name(cls) -> str:
        return "amazon"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
            for vuln in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                namespace = vuln.NamespaceName.lower()
                vuln_id = vuln.Name.lower()

                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.__schema__,
                    payload={"Vulnerability": vuln.json()},
                )

        return self.parser.urls, len(writer)
