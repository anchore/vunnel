from __future__ import annotations

import os
from dataclasses import dataclass, field
from importlib import metadata
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .openvex_parser import OpenVEXParser

if TYPE_CHECKING:
    import datetime


def _default_user_agent() -> str:
    try:
        version = metadata.version("vunnel")
    except metadata.PackageNotFoundError:
        version = "unknown"
    return f"anchore/vunnel-{version}"


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            user_agent=_default_user_agent(),
        ),
    )
    request_timeout: int = 125
    openvex_url: str = "https://libraries.cgr.dev/openvex/v1/all.json"


class Provider(provider.Provider):
    __schema__ = schema.AnnotatedOpenVEXSchema()
    _namespace = "chainguard-libraries"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = OpenVEXParser(
            workspace=self.workspace,
            url=self.config.openvex_url,
            namespace=self._namespace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
            user_agent=self.runtime_cfg.user_agent,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "chainguard-libraries"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "language"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                for ecosystem, vuln_dict in self.parser.get():
                    for vuln_id, record in vuln_dict.items():
                        # TODO do we need separate identifiers by parser? Or will vuln_id never overlap
                        writer.write(
                            identifier=os.path.join(f"{self._namespace}:{ecosystem.lower()}", vuln_id),
                            schema=self.__schema__,
                            payload=record,
                        )

            return [self.config.openvex_url], len(writer)
