from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .openvex_parser import OpenVEXParser

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
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "chainguard-libraries"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        start_time = time.time()
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

        elapsed_time = time.time() - start_time
        self.logger.info(f"updating {self.name()} took {elapsed_time:.2f} seconds")
        return [self.config.openvex_url], len(writer)
