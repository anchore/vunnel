from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.providers.wolfi.parser import CGParser, Parser

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
    namespace: str = "chainguard"
    secdb_url: str = "https://packages.cgr.dev/chainguard/security.json"
    openvex_url: str = "https://packages.cgr.dev/chainguard/vex/all.json"


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parsers: dict[str, CGParser] = {}
        self.schemas: dict[str, schema.Schema] = {}
        if self.config.secdb_url != "":
            self.parsers["secdb"] = Parser(
                workspace=self.workspace,
                url=self.config.secdb_url,
                namespace=self.config.namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )
            self.schemas["secdb"] = schema.OSSchema()
        if self.config.openvex_url != "":
            self.parsers["openvex"] = OpenVEXParser(
                workspace=self.workspace,
                url=self.config.openvex_url,
                namespace=self.config.namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )
            self.schemas["openvex"] = schema.OpenVEXSchema()

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "chainguard"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        targets = []
        with self.results_writer() as writer:
            # For each parser, collect records
            for name, parser in self.parsers.items():
                # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                targets.append(parser.target_url)
                for release, vuln_dict in parser.get():
                    for vuln_id, record in vuln_dict.items():
                        # TODO do we need separate identifiers by parser? Or will vuln_id never overlap
                        writer.write(
                            identifier=os.path.join(f"{self.config.namespace.lower()}:{release.lower()}", vuln_id),
                            schema=self.schemas[name],
                            payload=record,
                        )

        return targets, len(writer)
