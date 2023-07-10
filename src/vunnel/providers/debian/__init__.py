from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vunnel import provider, result, schema

from .parser import Parser, debian_distro_map

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    releases: dict[str, Any] = field(default_factory=lambda: debian_distro_map.copy())
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125

    def __post_init__(self) -> None:
        self.releases = {str(k).lower(): str(v).lower() for k, v in self.releases.items()}


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            distro_map=self.config.releases,
            logger=self.logger,
        )

        # this provider requires the previous state from former runs
        # note: we MUST keep the input directory, since it may have out-of-band updates to support
        # legacy vulns that are not in the Debian security tracker anymore.
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "debian"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
            for relno, vuln_id, record in self.parser.get():
                vuln_id = vuln_id.lower()
                writer.write(
                    identifier=os.path.join(f"debian:{relno}", vuln_id),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls, len(writer)
