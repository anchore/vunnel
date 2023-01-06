import os
from dataclasses import dataclass, field
from typing import Any

from vunnel import provider, schema, result

from .parser import Parser, debian_distro_map


@dataclass
class Config:
    distro_map: dict[str, Any] = field(default_factory=lambda: debian_distro_map)
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125

    def __post_init__(self) -> None:
        self.distro_map = {str(k).lower(): str(v).lower() for k, v in self.distro_map.items()}


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            distro_map=self.config.distro_map,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "debian"

    def update(self) -> tuple[list[str], int]:

        with self.results_writer() as writer:
            # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
            for relno, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                vuln_id = vuln_id.lower()
                writer.write(
                    identifier=os.path.join(f"debian:{relno}", vuln_id),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls, len(writer)
