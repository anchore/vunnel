from dataclasses import dataclass, field
from typing import Any

from vunnel import provider, schema

from .parser import Parser, debian_distro_map, namespace


@dataclass
class Config:
    distro_map: dict[str, Any] = field(default_factory=lambda: debian_distro_map)
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
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
            workspace=self.input,
            download_timeout=self.config.request_timeout,
            distro_map=self.config.distro_map,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "debian"

    def update(self) -> list[str]:

        with self.results_writer() as writer:
            for relno, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                writer.write(
                    identifier=f"{namespace}-{relno}-{vuln_id}".lower(),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls
