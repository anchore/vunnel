from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .manager import Manager

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
    url: str = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz"
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_input=provider.InputStatePolicy.DELETE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            user_agent=_default_user_agent(),
        ),
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    __schema__ = schema.CVE5Schema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.manager = Manager(
            url=self.config.url,
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            user_agent=self.config.runtime.user_agent,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "cve5"

    @classmethod
    def tags(cls) -> list[str]:
        return ["auxiliary"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                for identifier, record in self.manager.get():
                    writer.write(
                        identifier=identifier,
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.manager.urls, len(writer)
