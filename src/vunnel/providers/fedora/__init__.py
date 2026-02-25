from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import Parser

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
    # Fedora releases to process (empty list = all from Bodhi API)
    releases: list[str] = field(default_factory=list)
    # Bodhi API base URL
    bodhi_url: str = "https://bodhi.fedoraproject.org"
    # Number of results per page when querying Bodhi API
    rows_per_page: int = 100


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
            config=config,
            logger=self.logger,
            user_agent=self.runtime_cfg.user_agent,
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "fedora"

    @classmethod
    def supports_skip_download(cls) -> bool:
        return True

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os", "incremental"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                for vuln_id, record in self.parser.get(
                    last_updated=last_updated,
                    skip_if_exists=self.config.runtime.skip_if_exists,
                ):
                    writer.write(
                        identifier=vuln_id.lower(),
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.parser.urls, len(writer)
