from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from vunnel import provider, result, schema
from vunnel.providers.nvd.manager import Manager

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.KEEP,
        ),
    )
    request_timeout: int = 125
    request_retry_count: int = 10
    api_key: Optional[str] = "env:NVD_API_KEY"  # noqa: UP007
    overrides_url: str = "https://github.com/anchore/nvd-data-overrides/archive/refs/heads/main.tar.gz"
    overrides_enabled: bool = False

    def __post_init__(self) -> None:
        if self.api_key and self.api_key.startswith("env:"):
            self.api_key = os.environ.get(self.api_key[4:], "")

    def __str__(self) -> str:
        # sanitize secrets from any output
        api_value = self.api_key
        str_value = super().__str__()
        if not api_value:
            return str_value
        return str_value.replace(api_value, "********")


class Provider(provider.Provider):
    # this is the version for the behavior of the provider (processing) not an indication of the data shape.
    __version__ = 2
    __schema__ = schema.NVDSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        if self.config.runtime.skip_if_exists and config.runtime.existing_results != result.ResultStatePolicy.KEEP:
            raise ValueError(
                "if 'skip_if_exists' is set then 'runtime.existing_results' must be 'keep' (otherwise incremental updates will fail)",
            )

        if self.config.runtime.result_store != result.StoreStrategy.SQLITE:
            raise ValueError(
                f"only 'SQLITE' is supported for 'runtime.result_store' but got '{self.config.runtime.result_store}'",
            )

        if self.config.overrides_enabled and not self.config.overrides_url:
            raise ValueError(
                "if 'overrides_enabled' is set then 'overrides_url' must be set",
            )

        self.manager = Manager(
            workspace=self.workspace,
            schema=self.__schema__,
            download_timeout=self.config.request_timeout,
            download_retry_count=self.config.request_retry_count,
            api_key=self.config.api_key,
            logger=self.logger,
            overrides_enabled=self.config.overrides_enabled,
            overrides_url=self.config.overrides_url,
        )

    @classmethod
    def name(cls) -> str:
        return "nvd"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for identifier, record in self.manager.get(
                skip_if_exists=self.config.runtime.skip_if_exists,
                last_updated=last_updated,
            ):
                writer.write(
                    identifier=identifier.lower(),
                    schema=self.__schema__,
                    payload=record,
                )

        return self.manager.urls, len(writer)
