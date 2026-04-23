from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import Parser

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
    # When True, Wolfi vulnerability data is sourced from the Chainguard OSV feed
    # (packages.cgr.dev/chainguard/osv/) which includes both Chainguard and Wolfi packages
    # in each advisory record. In this mode the wolfi provider emits nothing — run the
    # chainguard provider instead to get Wolfi data.
    # When False (default), use the legacy secdb format from packages.wolfi.dev/os/security.json.
    use_osv: bool = False


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    _url = "https://packages.wolfi.dev/os/security.json"
    _namespace = "wolfi"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        if not config.use_osv:
            self.parser = Parser(
                workspace=self.workspace,
                url=self._url,
                namespace=self._namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )
            provider.disallow_existing_input_policy(config.runtime)
        else:
            self.parser = None

    @classmethod
    def name(cls) -> str:
        return "wolfi"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            if self.config.use_osv:
                self.logger.info(
                    "wolfi use_osv=True: Wolfi data is included in the chainguard OSV feed — "
                    "run the chainguard provider to get Wolfi vulnerability data. "
                    "This provider emits nothing in OSV mode."
                )
                return [self._url], 0

            with self.results_writer() as writer, self.parser:
                for release, vuln_dict in self.parser.get():
                    for vuln_id, record in vuln_dict.items():
                        writer.write(
                            identifier=os.path.join(f"{self._namespace.lower()}:{release.lower()}", vuln_id),
                            schema=self.__schema__,
                            payload=record,
                        )

            return [self._url], len(writer)
