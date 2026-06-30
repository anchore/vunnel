from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.providers.wolfi.parser import OSVParser, SecDBParser
from vunnel.utils import timer

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
    # Override with VUNNEL_PROVIDERS_CHAINGUARD_SECDB_URL
    secdb_url: str = "https://packages.cgr.dev/chainguard/security.json"
    # Override with VUNNEL_PROVIDERS_CHAINGUARD_OSV_URL
    osv_url: str = "https://advisories.cgr.dev/chainguard/v3/osv/chainguard-osv.tar.gz"
    # Override with VUNNEL_PROVIDERS_CHAINGUARD_USE_OSV
    use_osv: bool = False


class Provider(provider.Provider):
    # NOTE: schema and distribution version are actually set on init depending
    # on which feed we configure the provider to use.
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    _namespace = "chainguard"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        if self.config.use_osv:
            self.logger.info("Using OSV data source")
            self.feed_url = self.config.osv_url
            self.parser = OSVParser(
                workspace=self.workspace,
                url=config.osv_url,
                namespace=self._namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
                skip_download=self.config.runtime.skip_download,
            )
            self.schema = schema.OSVSchema(version="1.7.0")
        else:
            self.parser = SecDBParser(
                workspace=self.workspace,
                url=config.secdb_url,
                namespace=self._namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
                skip_download=self.config.runtime.skip_download,
            )
            self.feed_url = self.config.secdb_url
            self.schema = schema.OSSchema()

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "chainguard"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    @classmethod
    def supports_skip_download(cls) -> bool:
        return True

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                for release, vuln_dict in self.parser.get():
                    for vuln_id, record in vuln_dict.items():
                        writer.write(
                            identifier=os.path.join(f"{self._namespace.lower()}:{release.lower()}", vuln_id),
                            schema=self.schema,
                            payload=record,
                        )

            return [self.feed_url], len(writer)
