from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.providers.wolfi.parser import OSVParser, Parser, SecDBParser
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
    use_osv: bool = True


class Provider(provider.Provider):
    # NOTE: records are written with the schema of the feed they came from (OS for secdb, OSV for osv);
    # __schema__ reflects the secdb feed, which is always processed
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    _namespace = "chainguard"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        # the secdb feed is always processed and written under chainguard:rolling. When use_osv is set, the
        # OSV feed is processed as well and written under chainguard:cga (see OSVParser._release_) so the two
        # data sets remain distinguishable downstream.
        self.parsers: list[tuple[Parser, schema.Schema]] = [
            (
                SecDBParser(
                    workspace=self.workspace,
                    url=config.secdb_url,
                    namespace=self._namespace,
                    download_timeout=self.config.request_timeout,
                    logger=self.logger,
                    skip_download=self.config.runtime.skip_download,
                ),
                schema.OSSchema(),
            ),
        ]

        if self.config.use_osv:
            self.parsers.append(
                (
                    OSVParser(
                        workspace=self.workspace,
                        url=config.osv_url,
                        namespace=self._namespace,
                        download_timeout=self.config.request_timeout,
                        logger=self.logger,
                        skip_download=self.config.runtime.skip_download,
                    ),
                    schema.OSVSchema(version="1.7.0"),
                ),
            )

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
        self.logger.info(f"Using {'SecDB and OSV' if self.config.use_osv else 'SecDB'} data sources")
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                # parsers run one at a time: each owns a fix date finder backed by the same workspace store
                for parser, record_schema in self.parsers:
                    with parser:
                        # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                        for release, vuln_dict in parser.get():
                            for vuln_id, record in vuln_dict.items():
                                writer.write(
                                    identifier=os.path.join(f"{self._namespace.lower()}:{release.lower()}", vuln_id),
                                    schema=record_schema,
                                    payload=record,
                                )

            return [parser.url for parser, _ in self.parsers], len(writer)
