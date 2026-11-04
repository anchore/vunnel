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
    # Write the OSV feed instead of the secdb feed; set include_secdb to write both.
    use_osv: bool = False
    # Override with VUNNEL_PROVIDERS_CHAINGUARD_INCLUDE_SECDB
    # Requires use_osv. Also write the secdb feed, exactly as a secdb-only run would. Existing grype
    # clients need use_osv and include_secdb both set or both unset to produce correct results.
    include_secdb: bool = False


class Provider(provider.Provider):
    # NOTE: schema and distribution version are actually set on init depending
    # on which feed we configure the provider to use.
    # we use self._schema for this value
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    _namespace = "chainguard"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        if self.config.include_secdb and not self.config.use_osv:
            raise ValueError("include_secdb requires use_osv: without the OSV feed the secdb feed is already the one written")

        # the secdb feed, written alongside the OSV feed (see Config.include_secdb)
        self.secdb_parser: SecDBParser | None = None

        if self.config.use_osv:
            self.feed_url = self.config.osv_url
            self.parser: Parser = OSVParser(
                workspace=self.workspace,
                url=config.osv_url,
                namespace=self._namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
                skip_download=self.config.runtime.skip_download,
            )
            self._schema = schema.OSVSchema(version="1.7.0")
            if self.config.include_secdb:
                # exactly the parser a secdb-only run uses: same namespace, so the same identifiers,
                # records and fix-date lookups (ecosystem "chainguard:rolling")
                self.secdb_parser = SecDBParser(
                    workspace=self.workspace,
                    url=config.secdb_url,
                    namespace=self._namespace,
                    download_timeout=self.config.request_timeout,
                    logger=self.logger,
                    skip_download=self.config.runtime.skip_download,
                )
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
            self._schema = schema.OSSchema()

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
        self.logger.info(f"Using {'OSV' if self.config.use_osv else 'SecDB'} data source")
        feeds: list[tuple[Parser, schema.Schema, str]] = [(self.parser, self._schema, self.feed_url)]
        if self.secdb_parser:
            self.logger.info("Also writing the SecDB data source")
            feeds.append((self.secdb_parser, schema.OSSchema(), self.config.secdb_url))

        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                # both feeds share the namespace: OSV ids are CGA-* (OSV ids carry their database's prefix)
                # and secdb ids are upstream ids (CVE-*, GHSA-*, GO-*), so their identifiers don't overlap
                for parser, record_schema, _ in feeds:
                    with parser:
                        # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                        for release, vuln_dict in parser.get():
                            for vuln_id, record in vuln_dict.items():
                                writer.write(
                                    identifier=os.path.join(f"{self._namespace.lower()}:{release.lower()}", vuln_id),
                                    schema=record_schema,
                                    payload=record,
                                )

            return [url for _, _, url in feeds], len(writer)
