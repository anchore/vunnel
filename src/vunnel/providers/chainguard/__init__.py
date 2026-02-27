from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import orjson

from vunnel import provider, result, schema
from vunnel.utils import http_wrapper as http, timer
from vunnel.providers.wolfi.parser import Parser

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
    # When True, fetch from the Chainguard OSV endpoint which provides per-package
    # granularity for both Chainguard and Wolfi ecosystems. When False (default), use the
    # legacy secdb format from packages.cgr.dev/chainguard/security.json.
    use_osv: bool = False


class Provider(provider.Provider):
    _secdb_schema = schema.OSSchema()
    _osv_schema = schema.OSVSchema()

    __schema__ = _secdb_schema
    __distribution_version__ = int(__schema__.major_version)

    _secdb_url = "https://packages.cgr.dev/chainguard/security.json"
    _osv_index_url = "https://packages.cgr.dev/chainguard/osv/all.json"
    _osv_record_url_template = "https://packages.cgr.dev/chainguard/osv/{id}.json"
    _namespace = "chainguard"

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        if not config.use_osv:
            # secdb path: reuse the wolfi parser (same format, different URL/namespace)
            self.parser = Parser(
                workspace=self.workspace,
                url=self._secdb_url,
                namespace=self._namespace,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )
            provider.disallow_existing_input_policy(config.runtime)
        else:
            self.parser = None

    @classmethod
    def name(cls) -> str:
        return "chainguard"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            if self.config.use_osv:
                return self._update_osv()
            else:
                return self._update_secdb()

    def _update_osv(self) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            self.logger.info(f"downloading Chainguard OSV index from {self._osv_index_url}")
            resp = http.get(self._osv_index_url, self.logger, timeout=self.config.request_timeout)
            index = orjson.loads(resp.content)

            self.logger.info(f"fetching {len(index)} Chainguard OSV records")
            for entry in index:
                record_id = entry["id"]
                record_url = self._osv_record_url_template.format(id=record_id)

                try:
                    record_resp = http.get(record_url, self.logger, timeout=self.config.request_timeout)
                    record = orjson.loads(record_resp.content)

                    writer.write(
                        identifier=record_id.lower(),
                        schema=self._osv_schema,
                        payload=record,
                    )
                except Exception:
                    self.logger.exception(f"failed to fetch Chainguard OSV record {record_id}")

        return [self._osv_index_url], len(writer)

    def _update_secdb(self) -> tuple[list[str], int]:
        with self.results_writer() as writer, self.parser:
            for release, vuln_dict in self.parser.get():
                for vuln_id, record in vuln_dict.items():
                    writer.write(
                        identifier=os.path.join(f"{self._namespace.lower()}:{release.lower()}", vuln_id),
                        schema=self._secdb_schema,
                        payload=record,
                    )

        return [self._secdb_url], len(writer)
