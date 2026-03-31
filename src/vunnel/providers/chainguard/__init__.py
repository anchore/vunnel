from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import orjson
import requests

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
    # Base URL for the OSV feed. The index is fetched from {osv_base_url}/all.json
    # and individual records from {osv_base_url}/{id}.json.
    osv_base_url: str = "https://packages.cgr.dev/chainguard/osv"


class Provider(provider.Provider):
    _secdb_schema = schema.OSSchema()
    _osv_schema = schema.OSVSchema(version="1.7.0")

    __schema__ = _secdb_schema
    __distribution_version__ = int(__schema__.major_version)

    _secdb_url = "https://packages.cgr.dev/chainguard/security.json"
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
        base_url = self.config.osv_base_url.rstrip("/")
        index_url = f"{base_url}/all.json"

        # Fetch the index first. If this fails, the feed is fundamentally unusable.
        self.logger.info(f"downloading Chainguard OSV index from {index_url}")
        try:
            resp = http.get(index_url, self.logger, timeout=self.config.request_timeout)
            index = orjson.loads(resp.content)
        except requests.RequestException as e:
            raise RuntimeError(f"failed to fetch Chainguard OSV index from {index_url}: {e}") from e
        except orjson.JSONDecodeError as e:
            raise RuntimeError(f"Chainguard OSV index at {index_url} contains invalid JSON: {e}") from e

        # The index must be a list of entries. A dict, null, or other type indicates
        # a malformed feed that would silently produce zero results if not caught.
        if not isinstance(index, list):
            raise RuntimeError(
                f"Chainguard OSV index at {index_url} has invalid structure: "
                f"expected a list, got {type(index).__name__}"
            )

        self.logger.info(f"fetching {len(index)} Chainguard OSV records")

        with self.results_writer() as writer:
            for i, entry in enumerate(index):
                # Each entry must be a dict with an "id" field. Validate both
                # to catch malformed feeds early with clear error messages.
                if not isinstance(entry, dict):
                    raise RuntimeError(
                        f"Chainguard OSV index entry {i} has invalid type: "
                        f"expected dict, got {type(entry).__name__}. Entry contents: {entry!r}"
                    )
                if "id" not in entry:
                    raise RuntimeError(
                        f"Chainguard OSV index entry {i} is missing required 'id' field. "
                        f"Entry contents: {entry}"
                    )
                record_id = entry["id"]
                record_url = f"{base_url}/{record_id}.json"

                # Fetch and parse the record. Any failure here is fatal - we cannot
                # produce a partial feed with missing entries, as downstream consumers
                # would have no way to know data is missing.
                try:
                    record_resp = http.get(record_url, self.logger, timeout=self.config.request_timeout)
                except requests.RequestException as e:
                    raise RuntimeError(
                        f"failed to fetch Chainguard OSV record {record_id} from {record_url}: {e}"
                    ) from e

                try:
                    record = orjson.loads(record_resp.content)
                except orjson.JSONDecodeError as e:
                    raise RuntimeError(
                        f"Chainguard OSV record {record_id} at {record_url} contains invalid JSON: {e}"
                    ) from e

                writer.write(
                    identifier=record_id.lower(),
                    schema=self._osv_schema,
                    payload=record,
                )

        return [index_url], len(writer)

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
