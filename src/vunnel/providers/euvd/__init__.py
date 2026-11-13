"""ENISA EU Vulnerability Database (EUVD) provider.

EUVD is the European Union's vulnerability registry, published by ENISA. The
public search API (https://euvd.enisa.europa.eu/apidoc) became fully available
in early 2026 and is the data source NIS2/CRA-aligned consumers rely on for
EU-coordinated vulnerability identifiers and CVSS evaluations.

This provider feeds normalized EUVD records into the vunnel cache so
downstream tools (e.g. grype) can surface ENISA EUVD identifiers and ENISA
CVSS evaluations alongside CVE/GHSA matches. It does not perform any package
matching itself; like the KEV provider it is metadata-only and tagged
``auxiliary``.

Tracking: https://github.com/anchore/vunnel/issues/915
Tracking (grype side): https://github.com/anchore/grype/issues/2601
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .manager import DEFAULT_URL, Manager

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    url: str = DEFAULT_URL
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_input=provider.InputStatePolicy.DELETE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    __schema__ = schema.EUVDSchema()
    __distribution_version__ = int(__schema__.major_version)

    _namespace = "euvd"

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
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "euvd"

    @classmethod
    def tags(cls) -> list[str]:
        # Auxiliary, like the KEV provider — the data is enrichment metadata for
        # records sourced from NVD/GHSA/OSV, not a primary match feed.
        return ["auxiliary"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                for vuln_id, record in self.manager.get(last_updated=last_updated):
                    writer.write(
                        identifier=f"{self._namespace}:{vuln_id.lower()}",
                        schema=self.__schema__,
                        payload=record,
                    )

            return self.manager.urls, len(writer)
