from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vunnel import provider, result, schema
from vunnel.tool import fixdate
from vunnel.utils import timer

from .csaf_advisory_client import SLESCSAFAdvisoryClient
from .csaf_client import SLESCSAFClient
from .csaf_parser import FixDates, downconvert_docs
from .parser import Parser

if TYPE_CHECKING:
    import datetime
    from collections.abc import Generator


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    allow_versions: list[Any] = field(default_factory=lambda: [11, 12, 15, 16])  # corresponds to major versions
    # Ingest SUSE's CSAF VEX feed instead of the legacy OVAL feed. CSAF is the richer,
    # continuously-updated source: it distinguishes plain vs LTSS support tracks (OVAL
    # folds them together), records an explicit won't-fix disposition OVAL has no way
    # to express, and streams straight out of one archive instead of a per-major-version
    # download. Default on; set False to fall back to the OVAL-based parser.
    use_csaf: bool = True

    def __post_init__(self) -> None:
        self.allow_versions = [str(v).lower() for v in self.allow_versions]


class Provider(provider.Provider):
    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.urls: list[str] = []

        self.parser: Parser | None = None
        self.csaf_client: SLESCSAFClient | None = None
        self.csaf_advisory_client: SLESCSAFAdvisoryClient | None = None
        self.fixdater: fixdate.Finder | None = None

        if self.config.use_csaf:
            self.csaf_client = SLESCSAFClient(
                workspace=self.workspace,
                logger=self.logger,
                download_timeout=self.config.request_timeout,
                skip_download=self.config.runtime.skip_download,
            )
            # the OVAL path dates its fixes through the same finder; the CSAF path must
            # too, or switching feeds silently drops FixedIn.Available entirely.
            self.fixdater = fixdate.default_finder(self.workspace)
            # the VEX feed carries no fix date of its own; the advisory feed is the only
            # place a real one exists.
            self.csaf_advisory_client = SLESCSAFAdvisoryClient(
                workspace=self.workspace,
                logger=self.logger,
                download_timeout=self.config.request_timeout,
                skip_download=self.config.runtime.skip_download,
            )
        else:
            self.parser = Parser(
                workspace=self.workspace,
                allow_versions=self.config.allow_versions,
                download_timeout=self.config.request_timeout,
                logger=self.logger,
            )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return "sles"

    @classmethod
    def tags(cls) -> list[str]:
        return [
            "vulnerability",
            "os",
            # this generates a large dataset and historically can take a while to process (long wall clock time)
            "large",
        ]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer:
                # the three CSAF collaborators are always constructed together
                if self.csaf_client is not None and self.csaf_advisory_client is not None and self.fixdater is not None:
                    csaf = self._get_csaf(self.csaf_client, self.csaf_advisory_client, self.fixdater)
                    for identifier, payload in csaf:
                        writer.write(identifier=identifier, schema=self.__schema__, payload=payload)
                    self.urls = [self.csaf_client.archive_url, self.csaf_advisory_client.archive_url]
                elif self.parser is not None:
                    with self.parser:
                        # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
                        for namespace, vuln_id, record in self.parser.get():
                            namespace = namespace.lower()
                            vuln_id = vuln_id.lower()
                            writer.write(
                                identifier=os.path.join(namespace, vuln_id),
                                schema=self.__schema__,
                                payload=record,
                            )
                    self.urls = self.parser.urls

            return self.urls, len(writer)

    def _get_csaf(
        self,
        csaf_client: SLESCSAFClient,
        advisory_client: SLESCSAFAdvisoryClient,
        finder: fixdate.Finder,
    ) -> Generator[tuple[str, dict[str, Any]]]:
        csaf_client.download()

        with finder as fixdater:
            fixdater.download()
            advisory_client.download()
            advisory_dates = advisory_client.fix_dates()

            for ns, cve_id, payload in downconvert_docs(
                csaf_client.iter_docs(),
                allow_versions=self.config.allow_versions,
                logger=self.logger,
                fix_dates=FixDates(fixdater, advisory_dates),
            ):
                yield os.path.join(ns.lower(), cve_id.lower()), payload
