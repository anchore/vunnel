from __future__ import annotations

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
            existing_input=provider.InputStatePolicy.KEEP,
        ),
    )
    request_timeout: int = 125
    # Compatibility switch: when True, OSV fragment envelopes are rewritten into the
    # v3 OS-schema `{"Vulnerability": {...}}` shape as they are yielded. Leave this off
    # unless you're feeding a grype-db build that pre-dates the OSV transformer — there
    # is no provenance for the inference and won't-fix annotations in the OS shape, so
    # downstream consumers lose that signal.
    downconvert_osv_to_os: bool = False


class Provider(provider.Provider):
    # processing-version: unchanged across the OSV rewrite. The on-disk input
    # layout differs from v3 but nothing useful carries over, so bumping this
    # would only churn caches.
    __version__ = 3

    __schema__ = schema.OSVSchema()
    # Distribution version stays at 1 (derived from major_version, which is "1" for
    # both OSSchema and OSVSchema). Bumping this trips provider.py's "version changed
    # -> workspace.clear()" logic, which would erase input/fragments/ (frozen OSV
    # state for releases that have dropped out of the feed) and input/normalized-cve-data/
    # (at-cutover EOL source). Per-envelope schema URLs are the dispatch signal.
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if config is None:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        # input/ is operationally load-bearing. Two things must survive between runs:
        #   - fragments/        : frozen per-ecosystem OSV state for releases no longer
        #                         in today's tarball. The only source for those releases.
        #   - normalized-cve-data/ : at-cutover EOL data (pre-OSV releases). Phase 1.
        # Guard both the steady-state and on-error policies against wiping input/.
        provider.disallow_existing_input_policy(config.runtime)
        if config.runtime.on_error.input != provider.InputStatePolicy.KEEP:
            raise ValueError(
                f"on_error.input policy is {config.runtime.on_error.input!r}; only 'keep' is allowed for the ubuntu provider",
            )

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
            downconvert_osv_to_os=self.config.downconvert_osv_to_os,
        )

    @classmethod
    def name(cls) -> str:
        return "ubuntu"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "os"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            with self.results_writer() as writer, self.parser:
                for identifier, record_schema, payload in self.parser.get():
                    writer.write(
                        identifier=identifier.lower(),
                        schema=record_schema,
                        payload=payload,
                    )

            return self.parser.urls, len(writer)
