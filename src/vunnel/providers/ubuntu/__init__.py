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


class Provider(provider.Provider):
    # processing-version: unchanged across the OSV rewrite. The on-disk input
    # layout differs from v3 but nothing useful carries over, so bumping this
    # would only churn caches.
    __version__ = 3

    __schema__ = schema.OSVSchema()
    # Distribution version stays at 1 (derived from major_version, which is "1" for
    # both OSSchema and OSVSchema). We deliberately do NOT bump this, even though
    # the envelope shape changes: every record carries its own schema URL in the
    # envelope (OSV records use the OSV URL, legacy passthrough preserves the OS URL),
    # so downstream can dispatch on per-record shape without a global bump signal.
    # Bumping this would trip provider.py's "version changed -> workspace.clear()"
    # logic and erase the operationally-critical input/legacy/ cache.
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if config is None:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        # The legacy passthrough cache under input/legacy/ is the only source of
        # records for releases Canonical has dropped from the OSV feed. Losing
        # it requires re-seeding from a frozen pre-rewrite production results.db,
        # which may not be readily available — guard against any policy that
        # lets the framework wipe input/.
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
