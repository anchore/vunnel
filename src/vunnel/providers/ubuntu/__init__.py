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
    # Accepted so an existing config still loads, and read nowhere else: every record
    # is emitted in the v3 OS schema. The emit path assembles a release's disposition
    # from three sources, two of which can speak about a package the OSV record does
    # not carry, so there is no per-release OSV envelope left to hand out instead.
    # Setting it false logs a warning and changes nothing.
    downconvert_osv_to_os: bool = True
    # Also emit `ubuntu:X.YY+esm` distro-channel records for plain Ubuntu Pro (ESM),
    # carrying the real Pro fix version (mirrors RHEL EUS's `rhel:X.Y+eus`). Default
    # on. Set False for the frozen-v5 lane: its build isn't validated against `+esm`
    # channels, so it takes base records only.
    downconvert_emit_esm: bool = True


class Provider(provider.Provider):
    # processing-version: unchanged across the OSV rewrite. The on-disk input
    # layout differs from v3 but nothing useful carries over, so bumping this
    # would only churn caches.
    __version__ = 3

    __schema__ = schema.OSVSchema()
    # Distribution version stays at 1 (derived from major_version, which is "1" for
    # both OSSchema and OSVSchema). Bumping this trips provider.py's "version changed
    # -> workspace.clear()" logic, which would erase input/normalized-cve-data/ — the
    # frozen security-tracker snapshot, which nothing can rebuild and which is the only
    # source for every release the feeds do not carry. Per-envelope schema URLs are the
    # dispatch signal.
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if config is None:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        # input/ is operationally load-bearing: `normalized-cve-data/` is the frozen
        # security-tracker snapshot, the only source for every release the feeds do not
        # carry and for the fix versions they have stopped carrying, and nothing
        # regenerates it. Guard both the steady-state and on-error policies against
        # wiping input/.
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
            downconvert_emit_esm=self.config.downconvert_emit_esm,
        )

    @classmethod
    def name(cls) -> str:
        return "ubuntu"

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
            with self.results_writer() as writer, self.parser:
                for identifier, record_schema, payload in self.parser.get():
                    writer.write(
                        identifier=identifier.lower(),
                        schema=record_schema,
                        payload=payload,
                    )

            return self.parser.urls, len(writer)
