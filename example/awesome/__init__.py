from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .parser import Parser

if TYPE_CHECKING:
    import datetime

# NOTE, CHANGE ME!: a unique and semantically useful name for this provider
PROVIDER_NAME = "my-awesome-provider"

# NOTE, CHANGE ME!: the data shape that all entries produced by this provider conform to
SCHEMA = schema.OSSchema()


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125

    # NOTE, CHANGE ME!: Example for fetching secrets from the environment and sanitizing output.
    # It is important to sanitize the __str__ method so that these secrets are not accidentally
    # written to log output.
    #
    # token: str = "env:VUNNEL_AWESOME_TOKEN"
    #
    # def __post_init__(self) -> None:
    #     if self.token.startswith("env:"):
    #         self.token = os.environ.get(self.token[4:], "")
    #
    # def __str__(self) -> str:
    #     # sanitize secrets from any output
    #     tok_value = self.token
    #     str_value = super().__str__()
    #     if not tok_value:
    #         return str_value
    #     return str_value.replace(tok_value, "********")


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            ws=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
            # NOTE, CHANGE ME!: example of passing a config secret to the parser to download the vulnerability data
            # token=self.config.token
        )

        # this provider requires the previous state from former runs
        provider.disallow_existing_input_policy(config.runtime)

    @classmethod
    def name(cls) -> str:
        return PROVIDER_NAME

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:

        # NOTE: CHANGE ME! Why is last_updated passed in here? This allows you to be able to make decisions about
        # incremental updates of the existing vulnerability data state instead of needing to download all
        # vulnerability data from the source. For an example of this see the NVD provider implementation at
        # https://github.com/anchore/vunnel/blob/main/src/vunnel/providers/nvd/manager.py

        with self.results_writer() as writer:

            for vuln_id, record in self.parser.get():
                vuln_id = vuln_id.lower()

                writer.write(
                    identifier=vuln_id,
                    schema=SCHEMA,
                    payload=record,
                )

        return self.parser.urls, len(writer)
