from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .parser import Parser

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    token: str = "env:GITHUB_TOKEN"
    api_url: str = "https://api.github.com/graphql"
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125

    def __post_init__(self) -> None:
        if self.token.startswith("env:"):
            self.token = os.environ.get(self.token[4:], "")

    def __str__(self) -> str:
        # sanitize secrets from any output
        tok_value = self.token
        str_value = super().__str__()
        if not tok_value:
            return str_value
        return str_value.replace(tok_value, "********")


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.GithubSecurityAdvisorySchema()
        self.parser = Parser(
            workspace=self.workspace,
            token=config.token,
            api_url=config.api_url,
            download_timeout=config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "github"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        namespace = "github"
        with self.results_writer() as writer:
            for advisory in self.parser.get():
                all_fixes = copy.deepcopy(advisory.get("FixedIn")) if isinstance(advisory.get("FixedIn"), list) else []
                for ecosystem in advisory.ecosystems:
                    advisory["namespace"] = f"{namespace}:{ecosystem}"

                    # filter the list of fixes for this ecosystem
                    advisory["FixedIn"] = [item for item in all_fixes if item.get("ecosystem") == ecosystem]

                    vuln_id = advisory["ghsaId"]

                    namespace = namespace.lower()
                    ecosystem = ecosystem.lower()
                    vuln_id = vuln_id.lower()

                    writer.write(
                        identifier=os.path.join(f"{namespace}:{ecosystem}", vuln_id),
                        schema=self.schema,
                        payload={"Vulnerability": {}, "Advisory": dict(advisory)},
                    )

        return [self.parser.api_url], len(writer)
