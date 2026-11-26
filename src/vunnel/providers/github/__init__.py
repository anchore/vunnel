from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import Parser, RepoAdvisorySource

if TYPE_CHECKING:
    import datetime


@dataclass
class Config:
    # S105 is disabled for this line because the hard coded value is the name of an env var, not the value of the token
    token: str = "env:GITHUB_TOKEN"  # noqa: S105
    api_url: str = "https://api.github.com/graphql"
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    rest_api_url: str = "https://api.github.com"
    # repositories whose repository-scoped advisories are fetched in addition to the global
    # GitHub Advisory Database. Advisories of projects that aren't a package in a GHSA ecosystem
    # (e.g. language runtimes) have no usable ecosystem, so the entry names the syft package type
    # (and optionally the package name) to emit them under. When `ecosystem` is empty it is inferred
    # from each affected package's GHSA ecosystem instead, as for the global database. `package`
    # renames every affected package whatever its ecosystem, so pair it with `ecosystem`.
    repos: list[RepoAdvisorySource] = field(
        default_factory=lambda: [
            # the ruby interpreter is cataloged by syft as a binary package named "ruby"
            RepoAdvisorySource(repo="ruby/ruby", ecosystem="binary", package="ruby"),
        ],
    )

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
    # this is the version for the behavior of the provider (processing) not an indication of the data shape.
    __version__ = 2
    __schema__ = schema.GithubSecurityAdvisorySchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            workspace=self.workspace,
            token=config.token,
            api_url=config.api_url,
            download_timeout=config.request_timeout,
            logger=self.logger,
            repos=config.repos,
            rest_api_url=config.rest_api_url,
        )

    @classmethod
    def name(cls) -> str:
        return "github"

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "language", "incremental"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            namespace = "github"
            with self.results_writer() as writer, self.parser:
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
                            schema=self.__schema__,
                            payload={"Vulnerability": {}, "Advisory": dict(advisory)},
                        )

            return [self.parser.api_url], len(writer)
