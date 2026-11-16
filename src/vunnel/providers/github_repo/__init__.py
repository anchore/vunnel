"""
GitHub repository advisories provider.

Tracks a configured list of GitHub repositories and emits their *published*
repository security advisories that have not yet been merged into the global
GitHub Advisory Database. GitHub's review of repository advisories can take
weeks; this provider closes that gap for selected repositories.

Records use the same schema and ``github:<ecosystem>`` namespaces as the
``github`` provider. Once an advisory is merged into the global database it is
no longer emitted here, and the ``github`` provider becomes its source.

Example configuration::

    providers:
      github_repo:
        token: env:GITHUB_TOKEN   # required: the merge check uses the GitHub GraphQL API
        repos:
          - netty/netty
          - https://github.com/FasterXML/jackson-databind
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vunnel import provider, result, schema
from vunnel.utils import timer

from .parser import DEFAULT_API_URL, Parser, normalize_repo

if TYPE_CHECKING:
    import datetime

PROVIDER_NAME = "github_repo"

# records share the namespace of the `github` provider so downstream consumers treat them identically
NAMESPACE = "github"


@dataclass
class Config:
    # S105 is disabled for this line because the hard coded value is the name of an env var, not the value of the token
    token: str = "env:GITHUB_TOKEN"  # noqa: S105
    api_url: str = DEFAULT_API_URL
    repos: list[str] = field(default_factory=list)

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

        # normalize and de-duplicate (preserving order); invalid entries fail fast
        self.repos = list(dict.fromkeys(normalize_repo(r) for r in self.repos or []))

    def __str__(self) -> str:
        # sanitize secrets from any output
        tok_value = self.token
        str_value = super().__str__()
        if not tok_value:
            return str_value
        return str_value.replace(tok_value, "********")


class Provider(provider.Provider):
    # this is the version for the behavior of the provider (processing) not an indication of the data shape.
    __version__ = 1
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
            repos=config.repos,
            api_url=config.api_url,
            download_timeout=config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return PROVIDER_NAME

    @classmethod
    def tags(cls) -> list[str]:
        return ["vulnerability", "language"]

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with timer(self.name(), self.logger):
            if not self.config.repos:
                self.logger.warning("no repositories configured, nothing to do")

            with self.results_writer() as writer, self.parser:
                for advisory in self.parser.get():
                    fixed_in = advisory.get("FixedIn")
                    all_fixes: list[dict[str, Any]] = copy.deepcopy(fixed_in) if isinstance(fixed_in, list) else []
                    for ecosystem in sorted(advisory.ecosystems or ()):
                        namespace = f"{NAMESPACE}:{ecosystem}".lower()
                        advisory["namespace"] = namespace

                        # filter the list of fixes for this ecosystem
                        advisory["FixedIn"] = [item for item in all_fixes if item.get("ecosystem") == ecosystem]

                        writer.write(
                            identifier=os.path.join(namespace, advisory["ghsaId"].lower()),
                            schema=self.__schema__,
                            payload={"Vulnerability": {}, "Advisory": dict(advisory)},
                        )

            return self.parser.urls, len(writer)
