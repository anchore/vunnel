import copy
import os
from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser, namespace


@dataclass
class Config:
    token: str = "env:GITHUB_TOKEN"
    api_url: str = "https://api.github.com/graphql"
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125

    def __post_init__(self):
        if self.token.startswith("env:"):
            self.token = os.environ.get(self.token[4:], "")

    def __str__(self):
        # sanitize secrets from any output
        tok_value = self.token
        str_value = super().__str__()
        if not tok_value:
            return str_value
        return str_value.replace(tok_value, "********")


class Provider(provider.Provider):
    name = "github"

    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.GithubSecurityAdvisorySchema()
        self.parser = Parser(
            workspace=self.input,
            token=config.token,
            api_url=config.api_url,
            download_timeout=config.request_timeout,
            logger=self.logger,
        )

    def update(self) -> list[str]:

        with self.results_writer() as writer:
            for advisory in self.parser.get():
                all_fixes = copy.deepcopy(advisory.get("FixedIn")) if isinstance(advisory.get("FixedIn"), list) else []
                for ecosystem in advisory.ecosystems:

                    advisory["namespace"] = f"{namespace}:{ecosystem}"

                    # filter the list of fixes for this ecosystem
                    advisory["FixedIn"] = [item for item in all_fixes if item.get("ecosystem") == ecosystem]

                    vuln_id = advisory["ghsaId"]

                    writer.write(
                        identifier=f"{namespace}-{ecosystem}-{vuln_id}".lower(),
                        schema=self.schema,
                        payload={"Vulnerability": {}, "Advisory": dict(advisory)},
                    )

        return [self.parser.api_url]
