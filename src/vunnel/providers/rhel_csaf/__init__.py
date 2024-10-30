import datetime
from dataclasses import dataclass, field

from vunnel import provider, result, schema

from .parser import Parser


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    parallelism: int = 4
    full_sync_interval: int = 2
    skip_namespaces: list[str] = field(default_factory=lambda: ["rhel:3", "rhel:4"])


class Provider(provider.Provider):

    __schema__ = schema.OSSchema()
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")
        self.parser = Parser(workspace=self.workspace, logger=self.logger)

    @classmethod
    def name(cls) -> str:
        return "rhel_csaf"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for namespace, vuln_id, record in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                namespace = namespace.lower()
                vuln_id = vuln_id.lower()
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.__schema__,
                    payload=record,
                )

        return self.parser.urls, len(writer)
