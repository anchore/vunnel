import os
from dataclasses import dataclass, field

from vunnel import provider, schema, result

from .parser import Parser


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {self.config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "alpine"

    def update(self) -> tuple[list[str], int]:

        with self.results_writer() as writer:
            # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
            for namespace, vulns in self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists):
                namespace = namespace.lower()
                for vuln_id, record in vulns.items():
                    vuln_id = vuln_id.lower()
                    writer.write(
                        identifier=os.path.join(namespace, vuln_id),
                        schema=self.schema,
                        payload=record,
                    )

        return self.parser.urls, len(writer)
