from dataclasses import dataclass, field

from vunnel import provider, schema

from .parser import Parser


@dataclass(frozen=True)
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.InputStatePolicy.KEEP)
    )
    request_timeout: int = 125
    start_year: int = 2002
    end_year: int | None = None


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

    @classmethod
    def name(cls) -> str:
        return "nvd"

    def update(self) -> list[str]:
        parser = Parser(
            workspace=self.input,
            download_timeout=self.config.request_timeout,
            start_year=self.config.start_year,
            end_year=self.config.end_year,
            logger=self.logger,
        )

        vuln_tuples = parser.get(skip_if_exists=self.config.runtime.skip_if_exists)

        with self.results_writer(batch_size=500) as writer:
            for cve_id, cve in vuln_tuples:
                writer.write(
                    identifier=f"nvd-{cve_id}".lower(),
                    schema=schema.NVDSchema(),
                    payload=cve,
                )

        return parser.urls
