import json
import os
from dataclasses import dataclass, field

from vunnel import provider

from .data import CentOSDataProvider, centos_config


@dataclass(frozen=True)
class Config:
    skip_namespaces: list[str] = field(default_factory=lambda: ["centos:3", "centos:4"])
    request_timeout: int = 125
    use_existing_data: bool = True


class Provider(provider.Provider):
    name = "centos"

    def __init__(self, root: str, config: Config):
        super().__init__(root)
        self.config = config

    def update(self) -> list[str]:
        data_provider = CentOSDataProvider(
            workspace=self.workspace,
            config=centos_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )
        # { (CVE, namespace): {...data...}" }
        vuln_dict = data_provider.get(skip_if_exists=self.config.use_existing_data)

        self.logger.info(f"processed {len(vuln_dict)} entries")

        files = set()
        for key, value in vuln_dict.items():
            if key[1] not in self.config.skip_namespaces and key[0].lower().startswith("rhsa"):
                el = {"key": key[0], "namespace": key[1], "payload": value[1]}
                filename = os.path.join(self.results, f"{key[0].lower()}.json")

                # TODO(ALEX): we should put this back in
                # if filename in files:
                #     raise RuntimeError(f"filename {filename!r} already processed")

                with open(filename, "w", encoding="utf-8") as f:
                    self.logger.trace(f"writing {filename}")
                    json.dump(el, f)
                files.add(filename)

        self.logger.info(f"wrote {len(files)} entries")

        return data_provider.urls
