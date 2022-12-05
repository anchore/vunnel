import json
import os
from dataclasses import dataclass, field

from vunnel import provider

from .data import DataProvider, centos_config


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(existing_input=provider.ExistingStatePolicy.KEEP)
    )
    skip_namespaces: list[str] = field(default_factory=lambda: ["centos:3", "centos:4"])
    request_timeout: int = 125


class Provider(provider.Provider):
    name = "centos"

    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

    def update(self) -> list[str]:
        data_provider = DataProvider(
            workspace=self.input,
            config=centos_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )
        # { (CVE, namespace): {...data...}" }
        vuln_dict = data_provider.get(skip_if_exists=self.config.runtime.existing_input == provider.ExistingStatePolicy.KEEP)

        self.logger.info(f"processed {len(vuln_dict)} entries")

        files = set()
        for key, value in vuln_dict.items():
            if key[1] not in self.config.skip_namespaces and key[0].lower().startswith("rhsa"):
                el = {"key": key[0], "namespace": key[1], "payload": value[1]}
                filename = os.path.join(self.results, f"{key[0].lower()}.json")

                # TODO: there seems to be a lot of duplicates... is that intentional?
                if filename in files:
                    self.logger.warning(f"file {filename!r} already processed (skipping)")
                    continue

                with open(filename, "w", encoding="utf-8") as f:
                    self.logger.trace(f"writing {filename}")
                    json.dump(el, f)
                files.add(filename)

        self.logger.info(f"wrote {len(files)} entries")

        return data_provider.urls
