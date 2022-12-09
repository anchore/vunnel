import json
import os
from dataclasses import dataclass
from typing import Optional

from vunnel import provider

from .data import NVDDataProvider, namespace


@dataclass(frozen=True)
class Config:
    request_timeout: int = 125
    use_existing_data: bool = True
    start_year: int = 2002
    end_year: Optional[int] = None


class Provider(provider.Provider):
    name = "nvd"

    def __init__(self, root: str, config: Config):
        super().__init__(root)
        self.config = config

    def update(self) -> list[str]:
        data_provider = NVDDataProvider(
            workspace=self.workspace,
            download_timeout=self.config.request_timeout,
            start_year=self.config.start_year,
            end_year=self.config.end_year,
            logger=self.logger,
        )
        # { (CVE, namespace): {...data...}" }
        vuln_dict = data_provider.get(skip_if_exists=self.config.use_existing_data)

        # self.logger.info(f"processed {len(vuln_dict)} entries")
        group = f"{namespace}:cves"
        files = set()
        for cve_id, cve in vuln_dict:
            el = {"key": cve_id, "namespace": group, "payload": cve}
            filename = os.path.join(self.results, f"{cve_id.lower()}.json")

            # TODO(ALEX): we should put this back in
            # if filename in files:
            #     raise RuntimeError(f"filename {filename!r} already processed")

            with open(filename, "w", encoding="utf-8") as f:
                self.logger.trace(f"writing {filename}")
                json.dump(el, f)
            files.add(filename)

        self.logger.info(f"wrote {len(files)} entries")

        return data_provider.urls
