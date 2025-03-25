import logging
import os
from collections.abc import Generator
from pathlib import Path

import orjson

from vunnel.utils import http_wrapper


class Client:
    _default_api_path_ = "/api/v3/osv/"

    def __init__(
        self,
        download_path: str,
        logger: logging.Logger | None = None,
        rocky_versions: list[str] | None = None,
        api_host: str = "https://apollo.build.resf.org",
        skip_download: bool = False,
    ):
        if rocky_versions is None:
            rocky_versions = ["8", "9"]
        self.rocky_versions = rocky_versions
        self.api_host = api_host
        self.urls = [f"{api_host}{self._default_api_path_}"]
        if not logger:
            logger = logging.getLogger("rocky-linux-apollo-client")
        self.logger = logger
        self.download_path = download_path
        self._skip_download = skip_download

    def _download(self) -> None:
        next_page = self._default_api_path_
        while next_page:
            response = http_wrapper.get(f"{self.api_host}{next_page}", self.logger)
            response.raise_for_status()
            data = response.json()
            next_page = data["links"].get("next")
            advisories = data.get("advisories", [])
            for advisory in advisories:
                adv_id = advisory["id"].replace(":", "_")
                write_path = os.path.join(self.download_path, f"{adv_id}.json")
                with open(write_path, "wb") as f:
                    f.write(orjson.dumps(advisory))

    def get(self) -> Generator[Path, None, None]:
        os.makedirs(self.download_path, exist_ok=True)
        if not self._skip_download:
            self._download()
        else:
            self.logger.info("Skipping download of Rocky Linux advisories")
        downloads = Path(self.download_path)
        yield from sorted(downloads.rglob("*.json"))
