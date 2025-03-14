import logging
import os
from collections.abc import Generator
from typing import Any

from vunnel import workspace
from vunnel.utils import http_wrapper as http


class Manager:
    def __init__(self, url: str, workspace: workspace.Workspace, download_timeout: int = 125, logger: logging.Logger | None = None):
        self.workspace = workspace
        self.download_timeout = download_timeout

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        if url:
            self._kev_url_ = url

    @property
    def urls(self) -> list[str]:
        return [self._kev_url_]

    def get(self) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        data = self._download()
        yield from self._parse(data)

    def _download(self) -> dict[str, Any]:
        dest = os.path.join(self.workspace.input_path, "kev.json")

        response = http.get(self._kev_url_, self.logger, timeout=self.download_timeout)
        with open(dest, "w") as f:
            f.write(response.text)
        return response.json()

    def _parse(self, catalog: dict[str, Any]) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        for record in catalog["vulnerabilities"]:
            yield record["cveID"], record
