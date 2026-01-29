from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import yaml

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from vunnel import workspace


class SecurityRejections:
    """
    Handles fetching and parsing security-rejections data from GitLab.

    The security-rejections repository contains CVEs that Alpine has determined
    do not affect Alpine packages (false positives). These are emitted as NAK
    entries with Version: "0" to filter NVD CPE matches.
    """

    _db_types = ("main", "community")

    def __init__(
        self,
        url: str,
        workspace: workspace.Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
    ):
        self.url = url.rstrip("/")
        self.workspace = workspace
        self.download_timeout = download_timeout
        if logger is None:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self._rejections_dir = os.path.join(workspace.input_path, "security-rejections")
        self._data: dict[str, dict[str, list[str]]] = {}  # {db_type: {package: [cve_ids]}}

    def download(self) -> None:
        """Download main.yaml and community.yaml from the security-rejections GitLab repo."""
        os.makedirs(self._rejections_dir, exist_ok=True)

        for db_type in self._db_types:
            file_name = f"{db_type}.yaml"
            download_url = f"{self.url}/{file_name}"
            file_path = os.path.join(self._rejections_dir, file_name)

            try:
                self.logger.info(f"downloading security-rejections {db_type} from: {download_url}")
                r = http.get(download_url, self.logger, stream=True, timeout=self.download_timeout)

                with open(file_path, "wb") as fp:
                    for chunk in r.iter_content():
                        fp.write(chunk)

            except Exception:
                self.logger.warning(f"failed to download security-rejections {db_type}, continuing without it", exc_info=True)

    def _load(self) -> None:
        """Load downloaded YAML files into memory."""
        self._data = {}

        for db_type in self._db_types:
            file_path = os.path.join(self._rejections_dir, f"{db_type}.yaml")
            if not os.path.exists(file_path):
                self.logger.debug(f"security-rejections file not found: {file_path}")
                continue

            try:
                with open(file_path) as fp:
                    yaml_data = yaml.safe_load(fp)

                if not yaml_data:
                    continue

                # The YAML structure is: {package_name: [cve_ids]}
                # e.g., {"dnsmasq": ["CVE-2021-45951", "CVE-2021-45952"]}
                rejections: dict[str, list[str]] = {}
                for package, cve_list in yaml_data.items():
                    if isinstance(cve_list, list):
                        rejections[package] = cve_list
                    else:
                        self.logger.warning(f"unexpected format for package {package} in {db_type}.yaml")

                self._data[db_type] = rejections
                self.logger.debug(f"loaded {len(rejections)} packages with rejections from {db_type}.yaml")

            except Exception:
                self.logger.warning(f"failed to parse security-rejections {db_type}.yaml, continuing without it", exc_info=True)

    def get(self, db_type: str) -> dict[str, list[str]]:
        """
        Return rejections for the given db_type as {package: [cve_ids]}.

        Args:
            db_type: The database type ("main" or "community")

        Returns:
            Dictionary mapping package names to lists of rejected CVE IDs
        """
        # Lazy-load data on first access
        if not self._data:
            self._load()

        return self._data.get(db_type, {})
