from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace


class Parser:
    _release_ = "rolling"
    _advisories_dir = "echo-advisories"
    _advisories_filename = "data.json"

    def __init__(
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.download_timeout = download_timeout
        self.advisories_dir_path = Path(workspace.input_path) / self._advisories_dir
        self.url = url
        self.namespace = namespace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download(self) -> None:
        """
        Downloads echo advisories files
        :return:
        """
        if not os.path.exists(self.advisories_dir_path):
            os.makedirs(self.advisories_dir_path, exist_ok=True)

        try:
            self.logger.info(f"downloading {self.namespace} advisories {self.url}")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = self.advisories_dir_path / self._advisories_filename
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"Error downloading Echo advisories from {self.url}")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """
        Normalize all the advisories entries into vulnerability payload records
        :param release:
        :param advisories_data_dict:
        :return:
        """

        self.logger.debug("normalizing vulnerability data")

        vuln_dict = {}
        for package, package_cves in data.items():
            for cve_id, cve_info in package_cves.items():
                if cve_id not in vuln_dict:
                    record = copy.deepcopy(vulnerability.vulnerability_element)
                    record["Vulnerability"]["Name"] = cve_id
                    record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)
                    reference_links = vulnerability.build_reference_links(cve_id)
                    record["Vulnerability"]["Link"] = reference_links[0] if reference_links else ""
                    record["Vulnerability"]["Severity"] = cve_info.get("severity", "Unknown")
                    record["Vulnerability"]["FixedIn"] = []
                    vuln_dict[cve_id] = record
                cve_record = vuln_dict[cve_id]
                cve_record["Vulnerability"]["FixedIn"].append(  # type: ignore[union-attr]
                    {
                        "Name": package,
                        "Version": cve_info.get("fixed_version", ""),
                        "VersionFormat": "dpkg",
                        "NamespaceName": self.namespace + ":" + str(release),
                    },
                )
        return vuln_dict

    def get(self) -> Generator[tuple[str, dict[str, dict[str, Any]]], None, None]:
        """
        Download, load and normalize wolfi sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()
        with open(f"{self.advisories_dir_path}/{self._advisories_filename}") as fh:
            advisories_data_dict = orjson.loads(fh.read())

        yield self._release_, self._normalize(self._release_, advisories_data_dict)
