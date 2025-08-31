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
    _data_dir = "rootio-data"
    _data_filename = "cve_feed.json"

    def __init__(
        self,
        workspace: workspace.Workspace,
        url: str,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.download_timeout = download_timeout
        self.data_dir_path = Path(workspace.input_path) / self._data_dir
        self.url = url

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download(self) -> None:
        if not os.path.exists(self.data_dir_path):
            os.makedirs(self.data_dir_path, exist_ok=True)

        try:
            self.logger.info(f"downloading Root.io CVE feed from {self.url}")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = self.data_dir_path / self._data_filename
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"Error downloading Root.io data from {self.url}")
            raise

    def _normalize(self, distro_name: str, distro_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Transform Root.io data into OS schema format"""
        vuln_dict = {}

        distro_version = distro_data.get("distroversion", "unknown")
        namespace = f"rootio:distro:{distro_name}:{distro_version}"

        for package_data in distro_data.get("packages", []):
            pkg_info = package_data.get("pkg", {})
            package_name = pkg_info.get("name", "")

            for cve_id, cve_info in pkg_info.get("cves", {}).items():
                if cve_id not in vuln_dict:
                    record = copy.deepcopy(vulnerability.vulnerability_element)
                    record["Vulnerability"]["Name"] = cve_id
                    record["Vulnerability"]["NamespaceName"] = namespace

                    # Build reference links
                    reference_links = vulnerability.build_reference_links(cve_id)
                    record["Vulnerability"]["Link"] = reference_links[0] if reference_links else ""

                    record["Vulnerability"]["Severity"] = "Unknown"
                    record["Vulnerability"]["Description"] = f"Vulnerability {cve_id} in {package_name}"
                    record["Vulnerability"]["FixedIn"] = []
                    record["Vulnerability"]["Metadata"] = {
                        "CVE": [{"Name": cve_id, "Link": reference_links[0] if reference_links else ""}],
                    }
                    vuln_dict[cve_id] = record

                # Add fixed version info
                cve_record = vuln_dict[cve_id]
                fixed_versions = cve_info.get("fixed_versions", [])

                # Determine version format based on distro
                version_format = "dpkg"  # default
                if distro_name == "alpine":
                    version_format = "apk"
                elif distro_name in ["rhel", "centos", "rocky", "alma"]:
                    version_format = "rpm"

                for fixed_version in fixed_versions:
                    cve_record["Vulnerability"]["FixedIn"].append({
                        "Name": package_name,
                        "Version": fixed_version,
                        "VersionFormat": version_format,
                        "NamespaceName": namespace,
                        "VendorAdvisory": {"NoAdvisory": True},
                    })

                # If no fixed versions, add unfixed entry
                if not fixed_versions:
                    cve_record["Vulnerability"]["FixedIn"].append({
                        "Name": package_name,
                        "Version": "",  # Empty version indicates no fix available
                        "VersionFormat": version_format,
                        "NamespaceName": namespace,
                        "VendorAdvisory": {"NoAdvisory": True},
                    })

        return vuln_dict

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        """Download, parse and yield Root.io vulnerability records"""
        # Download the data
        self._download()

        # Load the JSON data
        with open(self.data_dir_path / self._data_filename) as fh:
            feed_data = orjson.loads(fh.read())

        # Process each distribution
        for distro_name, distro_list in feed_data.items():
            for distro_data in distro_list:
                distro_version = distro_data.get("distroversion", "unknown")
                namespace = f"rootio:distro:{distro_name}:{distro_version}"

                vuln_records = self._normalize(distro_name, distro_data)

                for vuln_id, record in vuln_records.items():
                    yield namespace, vuln_id, record
