from __future__ import annotations

import copy
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson
from cvss import CVSS3
from tqdm import tqdm

from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    import requests

    from vunnel import workspace


class Parser:
    _vuln_dir = "cves"
    _vuln_index = "index.txt"

    def __init__( # noqa: PLR0913
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        max_workers: int | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.download_timeout = download_timeout
        self.advisories_dir_path = Path(workspace.input_path) / self._vuln_dir
        self.max_workers = max_workers if isinstance(max_workers, int) else 8
        self.url = url
        self.namespace = namespace
        self.cves: list[str] = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _fetch_data(self, url: str) -> requests.Response:
        return http.get(f"{self.url}/{url}", self.logger, stream=True, timeout=self.download_timeout)

    def _download(self) -> None:
        """
        Downloads openEuler advisories files
        :return:
        """
        # download cve index.txt
        try:
            self.logger.info(f"downloading {self.namespace} cve index.txt")
            files = self._fetch_data(self._vuln_index).text.splitlines()
        except Exception:
            self.logger.exception(f"Error downloading {self.namespace} advisories from {self.url}")
            raise
        # download all cve files, for example, `2025/csaf-openeuler-cve-2025-0237.json`
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._fetch_data, file): file for file in files}
            for future in tqdm(as_completed(futures), total=len(files), desc=f"Downloading {self.namespace} CVE files"):
                file = futures[future]
                try:
                    data = future.result()
                    if not data:
                        continue
                    # store cves by year
                    year = file.split("/")[0]
                    if not os.path.exists(self.advisories_dir_path / year):
                        os.makedirs(self.advisories_dir_path / year, exist_ok=True)
                    # write into json files
                    cve_file = self.advisories_dir_path / file
                    with open(cve_file, "wb") as fp:
                        fp.write(data.content)
                    # record all stored file paths
                    self.cves.append(file)
                except Exception as e:
                    self.logger.warning(f"Failed to download {file}: {e}")

    def _get_cve_link(self, references: list[dict[str, str]], cve_id: str) -> str:
        for ref in references:
            if ref.get("category") == "self" and cve_id == ref.get("summary", ""):
                return ref.get("url", "")
        return ""

    def _get_cve_description(self, notes: list[dict[str, str]]) -> str:
        for note in notes:
            if note.get("category") == "description":
                return note.get("text", "")
        return ""

    def _parse_cve_file(self, cve: str) -> dict[str, Any]:
        # parse cve file
        with open(f"{self.advisories_dir_path}/{cve}") as f:
            root = orjson.loads(f.read())

        # each cve file records only one cve
        vuln = root.get("vulnerabilities", [])[0]
        if not vuln:
            return {}

        # record cve for all namespaces
        cve_record: dict[str, Any] = {}

        vuln_name = vuln.get("cve")
        vuln_link = self._get_cve_link(references=root.get("document", {}).get("references", []), cve_id=vuln_name)
        vuln_desc = self._get_cve_description(notes=vuln.get("notes", []))
        vuln_cvss = []
        vuln_seve = ""
        cvss_raw = vuln.get("scores", [])[0].get("cvss_v3", {})
        if cvss_raw:
            cvss_vector = cvss_raw.get("vectorString")
            cvss_obj = CVSS3(cvss_vector)
            vuln_seve = cvss_raw.get("baseSeverity")
            vuln_cvss.append(
                {
                    "base_metrics": {
                        "base_score": float(cvss_raw.get("baseScore")),
                        "exploitability_score": float(cvss_obj.esc.quantize(Decimal("0.1"))),
                        "impact_score": float(cvss_obj.isc.quantize(Decimal("0.1"))),
                        "base_severity": vuln_seve,
                    },
                    "status": cvss_raw.get("status", ""),
                    "vector_string": cvss_vector,
                    "version": cvss_raw.get("version"),
                },
            )

        # store cves by openEuler releases
        for pkg in vuln.get("product_status")["fixed"]:
            # only `.src` packages are used
            if not pkg.endswith(".src"):
                continue
            # Get openEuler version from fixed product (e.g., "openEuler-22.03-LTS-SP3:kernel-5.10.0-200.0.0.113.oe2203sp3.src")
            os_full_name = pkg.split(":")[0]  # e.g., openEuler-22.03-LTS-SP3
            release = os_full_name.split("-", maxsplit=1)[-1]  # e.g., 22.03-LTS-SP3
            namespace = f"{self.namespace}:{release}"  # e.g., openeuler:22.03-lts-sp3
            # use `{namespace}/{vuln_name}`` to donete the unique cve, e.g., openeuler:22.03-LTS-SP3/CVE-2025-0237
            full_namespace = f"{namespace}/{vuln_name}"
            if full_namespace not in cve_record:
                v = copy.deepcopy(vulnerability.vulnerability_element)
                v["Vulnerability"]["Name"] = vuln_name
                v["Vulnerability"]["Link"] = vuln_link
                v["Vulnerability"]["Description"] = vuln_desc
                v["Vulnerability"]["Severity"] = vuln_seve
                v["Vulnerability"]["CVSS"] = vuln_cvss
                v["Vulnerability"]["NamespaceName"] = namespace
                v["Vulnerability"]["FixedIn"] = []
                cve_record[full_namespace] = v

            # Get fixed package name (e.g., kernel-5.10.0-200.0.0.113.oe2203sp3.src)
            full_fixed_name = pkg.split(":")[1]
            pkg_parts = full_fixed_name.split("-", maxsplit=1)
            fixed_version = pkg_parts[1].split(".src")[0]  # 5.10.0-200.0.0.113.oe2203sp3
            cve_record[full_namespace]["Vulnerability"]["FixedIn"].append(
                {
                    "Name": pkg_parts[0],  # e.g., kernel
                    "Version": fixed_version,
                    "NamespaceName": namespace,
                    "VersionFormat": "rpm",
                },
            )
        return cve_record

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        # download the cve files
        self._download()

        # parse all cve files, record the cve data
        total_cves: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._parse_cve_file, cve): cve for cve in self.cves}
            for future in as_completed(futures):
                try:
                    data = future.result()
                    for full_namespace, vuln_dict in data.items():
                        if full_namespace in total_cves:
                            total_cves[full_namespace]["Vulnerability"]["FixedIn"].extend(vuln_dict["Vulnerability"]["FixedIn"])
                        else:
                            total_cves[full_namespace] = vuln_dict
                except Exception as e:
                    self.logger.warning(f"Failed to parse openEuler cves: {e}")

        for full_namespace, vuln_dict in total_cves.items():
            namespace, cve_id = full_namespace.split("/")
            yield namespace, cve_id, vuln_dict
