from __future__ import annotations

import copy
import logging
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import orjson

from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace
    from vunnel.tool import fixdate


class Parser:
    _release_ = "rolling"
    _security_feed_dir = "zerodeb-security"

    def __init__(  # noqa: PLR0913
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.fixdater = fixdater
        self.download_timeout = download_timeout
        self.security_feed_dir_path = os.path.join(workspace.input_path, self._security_feed_dir)
        self.metadata_url = url.strip("/")
        self.url = url
        self.namespace = namespace
        self._feed_filename = self._extract_filename_from_url(url)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @staticmethod
    def _extract_filename_from_url(url: str) -> str:
        return os.path.basename(urlparse(url).path)

    def _download(self) -> None:
        """
        Downloads 0-deb security feed.json file
        :return:
        """
        if not os.path.exists(self.security_feed_dir_path):
            os.makedirs(self.security_feed_dir_path, exist_ok=True)

        if self.fixdater:
            self.fixdater.download()

        try:
            self.logger.info("downloading 0-deb's security feed.json")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = os.path.join(self.security_feed_dir_path, self._feed_filename)
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error downloading feed from {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]]]:
        """
        Loads all db json and yields it
        :return:
        """
        dbtype_data_dict = {}

        # parse and transform the json
        try:
            with open(f"{self.security_feed_dir_path}/{self._feed_filename}") as fh:
                dbtype_data_dict = orjson.loads(fh.read())

                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} feed data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """
        Normalize all the security feed.json data into vulnerability payload records
        :param release:
        :param security_feed_data_dict:
        :return:
        """

        vuln_dict = {}

        self.logger.debug("normalizing vulnerability data")

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
                ecosystem = self.namespace + ":" + str(release)
                fixes = cve_info.get("fixed_in", [])
                fixed_in_entries = []
                if not fixes:
                    # No fix available - still need to associate the CVE with the package
                    fixed_in_entries.append({
                        "Name": package,
                        "Version": "None",
                        "VersionFormat": "dpkg",
                        "NamespaceName": ecosystem,
                    })
                for fix in fixes:
                    fix_version = str(fix["version"]) if fix["version"] is not None else "None"
                    fixed_in_entry = {
                        "Name": package,
                        "Version": fix_version,
                        "VersionFormat": "dpkg",
                        "NamespaceName": ecosystem,
                    }
                    fix_vulnerable_range = fix.get("vulnerable_range", None)
                    if fix_vulnerable_range:
                        fixed_in_entry["VulnerableRange"] = fix_vulnerable_range

                    if fix_version and self.fixdater:
                        result = self.fixdater.best(
                            vuln_id=str(cve_id),
                            cpe_or_package=package,
                            fix_version=fix_version,
                            ecosystem=ecosystem,
                        )
                        if result and result.date:
                            available = {
                                "Date": result.date.isoformat(),
                                "Kind": result.kind,
                            }
                            fixed_in_entry["Available"] = available
                    fixed_in_entries.append(fixed_in_entry)
                cve_record["Vulnerability"]["FixedIn"].extend(fixed_in_entries) # type: ignore[union-attr]
        return vuln_dict

    def get(self) -> Generator[tuple[str, dict[str, dict[str, Any]]]]:
        """
        Download, load and normalize 0-deb's security feed json and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        # load the data
        with open(f"{self.security_feed_dir_path}/{self._feed_filename}") as file:
            securty_feed_data_dict = orjson.loads(file.read())

        yield self._release_, self._normalize(self._release_, securty_feed_data_dict)
