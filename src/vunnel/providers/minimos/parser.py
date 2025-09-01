from __future__ import annotations

import copy
import logging
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace


class Parser:
    _release_ = "rolling"
    _secdb_dir_ = "secdb"

    def __init__(  # noqa: PLR0913
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.metadata_url = url.strip("/")
        self.url = url
        self.namespace = namespace
        self._db_filename = self._extract_filename_from_url(url)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @staticmethod
    def _extract_filename_from_url(url: str) -> str:
        return os.path.basename(urlparse(url).path)

    def _download(self) -> None:
        """
        Downloads minimos sec db files
        :return:
        """
        if not os.path.exists(self.secdb_dir_path):
            os.makedirs(self.secdb_dir_path, exist_ok=True)

        self.fixdater.download()

        try:
            self.logger.info(f"downloading {self.namespace} secdb {self.url}")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = os.path.join(self.secdb_dir_path, self._db_filename)
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        """
        Loads all db json and yields it
        :return:
        """
        # parse and transform the json
        try:
            with open(f"{self.secdb_dir_path}/{self._db_filename}") as fh:
                dbtype_data_dict = orjson.loads(fh.read())

                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} sec db data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, dict[str, Any]]:  # noqa: C901
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict = {}

        self.logger.debug("normalizing vulnerability data")

        for el in data["packages"]:
            pkg_el = el["pkg"]

            pkg = pkg_el["name"]
            for fix_version in pkg_el["secfixes"]:
                vids = []
                if pkg_el["secfixes"][fix_version]:
                    for rawvid in pkg_el["secfixes"][fix_version]:
                        tmp = rawvid.split()
                        for newvid in tmp:
                            if newvid not in vids:
                                vids.append(newvid)

                for vid in vids:
                    if vid not in vuln_dict:
                        # create a new record
                        vuln_dict[vid] = copy.deepcopy(vulnerability.vulnerability_element)
                        vuln_record = vuln_dict[vid]
                        reference_links = vulnerability.build_reference_links(vid)

                        # populate the static information about the new vuln record
                        vuln_record["Vulnerability"]["Name"] = str(vid)
                        vuln_record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)

                        if reference_links:
                            # TODO: Support multiple links
                            vuln_record["Vulnerability"]["Link"] = reference_links[0]

                        vuln_record["Vulnerability"]["Severity"] = "Unknown"
                    else:
                        vuln_record = vuln_dict[vid]

                    # SET UP fixedins
                    ecosystem = self.namespace + ":" + str(release)
                    fixed_el = {
                        "Name": pkg,
                        "Version": fix_version,
                        "VersionFormat": "apk",
                        "NamespaceName": ecosystem,
                    }

                    result = self.fixdater.best(
                        vuln_id=str(vid),
                        cpe_or_package=pkg,
                        fix_version=fix_version,
                        ecosystem=ecosystem,
                    )
                    if result and result.date:
                        fixed_el["Available"] = {
                            "Date": result.date.isoformat(),
                            "Kind": result.kind,
                        }

                    vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)  # type: ignore[union-attr]

        return vuln_dict

    def get(self) -> Generator[tuple[str, dict[str, dict[str, Any]]], None, None]:
        """
        Download, load and normalize minimos sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        # load the data
        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
