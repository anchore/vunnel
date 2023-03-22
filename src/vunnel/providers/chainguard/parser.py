from __future__ import annotations

import copy
import glob
import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

    from vunnel.workspace import Workspace

import requests

from vunnel import utils
from vunnel.utils import vulnerability

namespace = "chainguard"


class Parser:
    _url_ = "https://packages.cgr.dev"
    _db_types = ["chainguard"]
    _db_filename = "security.json"
    _secdb_dir_ = "secdb"

    def __init__(
        self,
        workspace: Workspace,
        download_timeout: int = 125,
        url: str | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else Parser._url_
        self.urls: list[str] = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @utils.retry_with_backoff()
    def _download(self) -> None:
        """
        Downloads chainguard sec db files
        :return:
        """
        if not os.path.exists(self.secdb_dir_path):
            os.makedirs(self.secdb_dir_path, exist_ok=True)

        for t in self._db_types:
            try:
                rel_dir = os.path.join(self.secdb_dir_path, t)
                os.makedirs(rel_dir, exist_ok=True)

                download_url = f"{self.metadata_url}/{t}/{self._db_filename}"

                self.urls.append(download_url)

                self.logger.info(f"downloading Chainguard secdb {download_url}")
                r = requests.get(download_url, stream=True, timeout=self.download_timeout)
                if r.status_code == 200:
                    file_path = os.path.join(rel_dir, self._db_filename)
                    with open(file_path, "wb") as fp:
                        for chunk in r.iter_content():
                            fp.write(chunk)
                else:
                    r.raise_for_status()
            except:  # noqa
                self.logger.exception(f"ignoring error processing secdb for {t}")

    def _load(self) -> Iterator[tuple[str, dict[str, Any]]]:
        """
        Loads all db json and yields it
        :return:
        """
        dbtype_data_dict = {}

        # parse and transform the json
        try:
            if os.path.exists(self.secdb_dir_path):
                for s in glob.glob(f"{self.secdb_dir_path}/**/{self._db_filename}", recursive=True):
                    dbtype = s.split("/")[-2]

                    if os.path.exists(s):
                        self.logger.debug(f"loading secdb data from: {s}")
                        with open(s, encoding="utf-8") as fh:
                            dbtype_data_dict[dbtype] = json.load(fh)

                yield "rolling", dbtype_data_dict
            else:
                raise Exception("Cannot find Chainguard sec db source ")
        except Exception:
            self.logger.exception("failed to load Chainguard sec db data")
            raise

    # noqa
    def _normalize(self, release: str, dbtype_data_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict: Any = {}

        for dbtype, data in dbtype_data_dict.items():
            self.logger.debug(f"normalizing {release}:{dbtype}")

            if not data["packages"]:
                continue

            for el in data["packages"]:
                pkg_el = el["pkg"]

                pkg = pkg_el["name"]
                for pkg_version in pkg_el["secfixes"]:
                    vids = []
                    if pkg_el["secfixes"][pkg_version]:
                        for rawvid in pkg_el["secfixes"][pkg_version]:
                            tmp = rawvid.split()
                            for newvid in tmp:
                                if newvid not in vids:
                                    vids.append(newvid)

                    for vid in vids:
                        if not re.match("^CVE-.*", vid):
                            # skip non-CVE records
                            continue

                        if vid not in vuln_dict:
                            # create a new record
                            vuln_dict[vid] = copy.deepcopy(vulnerability.vulnerability_element)
                            vuln_record = vuln_dict[vid]

                            # populate the static information about the new vuln record
                            vuln_record["Vulnerability"]["Name"] = str(vid)
                            vuln_record["Vulnerability"]["NamespaceName"] = namespace + ":" + str(release)
                            vuln_record["Vulnerability"]["Link"] = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + str(vid)
                            vuln_record["Vulnerability"]["Severity"] = "Unknown"
                        else:
                            vuln_record = vuln_dict[vid]

                        # SET UP fixedins
                        fixed_el = {
                            "Name": pkg,
                            "Version": pkg_version,
                            "VersionFormat": "apk",
                            "NamespaceName": namespace + ":" + str(release),
                        }

                        vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return vuln_dict

    def get(self) -> Iterator[tuple[str, dict[str, Any]]]:
        """
        Download, load and normalize Chainguard sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        # load the data
        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
