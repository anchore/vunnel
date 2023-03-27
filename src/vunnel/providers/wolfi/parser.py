from __future__ import annotations

import copy
import json
import logging
import os
import re
from urllib.parse import urlparse

import requests

from vunnel import utils
from vunnel.utils import vulnerability


class Parser:
    _release_ = "rolling"
    _secdb_dir_ = "secdb"

    def __init__(  # noqa: PLR0913
        self,
        workspace,
        url: str,
        namespace: str,
        download_timeout: int = 125,
        logger: logging.Logger = None,  # noqa: PLR0913
    ):
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else Parser._url_
        self.url = url
        self.namespace = namespace
        self._db_filename = self._extract_filename_from_url(url)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @staticmethod
    def _extract_filename_from_url(url):
        return os.path.basename(urlparse(url).path)

    @utils.retry_with_backoff()
    def _download(self):
        """
        Downloads wolfi sec db files
        :return:
        """
        if not os.path.exists(self.secdb_dir_path):
            os.makedirs(self.secdb_dir_path, exist_ok=True)

        try:
            self.logger.info(f"downloading {self.namespace} secdb {self.url}")
            r = requests.get(self.url, stream=True, timeout=self.download_timeout)
            if r.status_code == 200:
                file_path = os.path.join(self.secdb_dir_path, self._db_filename)
                with open(file_path, "wb") as fp:
                    for chunk in r.iter_content():
                        fp.write(chunk)
            else:
                r.raise_for_status()
        except:  # noqa
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self):
        """
        Loads all db json and yields it
        :return:
        """
        dbtype_data_dict = {}

        # parse and transform the json
        try:
            with open(f"{self.secdb_dir_path}/{self._db_filename}") as fh:
                dbtype_data_dict = json.load(fh)

                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} sec db data")
            raise

    # noqa
    def _normalize(self, release, data):
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
                        vuln_record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)
                        vuln_record["Vulnerability"]["Link"] = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + str(vid)
                        vuln_record["Vulnerability"]["Severity"] = "Unknown"
                    else:
                        vuln_record = vuln_dict[vid]

                    # SET UP fixedins
                    fixed_el = {
                        "Name": pkg,
                        "Version": pkg_version,
                        "VersionFormat": "apk",
                        "NamespaceName": self.namespace + ":" + str(release),
                    }

                    vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return vuln_dict

    def get(self):
        """
        Download, load and normalize wolfi sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        # load the data
        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
