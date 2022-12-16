import copy
import glob
import json
import logging
import os
import re

import requests

from vunnel import utils
from vunnel.utils import common

namespace = "wolfi"


class Parser:
    _url_ = "https://packages.wolfi.dev"
    _secdb_dir_ = "secdb"
    _db_types = ["os"]

    def __init__(self, workspace, download_timeout=125, url=None, logger=None):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else Parser._url_
        self.urls = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @utils.retry_with_backoff()
    def _download(self, skip_if_exists=False):
        """
        Downloads wolfi sec db files
        :return:
        """

        if skip_if_exists and os.path.exists(self.secdb_dir_path):
            self.logger.warning(
                f"'skip_if_exists' flag enabled and found source under {self.secdb_dir_path}. Skipping download",
            )
        else:
            if not os.path.exists(self.secdb_dir_path):
                os.makedirs(self.secdb_dir_path, exist_ok=True)

            for t in self._db_types:
                try:
                    rel_dir = os.path.join(self.secdb_dir_path, t)
                    os.makedirs(rel_dir, exist_ok=True)

                    filename = "security.json"
                    download_url = f"{self.metadata_url}/{t}/{filename}"

                    self.urls.append(download_url)

                    self.logger.info(f"downloading Wolfi secdb {download_url}")
                    r = requests.get(download_url, stream=True, timeout=self.download_timeout)
                    if r.status_code == 200:
                        file_path = os.path.join(rel_dir, filename)
                        with open(file_path, "wb") as fp:
                            for chunk in r.iter_content():
                                fp.write(chunk)
                    else:
                        r.raise_for_status()
                except:  # pylint: disable=bare-except
                    self.logger.exception(f"ignoring error processing secdb for {t}")

    def _load(self):
        """
        Loads all db json an yield it
        :return:
        """
        dbtype_data_dict = {}

        # parse and transform the json
        try:
            if os.path.exists(self.secdb_dir_path):
                for s in glob.glob(f"{self.secdb_dir_path}/**/security.json", recursive=True):
                    dbtype = s.split("/")[-2]

                    if os.path.exists(s):
                        self.logger.debug(f"loading secdb data from: {s}")
                        with open(s, "r", encoding="utf-8") as fh:
                            dbtype_data_dict[dbtype] = json.load(fh)

                yield "rolling", dbtype_data_dict
            else:
                raise Exception("Cannot find Wolfi sec db source ")
        except Exception:
            self.logger.exception("failed to load Wolfi sec db data")
            raise

    # pylint: disable=too-many-locals,too-many-nested-blocks,too-many-branches
    def _normalize(self, release, dbtype_data_dict):
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict = {}

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
                            vuln_dict[vid] = copy.deepcopy(common.vulnerability_element)
                            vuln_record = vuln_dict[vid]

                            # populate the static information about the new vuln record
                            vuln_record["Vulnerability"]["Name"] = str(vid)
                            vuln_record["Vulnerability"]["NamespaceName"] = namespace + ":" + str(release)
                            vuln_record["Vulnerability"]["Link"] = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + str(vid)
                            vuln_record["Vulnerability"]["Severity"] = "Unknown"

                            # lookup nvd record only when creating the vulnerability, no point looking it up every time
                            nvd_severity = None
                            # TODO: ALEX fix this in grype-db-builder
                            # if session:
                            #     try:
                            #         nvd_severity = nvd.get_severity(
                            #             vid, session=session
                            #         )
                            #     except Exception:
                            #         self.logger.exception(
                            #             "Ignoring error processing nvdv2 record"
                            #         )

                            # use nvd severity
                            if nvd_severity:
                                vuln_record["Vulnerability"]["Severity"] = nvd_severity
                        else:
                            vuln_record = vuln_dict[vid]

                        # SET UP fixedins
                        fixed_el = {}
                        fixed_el["VersionFormat"] = "apk"
                        fixed_el["NamespaceName"] = namespace + ":" + str(release)
                        fixed_el["Name"] = pkg
                        fixed_el["Version"] = pkg_version

                        vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return vuln_dict

    def get(self, skip_if_exists=False):
        """
        Download, load and normalize wolfi sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download(skip_if_exists)

        # load the data
        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
