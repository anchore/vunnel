# flake8: noqa

import copy
import logging
import os
import re
import shutil
from html.parser import HTMLParser
from typing import List

import requests
import yaml

from vunnel.utils.vulnerability import vulnerability_element

namespace = "alpine"
feedtype = "vulnerabilities"
purge_unreported = True

# read and connect time out for requests.get
requests_timeout = 125

# driver workspace
driver_workspace = None
ignore_links = {"last-update", "license.txt"}


class SecdbLandingParser(HTMLParser):
    _valid_link_ = re.compile(r"[^\.+]")  # match anything that doesn't start with one or more '.'

    def __init__(self):
        self.links = []
        super(SecdbLandingParser, self).__init__()

    def handle_starttag(self, tag, attrs):
        for attr, value in attrs:
            if attr == "href" and SecdbLandingParser._valid_link_.match(value):
                if value not in ignore_links:
                    self.links.append(value)
                    break


class Parser:
    _url_ = "https://secdb.alpinelinux.org"
    _secdb_dir_ = "secdb"
    _db_types = ["main", "community"]
    _release_regex_ = re.compile(r"v([0-9]+.[0-9]+)")
    _link_finder_regex_ = re.compile(r'href\s*=\s*"([^\.+].*)"')

    def __init__(self, workspace: str, logger: logging.Logger | None = None, download_timeout: int = 125, url: str | None = None):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.source_dir_path = os.path.join(
            workspace, self._secdb_dir_, "alpine-secdb-master"
        )  # no longer used except for cleanup, leaving it here for backwards compatibility
        self.secdb_dir_path = os.path.join(workspace, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else Parser._url_
        if logger is None:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self._urls = set()

    @property
    def urls(self) -> List[str]:
        return list(self._urls)

    def _download(self, skip_if_exists=False):
        """
        Downloads alpine sec db files
        :return:
        """
        # remove old source directory since its no longer used
        if os.path.exists(self.source_dir_path):
            shutil.rmtree(self.source_dir_path)
        if os.path.exists(os.path.join(self.secdb_dir_path, "alpine-secdb-master.tar.gz")):
            os.remove(os.path.join(self.secdb_dir_path, "alpine-secdb-master.tar.gz"))

        if skip_if_exists and os.path.exists(self.secdb_dir_path):
            self.logger.warning(
                "skip_if_exists flag enabled and found source under {}. Skipping download".format(self.secdb_dir_path)
            )
        else:
            links = []
            try:
                if not os.path.exists(self.secdb_dir_path):
                    os.makedirs(self.secdb_dir_path, exist_ok=True)

                self.logger.info("Downloading alpine secdb metadata from: {}".format(self.metadata_url))
                r = requests.get(self.metadata_url, timeout=self.download_timeout)
                if r.status_code == 200:
                    try:
                        self.logger.debug("HTML parsing secdb landing page content for links")
                        parser = SecdbLandingParser()
                        parser.feed(r.text)
                        links = parser.links
                    except:
                        self.logger.warning("Unable to html parse secdb landing page content for links")

                    if not links:
                        self.logger.debug("String parsing secdb landing page content for links")
                        links = re.findall(self._link_finder_regex_, r.text)
                else:
                    r.raise_for_status()
            except Exception:
                self.logger.exception("Error downloading or parsing alpine secdb metadata")
                raise

            if links:
                self.logger.debug("Found release specific secdb links: {}".format(links))
            else:
                raise Exception("Unable to find release specific secdb links")

            for link in links:
                if link not in ignore_links:
                    try:
                        rel = link.strip("/")
                        rel_dir = os.path.join(self.secdb_dir_path, rel)
                        os.makedirs(rel_dir, exist_ok=True)
                        for db_type in self._db_types:
                            file_name = "{}.yaml".format(db_type)
                            download_url = "/".join([self.metadata_url, rel, file_name])
                            self._urls.add(download_url)
                            self.logger.info("Downloading secdb {} {}".format(rel, db_type))
                            r = requests.get(download_url, stream=True, timeout=self.download_timeout)
                            if r.status_code == 200:
                                file_path = os.path.join(rel_dir, file_name)
                                with open(file_path, "wb") as fp:
                                    for chunk in r.iter_content():
                                        fp.write(chunk)
                            else:
                                r.raise_for_status()
                    except:
                        self.logger.exception("Ignoring error processing secdb for {}".format(link))

    def _load(self):
        """
        Loads all db yamls for a release and yield it
        :return:
        """
        # parse and transform the yaml
        try:
            if os.path.exists(self.secdb_dir_path):
                for f in os.listdir(self.secdb_dir_path):
                    release = None

                    if f == "edge":
                        release = f
                    else:
                        match = self._release_regex_.match(f)
                        if match:
                            release = match.group(1)

                    if release:
                        dbtype_data_dict = {}

                        for dbtype in self._db_types:
                            secdb_yaml_path = os.path.join(self.secdb_dir_path, f, "{}.yaml".format(dbtype))
                            if os.path.exists(secdb_yaml_path):
                                self.logger.debug("Loading secdb data from: {}".format(secdb_yaml_path))
                                with open(secdb_yaml_path, "r") as FH:
                                    yaml_data = yaml.safe_load(FH)
                                    dbtype_data_dict[dbtype] = yaml_data

                        yield release, dbtype_data_dict

            else:
                raise Exception("Cannot find alpine sec db source ")
        except Exception:
            self.logger.exception("Failed to load alpine sec db data")
            raise

    def _normalize(self, release, dbtype_data_dict):
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict = {}

        for dbtype, data in dbtype_data_dict.items():
            self.logger.debug("Normalizing {}:{}".format(release, dbtype))

            if data["packages"]:
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
                                vuln_dict[vid] = copy.deepcopy(vulnerability_element)
                                vuln_record = vuln_dict[vid]

                                # populate the static information about the new vuln record
                                vuln_record["Vulnerability"]["Name"] = str(vid)
                                vuln_record["Vulnerability"]["NamespaceName"] = namespace + ":" + str(release)
                                vuln_record["Vulnerability"]["Link"] = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + str(vid)
                                vuln_record["Vulnerability"]["Severity"] = "Unknown"

                                # lookup nvd record only when creating the vulnerability, no point looking it up every time
                                # nvd_severity = None
                                # try:
                                #    nvd_severity = nvd.get_severity(
                                #        vid
                                #    )
                                # except Exception:
                                #    self.logger.exception(
                                #        "Ignoring error processing nvdv2 record"
                                #    )

                                # use nvd severity
                                # if nvd_severity:
                                #    vuln_record["Vulnerability"][
                                #        "Severity"
                                #    ] = nvd_severity
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

    def get(self, skip_if_exists: bool = False):
        """
        Download, load and normalize alpine sec db and return a dict of releae - list of vulnerability records
        :return:
        """
        # download the data
        self._download(skip_if_exists)

        for release, dbtype_data_dict in self._load():
            print(release)
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
