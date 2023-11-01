from __future__ import annotations

import copy
import logging
import os
import re
import shutil
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import yaml

from vunnel.utils import http
from vunnel.utils.vulnerability import vulnerability_element

if TYPE_CHECKING:
    import requests

    from vunnel import workspace

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
        super().__init__()

    def handle_starttag(self, tag, attrs):
        for attr, value in attrs:
            if attr == "href" and SecdbLandingParser._valid_link_.match(value):  # noqa: SIM102
                if value not in ignore_links:
                    self.links.append(value)
                    break


class Parser:
    _url_ = "https://secdb.alpinelinux.org"
    _secdb_dir_ = "secdb"
    _db_types = ["main", "community"]  # noqa: RUF012
    _release_regex_ = re.compile(r"v([0-9]+.[0-9]+)")
    _link_finder_regex_ = re.compile(r'href\s*=\s*"([^\.+].*)"')

    def __init__(
        self,
        workspace: workspace.Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        url: str | None = None,
    ):
        self.download_timeout = download_timeout
        self.source_dir_path = os.path.join(
            workspace.input_path,
            self._secdb_dir_,
            "alpine-secdb-master",
        )  # no longer used except for cleanup, leaving it here for backwards compatibility
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else Parser._url_
        if logger is None:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self._urls = set()

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def _download(self):  # noqa: C901, PLR0912
        """
        Downloads alpine sec db files
        :return:
        """
        # remove old source directory since its no longer used
        if os.path.exists(self.source_dir_path):
            shutil.rmtree(self.source_dir_path)
        if os.path.exists(os.path.join(self.secdb_dir_path, "alpine-secdb-master.tar.gz")):
            os.remove(os.path.join(self.secdb_dir_path, "alpine-secdb-master.tar.gz"))

        links = []
        try:
            if not os.path.exists(self.secdb_dir_path):
                os.makedirs(self.secdb_dir_path, exist_ok=True)

            self.logger.info(f"downloading alpine secdb metadata from: {self.metadata_url}")
            r = self._download_metadata_url()
            try:
                self.logger.debug("HTML parsing secdb landing page content for links")
                parser = SecdbLandingParser()
                parser.feed(r.text)
                links = parser.links
            except Exception:
                self.logger.warning("unable to html parse secdb landing page content for links", exc_info=True)

            if not links:
                self.logger.debug("string parsing secdb landing page content for links")
                links = re.findall(self._link_finder_regex_, r.text)
        except Exception:
            self.logger.exception("error downloading or parsing alpine secdb metadata")
            raise

        if links:
            self.logger.debug(f"found release specific secdb links: {links}")
        else:
            raise Exception("unable to find release specific secdb links")

        for link in links:
            if link not in ignore_links:
                try:
                    rel = link.strip("/")
                    rel_dir = os.path.join(self.secdb_dir_path, rel)
                    os.makedirs(rel_dir, exist_ok=True)
                    for db_type in self._db_types:
                        if db_type == "community" and rel == "v3.2":
                            # edge case: community.yaml processing was added in v3.3
                            # since this involves semver processing and we have a known list, the simplest
                            # approach is to exclude this single version for now.
                            # future enhancement could add semver processing for something like "<3.3 continue"
                            continue

                        file_name = f"{db_type}.yaml"
                        download_url = "/".join([self.metadata_url, rel, file_name])

                        self.logger.info(f"Downloading secdb {rel} {db_type}")
                        r = self._download_url(download_url)

                        file_path = os.path.join(rel_dir, file_name)
                        with open(file_path, "wb") as fp:
                            for chunk in r.iter_content():
                                fp.write(chunk)

                except KeyboardInterrupt:
                    raise
                except Exception:
                    self.logger.exception(f"ignoring error processing secdb for {link}")

    def _download_metadata_url(self) -> requests.Response:
        return http.get(self.metadata_url, self.logger, timeout=self.download_timeout)

    def _download_url(self, url) -> requests.Response:
        self._urls.add(url)
        return http.get(url, self.logger, stream=True, timeout=self.download_timeout)

    def _load(self):
        """
        Loads all db yamls for a release and yield it
        :return:
        """
        # parse and transform the yaml
        try:
            if os.path.exists(self.secdb_dir_path):
                for f in sorted(os.listdir(self.secdb_dir_path)):
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
                            secdb_yaml_path = os.path.join(self.secdb_dir_path, f, f"{dbtype}.yaml")
                            if os.path.exists(secdb_yaml_path):
                                self.logger.debug(f"loading secdb data from: {secdb_yaml_path}")
                                with open(secdb_yaml_path) as FH:
                                    yaml_data = yaml.safe_load(FH)
                                    dbtype_data_dict[dbtype] = yaml_data

                        yield release, dbtype_data_dict

            else:
                raise Exception("Cannot find alpine sec db source ")
        except Exception:
            self.logger.exception("Failed to load alpine sec db data")
            raise

    def _normalize(self, release, dbtype_data_dict):  # noqa: C901
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict = {}

        for dbtype, data in dbtype_data_dict.items():
            self.logger.info(f"processing {release}:{dbtype}")

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

    def get(self):
        """
        Download, load and normalize alpine sec db and return a dict of releae - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
