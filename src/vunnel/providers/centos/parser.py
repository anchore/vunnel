# flake8: noqa
from __future__ import annotations

import bz2
import hashlib
import logging
import os
import re

import requests

from vunnel import utils
from vunnel.utils.oval_parser import Config, parse

namespace = "centos"
feedtype = "vulnerabilities"

# One time initialization of driver specific configuration
centos_config = Config()

# regexes
centos_config.tag_pattern = re.compile(r"\{http://oval.mitre.org/XMLSchema/.*\}(\w*)")
centos_config.ns_pattern = re.compile(r"(\{http://oval.mitre.org/XMLSchema/.*\})\w*")
centos_config.is_installed_pattern = re.compile(r"Red Hat Enterprise Linux (\d+).*is installed")
centos_config.pkg_version_pattern = re.compile(r"(.*) is earlier than (.*)")
centos_config.pkg_module_pattern = re.compile(r"Module (.*) is enabled")
centos_config.signed_with_pattern = re.compile(r"(.*) is signed with (.*) key")
centos_config.platform_version_pattern = re.compile(r"Red Hat Enterprise Linux (\d+)")

# xpath queries
centos_config.title_xpath_query = "{0}metadata/{0}title"
centos_config.severity_xpath_query = "{0}metadata/{0}advisory/{0}severity"
centos_config.platform_xpath_query = "{0}metadata/{0}affected/{0}platform"
centos_config.date_issued_xpath_query = "{0}metadata/{0}advisory/{0}issued"
centos_config.date_updated_xpath_query = "{0}metadata/{0}advisory/{0}updated"
centos_config.description_xpath_query = "{0}metadata/{0}description"
centos_config.sa_ref_xpath_query = '{0}metadata/{0}reference[@source="RHSA"]'
centos_config.cve_xpath_query = "{0}metadata/{0}advisory/{0}cve"
centos_config.criteria_xpath_query = "{0}criteria"
centos_config.criterion_xpath_query = ".//{0}criterion"

# maps
centos_config.severity_dict = {
    "low": "Low",
    "moderate": "Medium",
    "important": "High",
    "critical": "Critical",
}

# string formats
centos_config.ns_format = "centos:{}"

# read and connect time out for requests.get
requests_timeout = 125

# driver workspace
driver_workspace = None


class Parser:
    _url_ = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2"
    _meta_url_ = "https://www.redhat.com/security/data/oval/PULP_MANIFEST"
    _sha_line_regex_ = re.compile(r"com.redhat.rhsa-all.xml,([^,]+),.*")
    _xml_file_ = "com.redhat.rhsa-all.xml"
    _xml_sha_file_ = "com.redhat.rhsa-all.xml.sha256sum"

    def __init__(self, workspace, logger=None, config=None, download_timeout=125):
        self.config = config if config else centos_config
        self.download_timeout = download_timeout
        self.xml_file_path = os.path.join(workspace.input_path, self._xml_file_)
        self.xml_sha_file_path = os.path.join(workspace.input_path, self._xml_sha_file_)
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @property
    def urls(self) -> list[str]:
        return [
            self._url_,
            self._meta_url_,
        ]

    def _get_sha256(self):
        try:
            r = requests.get(self._meta_url_, timeout=self.download_timeout)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    match = self._sha_line_regex_.match(line.strip())
                    if match:
                        latest = match.group(1)
                        break
                else:
                    raise Exception("no matching sha256 found for {}".format(self._xml_file_))
                return latest
            else:
                raise Exception("GET {} failed with HTTP error {}".format(self._meta_url_, r.status_code))
        except:
            raise Exception("Error fetching/processing sha256")

    @utils.retry_with_backoff()
    def _download(self):
        download = True

        if os.path.exists(self.xml_file_path) and os.path.exists(self.xml_sha_file_path):
            with open(self.xml_sha_file_path) as fp:
                previous = fp.read()
                previous = previous.strip()

            latest = self._get_sha256()
            self.logger.debug("previous sha256: {}, latest sha256: {}".format(previous, latest))
            download = previous.lower() != latest.lower()

        if download:
            try:
                self.logger.info("downloading RHSA from {}".format(self._url_))
                r = requests.get(self._url_, stream=True, timeout=self.download_timeout)
                if r.status_code == 200:
                    # compute the sha256 as the file is decompressed
                    sha256 = hashlib.sha256()
                    with open(self.xml_file_path, "wb") as extracted:
                        decompressor = bz2.BZ2Decompressor()
                        for chunk in r.iter_content(chunk_size=1024):
                            uncchunk = decompressor.decompress(chunk)
                            extracted.write(uncchunk)
                            sha256.update(uncchunk)

                    sha256sum = str(sha256.hexdigest()).lower()
                    self.logger.debug("sha256 for {}: {}".format(self.xml_file_path, sha256sum))

                    # save the sha256 to another file
                    with open(self.xml_sha_file_path, "w") as fp:
                        fp.write(sha256sum)

                    return sha256sum
                else:
                    raise Exception("GET {} failed with HTTP error {}".format(self._url_, r.status_code))
            except Exception:
                self.logger.exception("error downloading RHSA file")
                raise Exception("error downloading RHSA file")
        else:
            self.logger.info("stored csum matches server csum. Skipping download")

        return None

    def parse(self):
        # normalize and return results
        return parse(self.xml_file_path, self.config)

    def get(self):
        # download
        self._download()

        return self.parse()
