from __future__ import annotations

import bz2
import logging
import os
import re

from vunnel.utils import http, rpm
from vunnel.utils.oval_parser import Config, parse

# One time initialization of driver specific configuration
ol_config = Config()

# regexes
ol_config.tag_pattern = re.compile(r"\{http://oval.mitre.org/XMLSchema/.*\}(\w*)")
ol_config.ns_pattern = re.compile(r"(\{http://oval.mitre.org/XMLSchema/.*\})\w*")
ol_config.is_installed_pattern = re.compile(r"Oracle Linux (\d+).*is installed")
ol_config.pkg_version_pattern = re.compile(r"(.*) is earlier than (.*)")
ol_config.pkg_module_pattern = re.compile(r"Module (.*) is enabled")
ol_config.signed_with_pattern = re.compile(r"(.*) is signed with the (.*) key")
ol_config.platform_version_pattern = re.compile(r"Oracle Linux (\d+)")

# xpath queries
ol_config.title_xpath_query = "{0}metadata/{0}title"
ol_config.severity_xpath_query = "{0}metadata/{0}advisory/{0}severity"
ol_config.platform_xpath_query = "{0}metadata/{0}affected/{0}platform"
ol_config.date_issued_xpath_query = "{0}metadata/{0}advisory/{0}issued"
ol_config.date_updated_xpath_query = None  # oracle oval does not contain date updated
ol_config.description_xpath_query = "{0}metadata/{0}description"
ol_config.sa_ref_xpath_query = '{0}metadata/{0}reference[@source="elsa"]'
ol_config.cve_xpath_query = "{0}metadata/{0}advisory/{0}cve"
ol_config.criteria_xpath_query = "{0}criteria"
ol_config.criterion_xpath_query = ".//{0}criterion"

# maps
ol_config.severity_dict = {
    "n/a": "Negligible",
    "low": "Low",
    "moderate": "Medium",
    "important": "High",
    "critical": "Critical",
}

# string formats
ol_config.ns_format = "ol:{}"


class Parser:
    _url_ = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"
    _xml_file_ = "com.oracle.elsa-all.xml"

    def __init__(self, workspace, config=None, download_timeout=125, logger=None):
        self.config = config if config else ol_config
        self.download_timeout = download_timeout
        self.xml_file_path = os.path.join(workspace.input_path, self._xml_file_)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @property
    def urls(self):
        return [self._url_]

    def _download(self):
        try:
            self.logger.info(f"downloading ELSA from {self._url_}")
            r = http.get(self._url_, self.logger, stream=True, timeout=self.download_timeout)
            if r.status_code != 200:
                raise Exception(f"GET {self._url_} failed with HTTP error {r.status_code}")

            with open(self.xml_file_path, "wb") as extracted:
                decompressor = bz2.BZ2Decompressor()
                for chunk in r.iter_content(chunk_size=1024):
                    extracted.write(decompressor.decompress(chunk))

        except Exception:
            self.logger.exception("error downloading ELSA file")
            raise

    def _parse_oval_data(self, path: str, config: dict):
        # normalize and return results
        raw_results = parse(path, config)

        # TODO: remove this filtering once Grype and GrypeDB support the types of version checks necessary
        # to correctly match these.
        # NOTE: Grype and GrypeDB need to identify both a version range AND a specific release version check.
        # See:https://github.com/anchore/anchore-engine/issues/1237 for details and links.
        # This approach is the minimally risk since it only impacts this driver and only ksplice-based packages.
        filterer = KspliceFilterer(logger=self.logger)
        return filterer.filter(raw_results)

    def get(self):
        # download
        self._download()
        return self._parse_oval_data(self.xml_file_path, self.config)


class KspliceFilterer:
    ksplice_regex = re.compile(".*ksplice.*")

    def __init__(self, logger=None):
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @classmethod
    def _is_ksplice_version(cls, version) -> bool:
        """
        Returns true if the package version (rpm) is a "ksplice" package

        :param version:
        :return:
        """
        epoch, version, release = rpm.split_fullversion(version)
        return cls.ksplice_regex.match(release) is not None

    def filter(self, vuln_dict: dict) -> dict:  # noqa: A003
        """

        Filters affected packages and ELSAs that are for ksplice packages since the matching logic for these in Grype isn't
        present and it consistently causes false-positives.

        This only removes the FixedIn records, it does not remove the
        parent vuln record. This is necessary to ensure the sync down to engines will get updated properly. No matches will be
        possible with no FixedIn records.

        TODO: this eventually should be removed once support for handling complex version constraints is supported in the feed
        data model and in Grype. See https://github.com/anchore/anchore-engine/issues/1237 for FP description

        :param vuln_dict: dict of vulns where key is distro and version and value is the list of vulns for that version
        :return:
        """
        for version, vuln in vuln_dict.values():  # noqa: B007
            fixes = vuln.get("Vulnerability", {}).get("FixedIn", [])
            if fixes:
                pre_filter_fix_count = len(fixes)

                # sort dictionary by "Name" and "Version" keys
                fixes = sorted(fixes, key=lambda k: (k["Name"], k["Version"]))

                vuln["Vulnerability"]["FixedIn"] = [fix for fix in fixes if not self._is_ksplice_version(fix.get("Version", ""))]

                post_filter_count = len(vuln["Vulnerability"]["FixedIn"])
                filter_diff = pre_filter_fix_count - post_filter_count

                if filter_diff > 0:
                    self.logger.debug(
                        "filtered %s ksplice-based package entries out of total %s package entries for vuln %s",
                        filter_diff,
                        pre_filter_fix_count,
                        vuln["Vulnerability"]["Name"],
                    )

        return vuln_dict
