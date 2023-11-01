from __future__ import annotations

import logging
import os
import re
from collections import namedtuple
from html.parser import HTMLParser

import defusedxml.ElementTree as ET

from vunnel.utils import http, rpm

namespace = "amzn"

AlasSummary = namedtuple("AlasSummary", ["id", "url", "sev", "cves"])
AlasFixedIn = namedtuple("AlasFixedIn", ["pkg", "ver"])

amazon_security_advisories = {
    # '1': 'https://alas.aws.amazon.com/alas.rss',
    "2": "https://alas.aws.amazon.com/AL2/alas.rss",
    "2022": "https://alas.aws.amazon.com/AL2022/alas.rss",
    "2023": "https://alas.aws.amazon.com/AL2023/alas.rss",
}

severity_map = {
    "low": "Low",
    "medium": "Medium",
    "important": "High",
    "critical": "Critical",
}


class Parser:
    _title_pattern_ = re.compile(r"([^\s]+)\s+\(([^\)]+)\):.*")
    _whitespace_pattern_ = re.compile(r"\s")
    _rss_file_name_ = "{}_rss.xml"
    _html_dir_name_ = "{}_html"

    def __init__(self, workspace, download_timeout=125, security_advisories=None, logger=None):
        self.workspace = workspace
        self.version_url_map = security_advisories if security_advisories else amazon_security_advisories
        self.download_timeout = download_timeout
        self.urls = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download_rss(self, rss_url, rss_file):
        try:
            self.logger.info(f"downloading amazon security advisory from {rss_url}")
            self.urls.append(rss_url)
            r = http.get(rss_url, self.logger, timeout=self.download_timeout)
            with open(rss_file, "w", encoding="utf-8") as fp:
                fp.write(r.text)
        except Exception:
            self.logger.exception("error downloading amazon linux vulnerability feeds")
            raise

    def _parse_rss(self, file_path):
        self.logger.debug(f"parsing RSS data from {file_path}")
        alas_summaries = []

        processing = False
        for event, element in ET.iterparse(file_path, events=("start", "end")):
            if event == "start" and element.tag == "item":
                processing = True
            elif processing and event == "end":
                if element.tag == "title":
                    found = re.search(self._title_pattern_, element.text.strip())
                    alas_id = found.group(1)
                    sev = found.group(2)
                elif element.tag == "description":
                    desc_str = element.text.strip()
                    cves = re.sub(self._whitespace_pattern_, "", desc_str).split(",") if desc_str else []
                elif element.tag == "link":
                    url = element.text.strip()
                elif element.tag == "item":
                    alas_summaries.append(AlasSummary(id=alas_id, url=url, sev=sev, cves=cves))
                    processing = False

            # clear the element if its not being processed
            if not processing and event == "end":
                element.clear()

        return sorted(alas_summaries)

    def _get_alas_html(self, alas_url, alas_file, skip_if_exists=True):
        if skip_if_exists and os.path.exists(alas_file):  # read alas from disk if its available
            self.logger.debug(f"loading existing ALAS from {alas_file}")
            with open(alas_file, encoding="utf-8") as fp:
                content = fp.read()
            return content  # noqa: RET504
        try:
            r = http.get(alas_url, self.logger, timeout=self.download_timeout)
            content = r.text
            with open(alas_file, "w", encoding="utf-8") as fp:
                fp.write(content)
            return content
        except Exception:
            self.logger.exception(f"error downloading data from {alas_url}")
            raise

    @staticmethod
    def get_package_name_version(pkg):
        if not pkg or not isinstance(pkg, str):
            raise ValueError(f"Invalid package name: {pkg}")

        if not pkg.endswith(".rpm"):
            pkg = pkg + ".rpm"

        name, version, release, epoch, arch = rpm.split_rpm_filename(pkg)

        if release:
            return AlasFixedIn(pkg=name, ver=(version + "-" + release))
        return AlasFixedIn(pkg=name, ver=version)

    def get(self, skip_if_exists=False):
        for version, url in self.version_url_map.items():
            rss_file = os.path.join(self.workspace.input_path, self._rss_file_name_.format(version))
            html_dir = os.path.join(self.workspace.input_path, self._html_dir_name_.format(version))

            self._download_rss(url, rss_file)

            # parse rss for alas summaries
            alas_summaries = self._parse_rss(rss_file)

            # setup directory for alas htmls
            if not os.path.exists(html_dir):
                self.logger.debug("initializing workspace for ALAS files")
                os.makedirs(html_dir)

            # iterate through list of alas summaries
            for alas in alas_summaries:
                # download alas html content
                alas_file = os.path.join(html_dir, alas.id)
                html_content = self._get_alas_html(alas.url, alas_file)

                # parse alas html for fixes
                parser = PackagesHTMLParser()
                parser.feed(html_content)

                # split the package name and version of the fixed in packages and construct a set
                fixed_in = {self.get_package_name_version(pkg_name) for pkg_name in parser.fixes}

                # concat the descriptions paragraph
                description = "".join(parser.issue_overview_text)

                # construct a vulnerability object and yield it
                yield map_to_vulnerability(version, alas, fixed_in, description)


class JsonifierMixin:
    def json(self):
        jsonified = {}
        for k, v in sorted(vars(self).items()):
            if k[0] != "_":
                if isinstance(v, (list, set)):
                    jsonified[k] = [x.json() if hasattr(x, "json") and callable(x.json) else x for x in v]
                elif isinstance(v, dict):
                    jsonified[k] = {x: y.json() if hasattr(y, "json") and callable(y.json) else y for x, y in sorted(v.items())}
                elif hasattr(v, "json"):
                    jsonified[k] = v.json()
                else:
                    jsonified[k] = v
        return jsonified


class Vulnerability(JsonifierMixin):
    """
    Class representing the record to be returned. Uses strange capitalization
    to be backwards compatible in the json output with previous version of feed data.
    """

    def __init__(self):
        self.Name = None
        self.NamespaceName = None
        self.Description = ""
        self.Severity = None
        self.Metadata = None
        self.Link = None
        self.FixedIn = []


class FixedIn(JsonifierMixin):
    """
    Class representing a fix record for return back to the service from the driver. The semantics of the version are:
    "None" -> Package is vulnerable and no fix available yet
    ! "None" -> Version of package with a fix for a vulnerability. Assume all older versions of the package are vulnerable.

    """

    def __init__(self):
        self.Name = None
        self.NamespaceName = None
        self.VersionFormat = None
        self.Version = None


class PackagesHTMLParser(HTMLParser):
    _new_packages_tuple_ = ("id", "new_packages")
    _arch_list_ = ["x86_64:", "noarch:", "src:"]  # noqa: RUF012

    def __init__(self):
        self.fixes = []
        self.issue_overview_text = []
        self.issue_overview_tag = None
        self.issue_overview_hit = False
        self.fix_tag = None
        self.fix_hit = False
        self.arch_hit = False
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if attrs and self._new_packages_tuple_ in attrs:
            # print('Encountered element with ID new_packages, start tag: {}'.format(tag))
            self.fix_hit = True
            self.fix_tag = tag
        if tag == "div" and ("id", "issue_overview") in attrs:
            self.issue_overview_hit = True
            self.issue_overview_tag = tag
        # else:
        #     print('Ignoring start tag: {}'.format(tag))

    def handle_endtag(self, tag):
        if self.fix_hit and self.fix_tag == tag:
            # print('Encountered end tag for element with ID new_packages')
            self.fix_hit = False
            self.arch_hit = False
        if self.issue_overview_hit and self.issue_overview_tag == tag:
            self.issue_overview_hit = False
        # else:
        #     print('Ignoring end tag: {}'.format(tag))

    def handle_data(self, data):
        data = data.strip()

        if self.fix_hit and data:
            if data in self._arch_list_:  # check if its a relevant arch
                # print('Found relevant arch: "{}"'.format(data))
                self.arch_hit = True
            elif data.endswith(":"):  # Using i686: or src: as an indicator for end of processing
                # if data != 'New Packages:':
                #     logger.debug('Ignoring irrelevant arch or data: {}'.format(data))
                self.arch_hit = False
            elif self.arch_hit:  # check if its a relevant package
                # print('Found relevant package: {}'.format(data))
                self.fixes.append(data)

        if self.issue_overview_hit and data and not data.__contains__("Issue Overview:"):
            self.issue_overview_text.append(data)
        # else:
        #     print('Ignoring data: {}'.format(data.strip()))


def map_to_vulnerability(version, alas, fixed_in, description):
    if not alas:
        raise ValueError("Invalid reference to AlasSummary")

    v = Vulnerability()
    v.Name = alas.id
    v.NamespaceName = namespace + ":" + version
    v.Description = description
    v.Severity = severity_map.get(alas.sev, "Unknown")
    v.Metadata = {
        "CVE": [],
    }

    if alas.cves:
        v.Metadata["CVE"] = [{"Name": cve} for cve in alas.cves]

    v.Link = alas.url
    for item in sorted(fixed_in):
        f = FixedIn()
        f.Name = item.pkg
        f.NamespaceName = v.NamespaceName
        f.VersionFormat = "rpm"
        f.Version = item.ver
        v.FixedIn.append(f)

    return v
