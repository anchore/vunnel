from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal, DecimalException
from typing import TYPE_CHECKING

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError

from vunnel.utils import http
from vunnel.utils.oval_v2 import (
    ArtifactParser,
    Impact,
    OVALElementEnum,
    OVALParserConfig,
    OVALParserFactory,
    Parsed,
    TestParser,
    VersionParser,
    VulnerabilityParser,
    iter_parse_vulnerability_file,
)
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics, FixedIn, Vulnerability

if TYPE_CHECKING:
    from vunnel.workspace import Workspace

namespace = "sles"


PARSER_CONFIG = OVALParserConfig(
    platform_regex=re.compile(r"SUSE Linux Enterprise Server \d+.* is installed"),
    artifact_regex=re.compile(r".* is installed"),
    source_url_xpath_query='{0}metadata/{0}reference[@source="SUSE CVE"]',
    severity_map={
        "low": "Low",
        "moderate": "Medium",
        "important": "High",
        "critical": "Critical",
    },
)


class Parser:
    __oval_url__ = "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.{}.xml.gz"
    __oval_file_name__ = "suse-linux-enterprise-server-{}.xml.gz"
    __oval_dir_path__ = "oval"
    __source_dir_path__ = "source"

    # this is pretty odd, but there are classmethods that need logging
    logger = logging.getLogger("sles-parser")

    def __init__(
        self,
        workspace: Workspace,
        allow_versions: list[str],
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.oval_dir_path = os.path.join(workspace.input_path, self.__source_dir_path__, self.__oval_dir_path__)
        self.allow_versions = allow_versions
        self.download_timeout = download_timeout
        self.urls = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        # this is pretty odd, but there are classmethods that need logging
        Parser.logger = logger

    def _download(self, major_version: str) -> str:
        if not os.path.exists(self.oval_dir_path):
            self.logger.debug(f"creating workspace for OVAL source data at {self.oval_dir_path}")
            os.makedirs(self.oval_dir_path)

        oval_file_path = os.path.join(self.oval_dir_path, self.__oval_file_name__.format(major_version))
        download_url = self.__oval_url__.format(major_version)
        self.urls.append(download_url)

        self.logger.info(
            "downloading OVAL file for SLES %s from %s",
            major_version,
            download_url,
        )
        r = http.get(download_url, self.logger, stream=True, timeout=self.download_timeout)

        with open(oval_file_path, "wb") as fp:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    fp.write(chunk)
                    fp.flush()

        return oval_file_path

    @classmethod
    def _get_name_and_version_from_test(
        cls,
        test_id: str,
        tests_dict: dict,
        artifacts_dict: dict,
        versions_dict: dict,
    ) -> tuple[str | None, str | None]:
        name = None
        version = None

        test_obj = tests_dict.get(test_id)
        if not test_obj:
            cls.logger.debug(
                "test reference not found for %s",
                test_id,
            )
            return name, version

        name_obj = artifacts_dict.get(test_obj.artifact_id)
        if not name_obj:
            cls.logger.debug(
                "object reference not found for %s",
                test_obj.artifact_id,
            )
            return name, version

        version_obj = versions_dict.get(test_obj.version_id)
        if not version_obj:
            cls.logger.debug(
                "state reference not found for %s",
                test_obj.version_id,
            )
            return name, version

        name = name_obj.name
        version = version_obj.value

        return name, version

    @classmethod
    def _make_cvss(cls, cvss_vector: str, vulnerability_id: str) -> CVSS | None:
        try:
            cvss3_obj = CVSS3(cvss_vector)

            cvss_object = CVSS(
                version=f"3.{cvss3_obj.minor_version}",
                vector_string=cvss_vector,
                base_metrics=CVSSBaseMetrics(
                    base_score=float(cvss3_obj.base_score.quantize(Decimal("0.1"))),
                    exploitability_score=float(cvss3_obj.esc.quantize(Decimal("0.1"))),
                    impact_score=float(cvss3_obj.isc.quantize(Decimal("0.1"))),
                    base_severity=cvss3_obj.severities()[0],
                ),
                status="N/A",
            )
        except (CVSS3MalformedError, DecimalException, AttributeError):
            cls.logger.exception(
                "error transforming CVSS vector %s, skipping it for %s",
                cvss_vector,
                vulnerability_id,
            )
            cvss_object = None

        return cvss_object

    @classmethod
    def _release_resolver(
        cls,
        version_release_feed: dict[str, dict[str, Vulnerability]],
        vulnerability_id: str,
    ) -> list[Vulnerability]:
        """
        An observation from the raw data shows that the same version could have multiple release names.
        Each of these release names is associated with a vulnerability object and those objects may be different
        even for the same version. This is an issue for the normalized data, namespacing in particular. Namespaces are
        created based on the version, they don't account for release names within a single version

        To address the issue this condensing function iterates through the map and picks one feed object per version.
        It prioritizes sles-release over sles-ltss-release since the latter is not available as a container image

        The input to this function version-release-feed map looks like this
        {
           15: {sles-release: vuln-a}, {sles-ltss-release: vuln-b}
           15.1: {"foo": vuln-c}
        }
        And the output would be
        [
          vuln-a,
          vuln-c
        ]
        """
        results = []
        for version, release_feed in version_release_feed.items():
            if len(release_feed) == 1:
                results.extend(release_feed.values())
                continue

            result = release_feed.get("sles-release")
            if result:
                results.append(result)
                continue

            result = release_feed.get("sles-ltss-release")
            if result:
                results.append(result)
                continue

            cls.logger.debug(
                "multiple unrecognized release names %s for %s, skipping %s for this namespace",
                list(release_feed.keys()),
                version,
                vulnerability_id,
            )

        return results

    @classmethod
    def _transform_oval_vulnerabilities(cls, major_version: str, parsed_dict: dict) -> list[Vulnerability]:  # noqa: C901
        cls.logger.info(
            "generating normalized vulnerabilities from oval vulnerabilities for %s",
            major_version,
        )

        vulnerabilities_dict = parsed_dict.get(OVALElementEnum.VULNERABILITY)
        tests_dict = parsed_dict.get(OVALElementEnum.TEST)
        artifacts_dict = parsed_dict.get(OVALElementEnum.ARTIFACT)
        versions_dict = parsed_dict.get(OVALElementEnum.VERSION)
        results = []

        if not vulnerabilities_dict or not tests_dict or not artifacts_dict or not versions_dict:
            return results

        for identity, vulnerability_obj in vulnerabilities_dict.items():  # noqa: B007
            # version->release->feed map
            version_release_feed = defaultdict()

            # process CVSS once per oval vulnerability and reuse it for all normalized vulnerabilities
            normalized_cvss_list = []
            for cvss_vector in vulnerability_obj.cvss_v3_vectors:
                cvss_object = cls._make_cvss(cvss_vector, vulnerability_obj.name)
                if cvss_object:
                    normalized_cvss_list.append(cvss_object)

            # process impact item, each impact translates to a normalized vulnerability
            for impact_item in vulnerability_obj.impact:
                # get the release and version
                (
                    release_name,
                    release_version,
                ) = cls._get_name_and_version_from_test(
                    impact_item.namespace_test_id,
                    tests_dict,
                    artifacts_dict,
                    versions_dict,
                )

                # validate release
                if not release_name:
                    cls.logger.debug(
                        "release name is invalid, skipping %s",
                        vulnerability_obj.name,
                    )
                    continue

                # validate version is inline with major version
                if not release_version or not release_version.startswith(major_version):
                    cls.logger.debug(
                        "%s %s is an unsupported namespace for major version %s, skipping %s for this namespace",
                        release_name,
                        release_version,
                        major_version,
                        vulnerability_obj.name,
                    )
                    continue

                # construct the feed namespace and payload
                feed_ns = f"{namespace}:{release_version}"

                # normalized fixes
                fixes = []
                for test_id in impact_item.affected_test_ids:
                    (
                        pkg_name,
                        pkg_version,
                    ) = cls._get_name_and_version_from_test(test_id, tests_dict, artifacts_dict, versions_dict)
                    if not pkg_name or not pkg_version:
                        cls.logger.debug(
                            "package name and or version invalid, skipping fixed-in for %s",
                            test_id,
                        )
                        continue

                    fixes.append(
                        FixedIn(
                            Name=pkg_name,
                            NamespaceName=feed_ns,
                            VersionFormat="rpm",
                            Version=pkg_version,
                            Module=None,
                            VendorAdvisory=None,
                        ),
                    )

                # create the normalized vulnerability
                feed_obj = Vulnerability(
                    Name=vulnerability_obj.name,
                    NamespaceName=feed_ns,
                    Description=vulnerability_obj.description,
                    Severity=vulnerability_obj.severity,
                    Link=vulnerability_obj.link,
                    CVSS=normalized_cvss_list,
                    FixedIn=fixes,
                )

                if release_version not in version_release_feed:
                    version_release_feed[release_version] = defaultdict(Vulnerability)

                version_release_feed[release_version][release_name] = feed_obj

            # resolve multiple normalized entries per version
            results.extend(cls._release_resolver(version_release_feed, vulnerability_obj.name))

            # free the contents
            version_release_feed.clear()

        return results

    def get(self):
        parser_factory = OVALParserFactory(
            parsers=[
                SLESVulnerabilityParser,
                TestParser,
                ArtifactParser,
                VersionParser,
            ],
            element_enum=OVALElementEnum,
        )
        parsed_dict = None

        for major_version in self.allow_versions:
            try:
                # download oval
                oval_file_path = self._download(major_version)

                # parse oval contents
                parsed_dict = iter_parse_vulnerability_file(
                    oval_file_path,
                    parser_config=PARSER_CONFIG,
                    parser_factory=parser_factory,
                )

                # map oval data to feed vulnerabilities
                for item in self._transform_oval_vulnerabilities(major_version, parsed_dict):
                    yield item.NamespaceName, item.Name, item.to_payload()
            except Exception:
                self.logger.exception("error processing OVAL for SLES %s", major_version)
                if parsed_dict:
                    parsed_dict.clear()


@dataclass
class SLESOVALVulnerability(Parsed):
    name: str
    severity: str
    description: str
    link: str
    cvss_v3_vectors: list[str]
    impact: list[Impact]


class SLESVulnerabilityParser(VulnerabilityParser):
    # this is pretty odd, but there are classmethods that need logging
    logger = logging.getLogger("sles-vulnerability-parser")

    @classmethod
    def parse(cls, xml_element, config: OVALParserConfig) -> SLESOVALVulnerability | None:
        identity = name = severity = description = link = None
        impact = cvss = []
        try:
            identity = xml_element.attrib["id"]

            oval_ns_match = re.search(config.namespace_regex, xml_element.tag)
            oval_ns = oval_ns_match.group(1) if oval_ns_match and len(oval_ns_match.groups()) > 0 else ""

            # def_version = xml_element.attrib["version"]
            name = xml_element.find(config.title_xpath_query.format(oval_ns)).text
            severity_element = xml_element.find(config.severity_xpath_query.format(oval_ns))
            try:
                severity = config.severity_map.get(severity_element.text.lower())
            except Exception:
                cls.logger.info("unknown severity due to exception", exc_info=True)
                severity = "Unknown"
                # TODO temporary hack! sles 15 data was tripping this, figure out a better way
            description = xml_element.find(config.description_xpath_query.format(oval_ns)).text.strip()
            suse_ref = xml_element.find(config.source_url_xpath_query.format(oval_ns))
            link = suse_ref.attrib["ref_url"]

            cvss = []
            for cve in xml_element.iterfind(config.cve_xpath_query.format(oval_ns)):
                # example cve element
                # <cve impact="important" cvss3="7/CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" href="https://www.suse.com/security/cve/CVE-2021-29154/">CVE-2021-29154</cve>
                if "cvss3" in cve.attrib:
                    cvss_v3 = cve.attrib["cvss3"]
                    if cvss_v3.startswith("CVSS"):
                        vector = cvss_v3
                    else:
                        _, vector = cvss_v3.split("/", 1)
                    cvss.append(vector)

            impact = VulnerabilityParser._parse_criteria(xml_element, oval_ns, config)  # noqa: SLF001
        except Exception:
            cls.logger.exception("ignoring error and skip parsing vulnerability definition element")
            identity = name = severity = description = link = None
            impact = cvss = []

        if identity and name and severity and link:
            return SLESOVALVulnerability(
                identity=identity,
                name=name,
                severity=severity,
                description=description,
                link=link,
                cvss_v3_vectors=cvss,
                impact=impact,
            )

        return None
