"""
A generic framework for parsing an OVAL xml file. Design is based on separate collections/sections in an OVAL schema.
Each section is associated with a parser that can be overridden by the driver. Parsed output represents a view of the
OVAL content, it's up to the driver to transform it into normalized feed data
"""
from __future__ import annotations

import enum
import gzip
import logging
import os
import re
import xml.etree.ElementTree as ET  # nosec (this is only used to get the definition for Element, which is not in defusedxml)
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass

from defusedxml.ElementTree import iterparse


class OVALElementEnum(enum.Enum):
    """
    XML tags of OVAL collection items
    """

    VULNERABILITY = "definition"
    TEST = "rpminfo_test"
    ARTIFACT = "rpminfo_object"
    VERSION = "rpminfo_state"


@dataclass
class OVALParserConfig:
    """
    Configuration for parsing an OVAL file. While the OVAL format is standard, each publisher expresses data slightly
    differently. Use an instance of this class to pass the configuration specific to an OVAL or a publisher
    """

    # to be defined
    # regexes
    platform_regex: re.Pattern
    artifact_regex: re.Pattern

    # xpath queries
    source_url_xpath_query: str

    # severity
    severity_map: dict

    # defaults
    # regexes
    tag_regex = re.compile(r"\{http://oval.mitre.org/XMLSchema/.*\}(\w*)")
    namespace_regex = re.compile(r"(\{http://oval.mitre.org/XMLSchema/.*\})\w*")

    # xpath queries
    title_xpath_query: str = "{0}metadata/{0}title"
    severity_xpath_query: str = "{0}metadata/{0}advisory/{0}severity"
    description_xpath_query: str = "{0}metadata/{0}description"
    cve_xpath_query: str = "{0}metadata/{0}advisory/{0}cve"
    criteria_xpath_query: str = "{0}criteria"


@dataclass
class Parsed(ABC):
    identity: str


@dataclass
class Version(Parsed):
    operation: str
    value: str


@dataclass
class Artifact(Parsed):
    name: str


@dataclass
class Test(Parsed):
    artifact_id: str
    version_id: str


@dataclass()
class Impact:
    namespace_test_id: str
    affected_test_ids: list[str]


class OVALElementParser(ABC):
    oval_element = None

    @staticmethod
    @abstractmethod
    def parse(xml_element: ET.Element, config: OVALParserConfig) -> Parsed | None:
        ...

    @staticmethod
    def _find_with_regex(data: str, regex: re.Pattern):
        """
        Utility function for executing a regular expression over raw data and returning the 1st group if a match is found.
        Returns the raw data as it is if no match was found
        """
        regex_match = re.search(regex, data)
        if regex_match and len(regex_match.groups()) > 0:
            return regex_match.group(1)
        return data


class VulnerabilityParser(OVALElementParser, ABC):
    """
    Parser for processing a definition element of the definitions OVAL collection. The main parse() is intentionally
    left as an abstract function for the driver to implement since each publisher expresses the vulnerability differently
    """

    oval_element = OVALElementEnum.VULNERABILITY

    @staticmethod
    def _parse_criteria(xml_element: ET.Element, oval_ns: str, config: OVALParserConfig) -> list[Impact]:
        """
        The first or outermost criteria with in a definition, may contain nested groups of criteria/criterion bound by
        different operators

        Example of xml element parsed
          <criteria operator="OR">
            <criteria operator="AND">
              <criteria operator="OR">
                <criterion test_ref="oval:org.opensuse.security:tst:2009301949" comment="SUSE Linux Enterprise Module for Basesystem 15 SP3 is installed"/>
                <criterion test_ref="oval:org.opensuse.security:tst:2009341508" comment="SUSE Linux Enterprise Server 15 SP1-LTSS is installed"/>
              </criteria>
              <criteria operator="OR">
                <criterion test_ref="oval:org.opensuse.security:tst:2009624165" comment="sqlite3-3.36.0-3.12.1 is installed"/>
                <criterion test_ref="oval:org.opensuse.security:tst:2009624166" comment="sqlite3-devel-3.36.0-3.12.1 is installed"/>
              </criteria>
            </criteria>
            <criteria operator="AND">
              <criterion test_ref="oval:org.opensuse.security:tst:2009341508" comment="SUSE Linux Enterprise Server 15 SP2 is installed"/>
              <criterion test_ref="oval:org.opensuse.security:tst:2009624165" comment="sqlite3-3.36.0-3.12.1 is installed"/>
            </criteria>
          </criteria
        """  # noqa: E501
        criteria_element = xml_element.find(config.criteria_xpath_query.format(oval_ns))
        results = []

        if not criteria_element:
            return results

        operator = criteria_element.attrib.get("operator")

        if operator and operator.lower() == "or":
            # indicates multiple groups of impacted artifacts, parse each group and gather results
            for child in criteria_element:
                results.extend(VulnerabilityParser._parse_group(child, config))
        else:
            # indicates a single group of impacted artifacts
            results.extend(VulnerabilityParser._parse_group(criteria_element, config))

        return results

    @staticmethod
    def _parse_group(criteria_element: ET.Element, config: OVALParserConfig) -> list[Impact]:
        """
        A logical group is bunch of conditions bound by AND operator

        Example of xml element parsed
        <criteria operator="AND">
          <criteria operator="OR">
            <criterion test_ref="oval:org.opensuse.security:tst:2009301949" comment="SUSE Linux Enterprise Module for Basesystem 15 SP3 is installed"/>
            <criterion test_ref="oval:org.opensuse.security:tst:2009341508" comment="SUSE Linux Enterprise Server 15 SP1-LTSS is installed"/>
          </criteria>
          <criteria operator="OR">
            <criterion test_ref="oval:org.opensuse.security:tst:2009624165" comment="sqlite3-3.36.0-3.12.1 is installed"/>
            <criterion test_ref="oval:org.opensuse.security:tst:2009624166" comment="sqlite3-devel-3.36.0-3.12.1 is installed"/>
          </criteria>
        </criteria>
        """  # noqa: E501
        results = []
        logger = logging.getLogger("oval-v2-parser")

        # further parsing makes the assumption that this element has 2 children, bail out of here if that's not true
        if len(criteria_element) != 2:
            return results

        namespace_ids = VulnerabilityParser._parse_sub_group(criteria_element[0], config, config.platform_regex)

        # assumes 1st child contains platform info and 2nd contains artifact info
        if not namespace_ids:
            return results

        try:
            test_ids = VulnerabilityParser._parse_sub_group(criteria_element[1], config, config.artifact_regex)
        except Exception:
            logger.exception("returning results early due to exception in _parse_sub_group")
            return results

        if not test_ids:
            return results

        for item in namespace_ids:
            results.append(
                Impact(
                    namespace_test_id=item,
                    affected_test_ids=test_ids,
                ),
            )

        return results

    @staticmethod
    def _parse_sub_group(crit_element: ET.Element, config: OVALParserConfig, regex: re.Pattern) -> list[str]:
        """
        A logical sub-group is bunch of conditions bound by OR operator or a single condition

        Examples of xml element parsed
        <criteria operator="OR">
          <criterion test_ref="oval:org.opensuse.security:tst:2009301949" comment="SUSE Linux Enterprise Module for Basesystem 15 SP3 is installed"/>
          <criterion test_ref="oval:org.opensuse.security:tst:2009341508" comment="SUSE Linux Enterprise Server 15 SP1-LTSS is installed"/>
        </criteria>

        <criterion test_ref="oval:org.opensuse.security:tst:2009624165" comment="sqlite3-3.36.0-3.12.1 is installed"/>

        """
        test_ids = []
        crit_tag = OVALElementParser._find_with_regex(crit_element.tag, config.tag_regex)  # noqa: SLF001

        if crit_tag == "criterion" and "comment" in crit_element.attrib:
            regex_match = re.search(regex, crit_element.attrib["comment"])
            if regex_match and "test_ref" in crit_element.attrib:
                test_ids.append(crit_element.attrib["test_ref"])
        elif crit_tag == "criteria":
            for criterion in crit_element:
                if "comment" in criterion.attrib:
                    regex_match = re.search(regex, criterion.attrib["comment"])
                    if regex_match and criterion.attrib.get("test_ref"):
                        test_ids.append(criterion.attrib["test_ref"])

        return test_ids


class TestParser(OVALElementParser):
    """
    Parser for processing a rpminfo_test element of the tests OVAL collection
    """

    oval_element = OVALElementEnum.TEST

    @staticmethod
    def parse(xml_element: ET.Element, config: OVALParserConfig) -> Test | None:
        """
        Examples of xml elements parsed

        <rpminfo_test id="oval:org.opensuse.security:tst:2009223735" version="1" comment="sle-module-basesystem-release is ==15" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
          <object object_ref="oval:org.opensuse.security:obj:2009042619"/>
          <state state_ref="oval:org.opensuse.security:ste:2009061809"/>
        </rpminfo_test>
        """
        logger = logging.getLogger("oval-v2-parser")

        identity = artifact_id = version_id = None
        try:
            identity = xml_element.attrib["id"]
            for child in xml_element:
                child_tag = OVALElementParser._find_with_regex(child.tag, config.tag_regex)  # noqa: SLF001
                if child_tag == "object":
                    artifact_id = child.attrib["object_ref"]
                elif child_tag == "state":
                    version_id = child.attrib["state_ref"]
        except Exception:
            logger.exception("ignoring error parsing test xml element")
            identity = artifact_id = version_id = None

        if identity and artifact_id and version_id:
            return Test(identity=identity, artifact_id=artifact_id, version_id=version_id)
        return None


class ArtifactParser(OVALElementParser):
    """
    Parser for processing a rpminfo_object element of the objects OVAL collection
    """

    oval_element = OVALElementEnum.ARTIFACT

    @staticmethod
    def parse(xml_element: ET.Element, config: OVALParserConfig) -> Artifact | None:
        """
        Example of xml element parsed

        <rpminfo_object id="oval:org.opensuse.security:obj:2009041419" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
          <name>policycoreutils-python</name>
        </rpminfo_object>
        """
        logger = logging.getLogger("oval-v2-parser")

        identity = name = None
        try:
            identity = xml_element.attrib["id"]
            for child in xml_element:
                child_tag = OVALElementParser._find_with_regex(child.tag, config.tag_regex)  # noqa: SLF001

                if child_tag in ["name"]:
                    name = child.text
                    break
        except Exception:
            logger.exception("ignoring error parsing object xml element")
            identity = name = None

        if identity and name:
            return Artifact(identity=identity, name=name)
        return None


class VersionParser(OVALElementParser):
    """
    Parser for processing a rpminfo_state element of the state OVAL collection
    """

    oval_element = OVALElementEnum.VERSION

    @staticmethod
    def parse(xml_element: ET.Element, config: OVALParserConfig) -> Version | None:
        """
        Examples of xml elements parsed

        <rpminfo_state id="oval:org.opensuse.security:ste:2009079458" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
          <version operation="equals">0</version>
        </rpminfo_state>

        <rpminfo_state id="oval:org.opensuse.security:ste:2009111500" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
          <evr datatype="evr_string" operation="less than">0:1.15.2-4.25</evr>
          <arch datatype="string" operation="pattern match">(noarch)</arch>
        </rpminfo_state>
        """
        logger = logging.getLogger("oval-v2-parser")

        identity = op = value = None
        try:
            identity = xml_element.attrib["id"]
            for child in xml_element:
                child_tag = OVALElementParser._find_with_regex(child.tag, config.tag_regex)  # noqa: SLF001
                if child_tag in ["version", "evr"] and "operation" in child.attrib:
                    op = child.attrib["operation"]
                    value = child.text
                    break
        except Exception:
            logger.exception("ignoring error parsing state xml element")
            identity = op = value = None

        if identity and op and value:
            return Version(identity=identity, operation=op, value=value)
        return None


class OVALParserFactory:
    """
    A factory that outputs a parser based on the xml content to be parsed

    Initialize the factory with a list of parser classes and an oval element enumeration.
    The latter ties a parser to the xml tag of element it can process
    """

    def __init__(self, parsers: list[type[OVALElementParser]], element_enum: type[enum.Enum]):
        if not parsers or not isinstance(parsers, list) or any(not issubclass(item, OVALElementParser) for item in parsers):
            raise ValueError("Invalid input for parsers, must be a list of OVALElementParser sub-classes")

        if not element_enum or not issubclass(element_enum, enum.Enum):
            raise ValueError("Invalid input for oval element enumeration, must be a python enum class")

        self.parser_map = {parser.oval_element: parser for parser in parsers}
        self.element_enum = element_enum

        if set(self.element_enum) != set(self.parser_map.keys()):
            raise ValueError("Parsers are not a match for the oval element enumeration")

    def get_parser(self, oval_element: enum.Enum) -> type[OVALElementParser] | None:
        """
        Returns the parser for input oval element if one is available
        """
        if oval_element and isinstance(oval_element, self.element_enum):
            return self.parser_map.get(oval_element)
        return None

    def get_oval_element(self, xml_element: ET.Element, config: OVALParserConfig) -> enum.Enum | None:
        """
        Checks and returns an oval enumeration instance if the xml content is a supported OVAL element
        """
        result = None
        if not ET.iselement(xml_element):
            return result

        tag = OVALElementParser._find_with_regex(xml_element.tag, config.tag_regex)  # noqa: SLF001

        try:
            result = self.element_enum(tag)
        except ValueError:
            result = None

        return result


def iter_parse_vulnerability_file(
    oval_file_path: str,
    parser_config: OVALParserConfig,
    parser_factory: OVALParserFactory,
) -> defaultdict[enum.Enum, dict[str, Parsed]]:
    """
    Starting point for parsing a vulnerability class OVAL file content.
    Iteratively parses the file using the parsers supplied by the input factory.
    Does not load the entire XML file into memory which makes it slower but OVAL files can be huge.
    Returns a dictionary where each key represents an oval element and the values are the parsed instances of that element
    """
    logger = logging.getLogger("oval-v2-parser")

    logger.info(f"parsing {oval_file_path}")
    parsed_dict: defaultdict[enum.Enum, dict[str, Parsed]] = defaultdict(dict)

    if os.path.exists(oval_file_path):
        ingress = False
        opener = open

        if oval_file_path.endswith(".gz"):
            opener = gzip.open

        with opener(oval_file_path, "rb") as f:
            for event, xml_element in iterparse(f, events=("start", "end")):
                # gather definition
                if event == "start" and parser_factory.get_oval_element(xml_element, parser_config):
                    ingress = True
                elif event == "end":
                    # is this an interesting oval element?
                    oval_element = parser_factory.get_oval_element(xml_element, parser_config)

                    # is the interesting oval element in ingress?
                    if oval_element and ingress:
                        # yes and yes, halt ingress and parse the element
                        ingress = False
                        parser = parser_factory.get_parser(oval_element)
                        if parser:
                            result = parser.parse(xml_element, parser_config)
                            if result:
                                parsed_dict[oval_element][result.identity] = result
                            else:
                                logger.warning("unable to parse %s element", repr(oval_element.value))
                        else:
                            logger.warning(
                                "no parser found for oval element %s, skipping",
                                oval_element,
                            )

                # clear the element if doesn't need to be processed or done processing
                if not ingress and event == "end":
                    xml_element.clear()
    else:
        logger.warning(f"{oval_file_path} not found, returning empty results")

    return parsed_dict
