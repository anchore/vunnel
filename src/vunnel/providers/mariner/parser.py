from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from lxml import etree
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

from vunnel.providers.mariner.model import Definition, RpminfoObject, RpminfoState, RpminfoTest
from vunnel.utils import http_wrapper as http
from vunnel.utils.vulnerability import FixedIn, Vulnerability

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

    from vunnel.workspace import Workspace

LESS_THAN_OR_EQUAL_TO = "less than or equal"
LESS_THAN = "less than"
GREATER_THAN = "greater than"

IGNORED_PATCHABLE_VALUES = ["Not Applicable"]


class MarinerXmlFile:
    def __init__(self, oval_file_path: str, logger: logging.Logger):
        parser_config = ParserConfig(
            fail_on_converter_warnings=False,
            fail_on_unknown_attributes=False,
            fail_on_unknown_properties=False,
        )
        xml_parser = XmlParser(config=parser_config)
        # S320 disable explanation: the mariner linux vulnerability feed is not untrusted xml
        root = etree.parse(oval_file_path)  # noqa: S320
        nsmap = etree.XPath("/*")(root)[0].nsmap
        default = nsmap[None]
        nsmap["default"] = default
        del nsmap[None]
        self.logger = logger

        # Go element by element to have flexible error handling
        self.definitions = []
        for def_element in etree.XPath("//default:definition", namespaces=nsmap)(root):
            try:
                element_bytes = etree.tostring(def_element)
                definition = xml_parser.from_string(element_bytes.decode(), Definition)
                self.definitions.append(definition)
            except Exception as ex:
                self.logger.warning(f"skipping definition element in {oval_file_path} due to {ex}")

        self.tests_by_id = {}
        for test_element in etree.XPath("//linux-def:rpminfo_test", namespaces=nsmap)(root):
            try:
                element_bytes = etree.tostring(test_element)
                test_obj = xml_parser.from_string(element_bytes.decode(), RpminfoTest)
                self.tests_by_id[test_obj.id] = test_obj
            except Exception as ex:
                self.logger.warning(f"skipping rpminfo_test element in {oval_file_path} due to {ex}")
        self.objects_by_id = {}
        for obj_element in etree.XPath("//linux-def:rpminfo_object", namespaces=nsmap)(root):
            try:
                element_bytes = etree.tostring(obj_element)
                obj = xml_parser.from_string(element_bytes.decode(), RpminfoObject)
                self.objects_by_id[obj.id] = obj
            except Exception as ex:
                self.logger.warning(f"skipping rpminfo_object element in {oval_file_path} due to {ex}")

        self.states_by_id = {}
        for state_element in etree.XPath("//linux-def:rpminfo_state", namespaces=nsmap)(root):
            try:
                element_bytes = etree.tostring(state_element)
                state_obj = xml_parser.from_string(element_bytes.decode(), RpminfoState)
                self.states_by_id[state_obj.id] = state_obj
            except Exception as ex:
                self.logger.warning(f"skipping rpminfo_object element in {oval_file_path} due to {ex}")
        self.mariner_version = oval_file_path.split("-")[-2]

    def name_and_version(self, test_id: str) -> tuple[str | None, str | None]:
        test = self.tests_by_id.get(test_id, None)
        if test is None or test.object_value is None or test.state is None:
            return (None, None)
        obj = self.objects_by_id.get(test.object_value.object_ref, None)
        if obj is None:
            return (None, None)
        state = self.states_by_id.get(test.state.state_ref, None)
        if state is None or state.evr is None:
            return (None, None)
        return (obj.name, state.evr.value)

    def namespace_name(self) -> str:
        return f"mariner:{self.mariner_version}"

    def get_tests(self, definition: Definition) -> list[RpminfoTest]:
        tests = []
        if definition and definition.criteria and definition.criteria.criterion:
            for criterion in definition.criteria.criterion:
                test = self.tests_by_id.get(criterion.test_ref, None)
                if test:
                    tests.append(test)
        return tests

    def get_states(self, tests: list[RpminfoTest]) -> list[RpminfoState]:
        states = []
        for test in tests:
            if test and test.state and test.state.state_ref:
                state = self.states_by_id.get(test.state.state_ref, None)
                if state:
                    states.append(state)
        return states

    def get_objects(self, tests: list[RpminfoTest]) -> list[RpminfoObject]:
        objects = []
        for test in tests:
            if test and test.object_value and test.object_value.object_ref:
                obj = self.objects_by_id.get(test.object_value.object_ref, None)
                if obj:
                    objects.append(obj)
        return objects

    def make_fixed_in(self, definition: Definition) -> FixedIn | None:
        tests = self.get_tests(definition)
        states = self.get_states(tests)
        objects = self.get_objects(tests)

        if not states or not objects:
            return None

        name = objects[0].name
        if not name:
            return None

        fixed_version = None

        vulnerability_range = []
        for state in states:
            if state.evr and state.evr.value:
                if state.evr.operation == LESS_THAN:
                    vulnerability_range.append(f"< {state.evr.value}")
                    # if vulnerability has an upper bound (< as opposed to <=),
                    # then assume the upper bound is the fixed version
                    fixed_version = state.evr.value
                elif state.evr.operation == GREATER_THAN:
                    vulnerability_range.append(f"> {state.evr.value}")
                elif state.evr.operation == LESS_THAN_OR_EQUAL_TO:
                    vulnerability_range.append(f"<= {state.evr.value}")

        if not vulnerability_range:
            return None

        # make output deterministic. Reverse so that
        # output reads like >1.2.3 <1.3.0 instead of the reverse.
        vulnerability_range.sort(reverse=True)

        if not fixed_version:
            fixed_version = "None"  # a required string in JSON schema

        vulnerability_range_str = ", ".join(vulnerability_range)

        return FixedIn(
            Name=name,
            NamespaceName=self.namespace_name(),
            VersionFormat="rpm",
            Version=fixed_version,
            VulnerableRange=vulnerability_range_str,
            Module=None,
            VendorAdvisory=None,
        )

    def vulnerability_id(self, definition: Definition) -> str | None:
        if definition.metadata is None or definition.metadata.reference is None or definition.metadata.reference.ref_id is None:
            return None
        return definition.metadata.reference.ref_id

    def description(self, definition: Definition) -> str | None:
        if not definition.metadata:
            return None
        return definition.metadata.description

    def vulnerabilities(self) -> Generator[Vulnerability, None, None]:
        for d in self.definitions:
            if d.metadata is None or d.metadata.severity is None:
                self.logger.warning("skipping definition because severity could not be found")
                continue
            if d.metadata and d.metadata.patchable and d.metadata.patchable in IGNORED_PATCHABLE_VALUES:
                continue
            link = ""
            if d.metadata.reference and d.metadata.reference.ref_url:
                link = d.metadata.reference.ref_url
            fixed_in = self.make_fixed_in(d)
            if not fixed_in:
                continue
            vulnerability_id = self.vulnerability_id(d)
            if not vulnerability_id:
                continue
            yield Vulnerability(
                Name=vulnerability_id,  # intentional; legacy API uses Name as field for vulnerability ID.
                NamespaceName=self.namespace_name(),
                Description=self.description(d) or "",
                Severity=d.metadata.severity,
                Link=link,
                CVSS=[],
                FixedIn=[fixed_in],
                Metadata={},  # Ideally, there's no metadata here.
            )


MARINER_URL_BASE = "https://raw.githubusercontent.com/microsoft/CBL-MarinerVulnerabilityData/main/{}"
MARINER_URL_FILENAME = "cbl-mariner-{}-oval.xml"
AL3_URL = "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml"

VERSION_TO_URL = {
    "1.0": MARINER_URL_BASE.format(MARINER_URL_FILENAME.format("1.0")),
    "2.0": MARINER_URL_BASE.format(MARINER_URL_FILENAME.format("2.0")),
    "3.0": AL3_URL,
}

VERSION_TO_FILENAME = {
    "1.0": MARINER_URL_FILENAME.format("1.0"),
    "2.0": MARINER_URL_FILENAME.format("2.0"),
    "3.0": "azurelinux-3.0-oval.xml",
}


class Parser:
    def __init__(self, workspace: Workspace, download_timeout: int, allow_versions: list[Any], logger: logging.Logger):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.allow_versions = allow_versions
        self._urls: set[str] = set()
        self.logger = logger

    def _download(self) -> list[str]:
        return [self._download_version(v) for v in self.allow_versions]

    def _download_version(self, version: str) -> str:
        filename = VERSION_TO_FILENAME[version]
        if not filename:
            raise Exception(f"mariner/azurelinux provider misconfigured: no filename for version {version}")
        url = VERSION_TO_URL[version]
        if not url:
            raise Exception(f"mariner/azurelinux provider misconfigured: no URL for version {version}")
        r = http.get(url, self.logger, timeout=self.download_timeout)
        destination = os.path.join(self.workspace.input_path, filename)
        with open(destination, "wb") as writer:
            writer.write(r.content)
        self._urls.add(url)
        return destination

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def get(self) -> Generator[tuple[str, str, dict[str, dict[str, Any]]], None, None]:
        for oval_file_path in self._download():
            parsed_file = MarinerXmlFile(oval_file_path, self.logger)
            for v in parsed_file.vulnerabilities():
                yield v.NamespaceName, v.Name, v.to_payload()
