from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import requests
from lxml import etree
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

from vunnel.providers.mariner.model import Definition, RpminfoObject, RpminfoState, RpminfoTest
from vunnel.utils.vulnerability import FixedIn, Vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace

LTE = "less than or equal"


class MarinerXmlFile:
    def __init__(self, oval_file_path: str, logger: logging.Logger):
        parser_config = ParserConfig(
            fail_on_converter_warnings=False,
            fail_on_unknown_attributes=False,
            fail_on_unknown_properties=False,
        )
        xml_parser = XmlParser(config=parser_config)
        root = etree.parse(oval_file_path)
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
                pass

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
        self.mariner_version = oval_file_path.split("-")[-2]  # TODO: less brittle way?

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

    def get_test(self, definition: Definition) -> RpminfoTest | None:
        if definition is None or definition.criteria is None or definition.criteria.criterion is None:
            return None
        return self.tests_by_id.get(definition.criteria.criterion.test_ref, None)

    def get_state(self, definition: Definition) -> RpminfoState | None:
        test = self.get_test(definition)
        if test is None or test.state is None or test.state.state_ref is None:
            return None
        return self.states_by_id.get(test.state.state_ref, None)

    def get_object(self, definition: Definition) -> RpminfoObject | None:
        test = self.get_test(definition)
        if test is None or test.object_value is None or test.object_value.object_ref is None:
            return None
        return self.objects_by_id.get(test.object_value.object_ref, None)

    def make_fixed_in(self, definition: Definition) -> FixedIn | None:
        state = self.get_state(definition)
        obj = self.get_object(definition)
        if state is None or state.evr is None:
            return None
        if obj is None or obj.name is None:
            return None
        version = state.evr.value
        if state.evr.operation == LTE:
            version = "None"  # legacy API needs the string "None" instead of None
        return FixedIn(Name=obj.name, NamespaceName=self.namespace_name(), VersionFormat="rpm", Version=version)

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
            if d.metadata.description:
                pass
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
                CVSS=[],  # NOTE: this is not present in OVAL XML.
                # This is a list because because there are several versions
                # Each version is a vector of info about the vulnerability
                # serialized as a string like CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
                # TODO: add test image to https://github.com/anchore/test-images
                FixedIn=[fixed_in],
                Metadata={},  # Ideally, there's no metadata here.
            )


MARINER_URL_BASE = "https://raw.githubusercontent.com/microsoft/CBL-MarinerVulnerabilityData/main/{}"
MARINER_URL_FILENAME = "cbl-mariner-{}-oval.xml"


class Parser:
    logger = logging.getLogger("mariner-parser")

    def __init__(self, workspace: Workspace, download_timeout: int, allow_versions: list[Any], logger: logging.Logger):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.allow_versions = allow_versions  # TODO: use this to pass in "2.0"?
        self._urls: set[str] = set()

    def _download(self) -> list[str]:
        return [self._download_version(v) for v in self.allow_versions]

    def _download_version(self, version: str) -> str:
        filename = MARINER_URL_FILENAME.format(version)
        url = MARINER_URL_BASE.format(filename)
        r = requests.get(url, timeout=self.download_timeout)
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
