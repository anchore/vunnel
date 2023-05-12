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

    def vulnerabilities(self) -> Generator[Vulnerability, None, None]:
        ns = self.namespace_name()
        for d in self.definitions:
            if d.criteria is None or d.criteria.criterion is None or d.criteria.criterion.test_ref is None:
                self.logger.warning("skipping definition it is missing criteria to identify package")
                continue
            name, version = self.name_and_version(d.criteria.criterion.test_ref)
            if name is None:
                self.logger.warning("skipping definition because package name could not be found")
                continue
            if version is None:
                self.logger.warning("skipping definition because package version could not be found")
                continue
            if d.metadata is None or d.metadata.severity is None:
                self.logger.warning("skipping definition because severity could not be found")
                continue
            description = ""
            if d.metadata.description:
                description = d.metadata.description
            link = ""
            if d.metadata.reference and d.metadata.reference.ref_url:
                link = d.metadata.reference.ref_url
            yield Vulnerability(
                Name=name,
                NamespaceName=self.namespace_name(),
                Description=description,
                Severity=d.metadata.severity,
                Link=link,
                CVSS=[],
                FixedIn=[
                    FixedIn(Name=name, NamespaceName=ns, VersionFormat="rpm", Version=version),
                ],
                Metadata={},
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
