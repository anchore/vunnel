from __future__ import annotations

import enum
import re
import tempfile

import defusedxml.ElementTree as ET
import pytest
from vunnel.utils.oval_v2 import (
    Artifact,
    ArtifactParser,
    OVALElementEnum,
    OVALElementParser,
    OVALParserConfig,
    OVALParserFactory,
    Test,
    TestParser,
    Version,
    VersionParser,
    iter_parse_vulnerability_file,
)

# in order to avoid pytest to collect this class as a test
# (e.g. "PytestCollectionWarning: cannot collect test class 'Test' because it has a __init__ constructor")
Test.__test__ = False
TestParser.__test__ = False


@pytest.fixture()
def dummy_config():
    return OVALParserConfig(
        platform_regex=None,
        artifact_regex=None,
        source_url_xpath_query=None,
        severity_xpath_query=None,
        severity_map=None,
    )


class TestTestParser:
    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(
                '<rpminfo_test id="oval:org.opensuse.security:tst:2009223735" version="1" comment="sle-module-basesystem-release is ==15" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'  # noqa: E501
                + '<object object_ref="oval:org.opensuse.security:obj:2009042619"/>'
                + '<state state_ref="oval:org.opensuse.security:ste:2009061809"/>'
                + "</rpminfo_test>",
                id="with-namespace",
            ),
            pytest.param(
                '<rpminfo_test id="oval:org.opensuse.security:tst:2009223735" version="1" comment="sle-module-basesystem-release is ==15" check="at least one">'  # noqa: E501
                + '<object object_ref="oval:org.opensuse.security:obj:2009042619"/>'
                + '<state state_ref="oval:org.opensuse.security:ste:2009061809"/>'
                + "</rpminfo_test>",
                id="without-namespace",
            ),
        ],
    )
    def test_happy_path(self, dummy_config, element):
        xml_element = ET.fromstring(element)
        result = TestParser.parse(xml_element, dummy_config)
        assert result
        assert isinstance(result, Test)
        assert result.identity == "oval:org.opensuse.security:tst:2009223735"
        assert result.artifact_id == "oval:org.opensuse.security:obj:2009042619"
        assert result.version_id == "oval:org.opensuse.security:ste:2009061809"

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="blank"),
            pytest.param(ET.fromstring('<rpminfo_object id="dummy"/>'), id="not-test"),
            pytest.param(
                ET.fromstring('<rpminfo_test id="dummy" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"/>'),
                id="invalid-test",
            ),
        ],
    )
    def test_unhappy_paths(self, dummy_config, element):
        assert TestParser.parse(element, dummy_config) is None


class TestArtifactParser:
    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(
                '<rpminfo_object id="oval:org.opensuse.security:obj:2009041419" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'  # noqa: E501
                + "<name>policycoreutils-python</name>"
                + "</rpminfo_object>",
                id="with-namespace",
            ),
            pytest.param(
                '<rpminfo_object id="oval:org.opensuse.security:obj:2009041419" version="1">'
                + "<name>policycoreutils-python</name>"
                + "</rpminfo_object>",
                id="without-namespace",
            ),
        ],
    )
    def test_happy_path(self, dummy_config, element):
        xml_element = ET.fromstring(element)
        result = ArtifactParser.parse(xml_element, dummy_config)
        assert result
        assert isinstance(result, Artifact)
        assert result.identity == "oval:org.opensuse.security:obj:2009041419"
        assert result.name == "policycoreutils-python"

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="blank"),
            pytest.param(ET.fromstring('<rpminfo_state id="dummy"/>'), id="not-artifact"),
            pytest.param(
                ET.fromstring(
                    '<rpminfo_object id="dummy" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"/>',  # noqa: E501
                ),
                id="invalid-artifact",
            ),
        ],
    )
    def test_unhappy_paths(self, dummy_config, element):
        assert ArtifactParser.parse(element, dummy_config) is None


class TestVersionParser:
    @pytest.mark.parametrize(
        ("element", "identity", "op", "value"),
        [
            pytest.param(
                '<rpminfo_state id="oval:org.opensuse.security:ste:2009079458" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'  # noqa: E501
                + '<version operation="equals">0</version>'
                + "</rpminfo_state>",
                "oval:org.opensuse.security:ste:2009079458",
                "equals",
                "0",
                id="version-with-namespace",
            ),
            pytest.param(
                '<rpminfo_state id="oval:org.opensuse.security:ste:2009111500" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'  # noqa: E501
                + '<evr datatype="evr_string" operation="less than">0:1.15.2-4.25</evr>'
                + '<arch datatype="string" operation="pattern match">(noarch)</arch>'
                + "</rpminfo_state>",
                "oval:org.opensuse.security:ste:2009111500",
                "less than",
                "0:1.15.2-4.25",
                id="evr-with-namespace",
            ),
            pytest.param(
                '<rpminfo_state id="oval:org.opensuse.security:ste:2009079458" version="1">'
                + '<version operation="equals">0</version>'
                + "</rpminfo_state>",
                "oval:org.opensuse.security:ste:2009079458",
                "equals",
                "0",
                id="version-without-namespace",
            ),
            pytest.param(
                '<rpminfo_state id="oval:org.opensuse.security:ste:2009111500" version="1">'
                + '<evr datatype="evr_string" operation="less than">0:1.15.2-4.25</evr>'
                + "</rpminfo_state>",
                "oval:org.opensuse.security:ste:2009111500",
                "less than",
                "0:1.15.2-4.25",
                id="evr-without-namespace",
            ),
        ],
    )
    def test_happy_path(self, dummy_config, element, identity, op, value):
        xml_element = ET.fromstring(element)
        result = VersionParser.parse(xml_element, dummy_config)
        assert result
        assert isinstance(result, Version)
        assert result.identity == identity
        assert result.operation == op
        assert result.value == value

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="blank"),
            pytest.param(ET.fromstring('<rpminfo_test id="dummy"/>'), id="not-version"),
            pytest.param(
                ET.fromstring(
                    '<rpminfo_state id="dummy" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"/>',  # noqa: E501
                ),
                id="invalid-version",
            ),
        ],
    )
    def test_unhappy_paths(self, dummy_config, element):
        assert ArtifactParser.parse(element, dummy_config) is None


class TestParserFactory:
    @pytest.fixture()
    def invalid_parsers_error(self):
        return "Invalid input for parsers, must be a list of OVALElementParser sub-classes"

    @pytest.fixture()
    def invalid_enum_error(self):
        return "Invalid input for oval element enumeration, must be a python enum class"

    @pytest.fixture()
    def parser_enum_mismatch_error(self):
        return "Parsers are not a match for the oval element enumeration"

    @pytest.fixture()
    def example_enum_class(self):
        class RandomEnum(enum.Enum):
            FOO = "foo"

        return RandomEnum

    @pytest.fixture()
    def example_parser_class(self, example_enum_class):
        class RandomParser(OVALElementParser):
            oval_element = example_enum_class.FOO

            @staticmethod
            def parse(xml_element, config: OVALParserConfig):
                pass

        return RandomParser

    @pytest.mark.parametrize(
        ("parsers", "oval_enum"),
        [
            pytest.param(
                [
                    TestParser,
                    ArtifactParser,
                    VersionParser,
                ],
                OVALElementEnum,
                id="missing-parser",
            ),
        ],
    )
    def test_init_parser_enum_mismatch(self, parsers, oval_enum, parser_enum_mismatch_error):
        with pytest.raises(ValueError) as e:
            OVALParserFactory(parsers, oval_enum)
        assert str(e.value) == parser_enum_mismatch_error

    @pytest.mark.parametrize(
        "parsers",
        [
            pytest.param(None, id="none"),
            pytest.param({}, id="wrong-type-dict"),
            pytest.param([], id="empty"),
            pytest.param("", id="wrong-type-string"),
        ],
    )
    def test_init_invalid_parsers(self, parsers, invalid_parsers_error):
        with pytest.raises(ValueError) as e:
            OVALParserFactory(parsers, None)
        assert str(e.value) == invalid_parsers_error

    @pytest.mark.parametrize(
        "test_enum_class",
        [
            pytest.param(None, id="none"),
            pytest.param({}, id="wrong-type-dict"),
            pytest.param("", id="wrong-type-string"),
        ],
    )
    def test_init_invalid_oval_enum(self, test_enum_class, invalid_enum_error):
        with pytest.raises(ValueError) as e:
            OVALParserFactory([TestParser], test_enum_class)
        assert str(e.value) == invalid_enum_error

    def test_init_happy_path(self, example_enum_class, example_parser_class):
        pf = OVALParserFactory(
            parsers=[example_parser_class],
            element_enum=example_enum_class,
        )
        assert pf
        assert isinstance(pf, OVALParserFactory)

    def test_get_parser_happy_path(self, example_enum_class, example_parser_class):
        pf = OVALParserFactory(
            parsers=[example_parser_class],
            element_enum=example_enum_class,
        )
        parser = pf.get_parser(example_enum_class.FOO)
        assert parser
        assert parser == example_parser_class

        pf.parser_map = {}
        parser = pf.get_parser(example_enum_class.FOO)
        assert parser is None

    @pytest.mark.parametrize(
        "test_enum_class",
        [
            pytest.param(None, id="none"),
            pytest.param({}, id="wrong-type-dict"),
            pytest.param("", id="wrong-type-string"),
            pytest.param(OVALElementEnum.TEST, id="wrong-type-enum"),
        ],
    )
    def test_get_parser_invalid_input(self, test_enum_class, example_enum_class, example_parser_class):
        pf = OVALParserFactory(
            parsers=[example_parser_class],
            element_enum=example_enum_class,
        )
        parser = pf.get_parser(test_enum_class)

        assert parser is None

    @pytest.mark.parametrize(
        "test_xml_element",
        [
            pytest.param(ET.fromstring('<foo id="dummy"/>'), id="valid-tag"),
            pytest.param(
                ET.fromstring('<foo id="dummy" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"/>'),
                id="valid-tag-with-ns",
            ),
        ],
    )
    def test_get_oval_element_happy_path(
        self,
        test_xml_element,
        example_enum_class,
        example_parser_class,
        dummy_config,
    ):
        pf = OVALParserFactory(
            parsers=[example_parser_class],
            element_enum=example_enum_class,
        )

        assert pf.get_oval_element(test_xml_element, dummy_config) == example_enum_class.FOO

    @pytest.mark.parametrize(
        "test_xml_element",
        [
            pytest.param(None, id="none"),
            pytest.param("", id="blank"),
            pytest.param("foobar", id="wrong-type-string"),
            pytest.param(ET.fromstring('<rpminfo_state id="dummy"/>'), id="invalid-tag"),
            pytest.param(
                ET.fromstring(
                    '<rpminfo_object id="dummy" version="1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"/>',
                ),
                id="invalid-tag-with-ns",
            ),
        ],
    )
    def test_get_oval_element_invalid_input(
        self,
        test_xml_element,
        example_enum_class,
        example_parser_class,
        dummy_config,
    ):
        pf = OVALParserFactory(
            parsers=[example_parser_class],
            element_enum=example_enum_class,
        )

        assert pf.get_oval_element(test_xml_element, dummy_config) is None


class TestOVALElementParser:
    @pytest.mark.parametrize(
        ("data", "regex", "expected"),
        [
            pytest.param(
                "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}object",
                re.compile(r"\{http://oval.mitre.org/XMLSchema/.*\}(\w*)"),
                "object",
                id="with-namespace",
            ),
            pytest.param(
                "object",
                re.compile(r"\{http://oval.mitre.org/XMLSchema/.*\}(\w*)"),
                "object",
                id="without-namespace",
            ),
        ],
    )
    def test_find_with_regex_happy_path(self, data, regex, expected):
        assert OVALElementParser._find_with_regex(data, regex) == expected

    @pytest.mark.parametrize(
        ("data", "regex"),
        [
            pytest.param(
                None,
                None,
                id="invalid-1",
            ),
            pytest.param(
                None,
                re.compile(r"foo"),
                id="invalid-2",
            ),
            pytest.param(
                "",
                None,
                id="invalid-3",
            ),
        ],
    )
    def test_find_with_regex_invalid_input(self, data, regex):
        with pytest.raises(Exception):
            OVALElementParser._find_with_regex(data, regex)


class TestIterParse:
    @pytest.mark.parametrize(
        ("content", "tag", "parser_fn", "expected"),
        [
            pytest.param(
                '<rpminfo_test id="oval:org.opensuse.security:tst:2009223735" version="1" comment="sle-module-basesystem-release is ==15" check="at least one" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'  # noqa: E501
                + '<object object_ref="oval:org.opensuse.security:obj:2009042619"/>'
                + '<state state_ref="oval:org.opensuse.security:ste:2009061809"/>'
                + "</rpminfo_test>",
                "rpminfo_test",
                TestParser.parse,
                Test(
                    identity="oval:org.opensuse.security:tst:2009223735",
                    artifact_id="oval:org.opensuse.security:obj:2009042619",
                    version_id="oval:org.opensuse.security:ste:2009061809",
                ),
                id="test-with-namespace",
            ),
            pytest.param(
                '<rpminfo_object id="oval:org.opensuse.security:obj:2009041419" version="1">'
                + "<name>policycoreutils-python</name>"
                + "</rpminfo_object>",
                "rpminfo_object",
                ArtifactParser.parse,
                Artifact(
                    identity="oval:org.opensuse.security:obj:2009041419",
                    name="policycoreutils-python",
                ),
                id="artifact-without-namespace",
            ),
        ],
    )
    def test_iter_parse_vulnerability_file_happy_path(self, dummy_config, content, tag, parser_fn, expected):
        class RandomElements(enum.Enum):
            FOO = tag

        class RandomParser(OVALElementParser):
            oval_element = RandomElements.FOO
            parse = parser_fn

        with tempfile.NamedTemporaryFile(mode="w") as fp:
            fp.write(content)
            fp.seek(0)

            results = iter_parse_vulnerability_file(
                fp.name,
                parser_config=dummy_config,
                parser_factory=OVALParserFactory(parsers=[RandomParser], element_enum=RandomElements),
            )

        assert results
        assert isinstance(results, dict)
        assert len(results) == 1
        assert list(results.keys())[0] == RandomElements.FOO

        foo_map = results.get(RandomElements.FOO)
        assert len(foo_map) == 1
        assert list(foo_map.keys())[0] == expected.identity
        assert foo_map.get(expected.identity) == expected
