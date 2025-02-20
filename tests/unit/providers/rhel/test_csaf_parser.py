from pathlib import Path

import pytest

from vunnel.utils.csaf_types import from_path
from vunnel.providers.rhel.csaf_parser import CSAFParser

from unittest.mock import Mock

@pytest.fixture()
def fixture_dir():
    return Path(__file__).parent / "test-fixtures"

@pytest.fixture()
def csaf_parser(basic_csaf_doc):
    mock_client = Mock()
    mock_client.csaf_doc_for_rhsa.return_value = basic_csaf_doc
    return CSAFParser(workspace=Mock(), client=mock_client, logger=Mock(), download_timeout=125)

@pytest.fixture()
def basic_csaf_doc(fixture_dir):
    return from_path(fixture_dir / "csaf/advisories/rhsa-2023_3821.json")

@pytest.fixture()
def multi_platform_csaf_doc(fixture_dir):
    return from_path(fixture_dir / "csaf/advisories/rhsa-2024_0811.json")


def test_csaf_parser_platform_module_name_version_from_fpi(basic_csaf_doc, csaf_parser):
    fpi = "AppStream-8.8.0.Z.MAIN.EUS:ruby:2.7:8080020230427102918:63b34585:ruby-0:2.7.8-139.module+el8.8.0+18745+f1bef313.src"
    expected_platform_cpe = "cpe:/a:redhat:enterprise_linux:8::appstream"
    expected_module_name = "ruby:2.7"
    expected_package_name = "ruby"
    expected_package_version = "0:2.7.8-139.module+el8.8.0+18745+f1bef313"
    actual_platform_cpe, actual_module_name, actual_package_name, actual_package_version =  csaf_parser.platform_module_name_version_from_fpi(basic_csaf_doc, fpi)
    assert actual_platform_cpe == expected_platform_cpe
    assert actual_module_name == expected_module_name
    assert actual_package_name == expected_package_name
    assert actual_package_version == expected_package_version

def test_best_version_module_from_fpis_package_name(csaf_parser, fixture_dir):
    # and more than one platform
    fpis = [
        # right answer:
        "AppStream-8.8.0.Z.MAIN.EUS:ruby:2.7:8080020230427102918:63b34585:ruby-0:2.7.8-139.module+el8.8.0+18745+f1bef313.src",
        # wrong package name (note: different version):
        "AppStream-8.8.0.Z.MAIN.EUS:ruby:2.7:8080020230427102918:63b34585:rubygem-irb-0:1.2.6-139.module+el8.8.0+18745+f1bef313.noarch",
    ]
    doc = from_path(fixture_dir / "csaf/advisories/rhsa-2023_3821.json")
    actual_version, actual_module = csaf_parser.best_version_module_from_fpis(
        doc,
        "RHSA-2023:3821",
        fpis,
        "ruby",
        "cpe:/a:redhat:enterprise_linux:8")
    assert actual_version == "0:2.7.8-139.module+el8.8.0+18745+f1bef313"
    assert actual_module == "ruby:2.7"

def test_best_version_module_from_fpis_multi_platform(csaf_parser, fixture_dir, multi_platform_csaf_doc):
    fpis = [
        # RHEL 9 variant, has platform cpe like "cpe:/a:redhat:rhel_eus:9.0::appstream"
        "AppStream-9.0.0.Z.EUS:sudo-0:1.9.5p2-7.el9_0.4.src",
        # the right answer, has platform cpe "cpe:/a:redhat:enterprise_linux:9::appstream",
        # which starts with "cpe:/a:redhat:enterprise_linux:9"
        "AppStream-9.3.0.Z.MAIN:sudo-0:1.9.5p2-10.el9_3.src",
        # RHEL 8 variant, has platform cpe like "cpe:/o:redhat:rhel_eus:8.6::baseos"
        "BaseOS-8.6.0.Z.EUS:sudo-0:1.9.5p2-1.el8_6.src",
    ]
    platform_cpe = "cpe:/a:redhat:enterprise_linux:9"
    fix_id = "RHSA-2024:0811"
    actual_version, actual_module = csaf_parser.best_version_module_from_fpis(
        multi_platform_csaf_doc, fix_id, fpis, "sudo", platform_cpe,
    )
    assert actual_module is None
    assert actual_version == "0:1.9.5p2-10.el9_3"
