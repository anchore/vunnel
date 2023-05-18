from __future__ import annotations
import logging

import shutil

import pytest
from pytest_unordered import unordered
from vunnel import result, workspace
from vunnel.providers.mariner import Config, Provider, parser
from vunnel.providers.mariner.parser import MarinerXmlFile
from vunnel.utils.vulnerability import Vulnerability, FixedIn


@pytest.mark.parametrize(
    ("input_file", "expected"),
    [
        (
            "test-fixtures/mariner-truncated-2.0-oval.xml",
            [
                Vulnerability(
                    Name="CVE-2023-21980",
                    NamespaceName="mariner:2.0",
                    Description="CVE-2023-21980 affecting package mysql 8.0.32-1. An upgraded version of the package is available that resolves this issue.",
                    Severity="High",
                    Link="https://nvd.nist.gov/vuln/detail/CVE-2023-21980",
                    CVSS=[],
                    FixedIn=[FixedIn(Name="mysql", NamespaceName="mariner:2.0", VersionFormat="rpm", Version="0:8.0.33-1.cm2")],
                    Metadata={},
                ),
                Vulnerability(
                    Name="CVE-2023-21977",
                    NamespaceName="mariner:2.0",
                    Description="CVE-2023-21977 affecting package mysql 8.0.32-1. An upgraded version of the package is available that resolves this issue.",
                    Severity="Medium",
                    Link="https://nvd.nist.gov/vuln/detail/CVE-2023-21977",
                    CVSS=[],
                    FixedIn=[FixedIn(Name="mysql", NamespaceName="mariner:2.0", VersionFormat="rpm", Version="0:8.0.33-1.cm2")],
                    Metadata={},
                ),
                Vulnerability(
                    Name="CVE-2022-3736",
                    NamespaceName="mariner:2.0",
                    Description="CVE-2022-3736 affecting package bind 9.16.33-1. No patch is available currently.",
                    Severity="High",
                    Link="https://nvd.nist.gov/vuln/detail/CVE-2022-3736",
                    CVSS=[],
                    FixedIn=[
                        FixedIn(Name="bind", NamespaceName="mariner:2.0", VersionFormat="rpm", Version="None"),
                    ],
                ),
            ],
        )
    ],
)
def test_parse(tmpdir, helpers, input_file, expected):
    mock_data_path = helpers.local_dir(input_file)
    subject = MarinerXmlFile(mock_data_path, logger=logging.getLogger("test_pariner"))

    vulnerabilities = [v for v in subject.vulnerabilities()]
    assert len(vulnerabilities) == len(expected)
    assert vulnerabilities == expected
