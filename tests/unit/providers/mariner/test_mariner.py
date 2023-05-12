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
                    Name="mysql",
                    NamespaceName="mariner:2.0",
                    Description="CVE-2023-21980 affecting package mysql 8.0.32-1. An upgraded version of the package is available that resolves this issue.",
                    Severity="High",
                    Link="https://nvd.nist.gov/vuln/detail/CVE-2023-21980",
                    CVSS=[],
                    FixedIn=[FixedIn(Name="mysql", NamespaceName="mariner:2.0", VersionFormat="rpm", Version="0:8.0.33-1.cm2")],
                    Metadata={},
                ),
                Vulnerability(
                    Name="mysql",
                    NamespaceName="mariner:2.0",
                    Description="CVE-2023-21977 affecting package mysql 8.0.32-1. An upgraded version of the package is available that resolves this issue.",
                    Severity="Medium",
                    Link="https://nvd.nist.gov/vuln/detail/CVE-2023-21977",
                    CVSS=[],
                    FixedIn=[FixedIn(Name="mysql", NamespaceName="mariner:2.0", VersionFormat="rpm", Version="0:8.0.33-1.cm2")],
                    Metadata={},
                ),
            ],
        )
    ],
)
def test_parse(tmpdir, helpers, input_file, expected):
    mock_data_path = helpers.local_dir(input_file)
    subject = MarinerXmlFile(mock_data_path, logger=logging.getLogger("test_pariner"))

    vulnerabilities = [v for v in subject.vulnerabilities()]
    assert vulnerabilities == expected
