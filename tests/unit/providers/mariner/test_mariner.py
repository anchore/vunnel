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
                    FixedIn=[
                        FixedIn(
                            Name="mysql",
                            NamespaceName="mariner:2.0",
                            VersionFormat="rpm",
                            Version="0:8.0.33-1.cm2",
                            Module=None,
                            VendorAdvisory=None,
                        )
                    ],
                    Metadata={},
                ),
                Vulnerability(
                    Name="CVE-2023-21977",
                    NamespaceName="mariner:2.0",
                    Description="CVE-2023-21977 affecting package mysql 8.0.32-1. An upgraded version of the package is available that resolves this issue.",
                    Severity="Medium",
                    Link="https://nvd.nist.gov/vuln/detail/CVE-2023-21977",
                    CVSS=[],
                    FixedIn=[
                        FixedIn(
                            Name="mysql",
                            NamespaceName="mariner:2.0",
                            VersionFormat="rpm",
                            Version="0:8.0.33-1.cm2",
                            Module=None,
                            VendorAdvisory=None,
                        )
                    ],
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
                        FixedIn(
                            Name="bind",
                            NamespaceName="mariner:2.0",
                            VersionFormat="rpm",
                            Version="None",
                            Module=None,
                            VendorAdvisory=None,
                        ),
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


@pytest.fixture()
def disable_get_requests(monkeypatch):
    def disabled(*args, **kwargs):
        raise RuntimeError("requests disabled but HTTP GET attempted")

    monkeypatch.setattr(parser.requests, "get", disabled)


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(allow_versions=["2.0"])
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/mariner-truncated-2.0-oval.xml")
    shutil.copy(mock_data_path, workspace.input_dir / "mariner-truncated-2.0-oval.xml")

    def mock_download(*args, **kwargs):
        return [mock_data_path]

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    assert 3 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)
