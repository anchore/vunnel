from __future__ import annotations
import json
import pytest
from unittest.mock import MagicMock, call, patch
from pathlib import Path
from vunnel import result, workspace
from vunnel.providers.openeuler import Config, Provider
from vunnel.providers.openeuler.parser import Parser



class TestParser:
    def test_get_cve_link(self, tmpdir):
        parser = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            url="https://repo.openeuler.org/security/data/csaf/cve/",
            namespace="openeuler"
        )
        mock_references = [
			{
				"summary":"nvd cve",
				"category":"external",
				"url":"https://nvd.nist.gov/vuln/detail/CVE-2022-0135"
			},
			{
				"summary":"CVE-2022-0135 vex file",
				"category":"self",
				"url":"https://repo.openeuler.org/security/data/csaf/cve/2022/csaf-openeuler-cve-2022-0135.json"
			},
			{
				"summary":"openEuler-SA-2022-1890",
				"category":"self",
				"url":"https://www.openeuler.org/en/security/security-bulletins/detail/?id=openEuler-SA-2022-1890"
			},
			{
				"summary":"CVE-2022-0135",
				"category":"self",
				"url":"https://www.openeuler.org/en/security/cve/detail?cveId=CVE-2022-0135&packageName=virglrenderer"
			}
		]
        link = parser._get_cve_link(references=mock_references, cve_id="CVE-2022-0135")
        assert link == "https://www.openeuler.org/en/security/cve/detail?cveId=CVE-2022-0135&packageName=virglrenderer"
        
    def test_get_cve_description(self, tmpdir):
        parser = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            url="https://repo.openeuler.org/security/data/csaf/cve/",
            namespace="openeuler"
        )
        mock_notes = [
            {
                "text":"An out-of-bounds write issue was found in the VirGL virtual OpenGL renderer (virglrenderer).",
                "category":"description",
                "title":"Vulnerability Description"
            }
        ]
        description = parser._get_cve_description(mock_notes)
        assert description == "An out-of-bounds write issue was found in the VirGL virtual OpenGL renderer (virglrenderer)."
    
    def test_parse_cve_file(self, helpers):
        parser = Parser(
            workspace=helpers.provider_workspace_helper(
                name=Provider.name(),
                input_fixture="test-fixtures/input",
            ),
            url="https://repo.openeuler.org/security/data/csaf/cve/",
            namespace="openeuler",
            max_workers=2,
        )
        cve_records = parser._parse_cve_file(cve="2022/csaf-openeuler-cve-2022-0135.json")
        for full_namespace, vuln in cve_records.items():
            namespace = full_namespace.lower()
            if namespace == "openeuler:20.03-lts-sp1/cve-2022-0135":
                assert vuln["Vulnerability"]["FixedIn"][0]["Name"] == "virglrenderer"
            elif namespace == "openeuler:20.03-lts-sp3/cve-2022-0135":
                assert vuln["Vulnerability"]["Link"] == "https://www.openeuler.org/en/security/cve/detail?cveId=CVE-2022-0135&packageName=virglrenderer"
            elif namespace == "openeuler:22.03-lts/cve-2022-0135":
                assert vuln["Vulnerability"]["Severity"] == "HIGH"
            else:
                assert False

def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.parser.cves = [
        "2022/csaf-openeuler-cve-2022-0135.json",
        "2025/csaf-openeuler-cve-2025-0240.json",
    ] 
    def mock_download():
        return None
    monkeypatch.setattr(p.parser, "_download", mock_download)
    p.update(None)

    assert workspace.num_result_entries() == 6
    assert workspace.result_schemas_valid(require_entries=True)

def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )

    c = Config()
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.parser.cves = [
        "2022/csaf-openeuler-cve-2022-0135.json",
        "2025/csaf-openeuler-cve-2025-0240.json",
    ]

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download", mock_download)
    p.update(None)

    workspace.assert_result_snapshots()