from __future__ import annotations

import os.path
import shutil

import pytest
from vunnel import result, workspace
from vunnel.providers.debian import Config, Provider, parser


@pytest.fixture()
def disable_get_requests(monkeypatch):
    def disabled(*args, **kwargs):
        raise RuntimeError("requests disabled but HTTP GET attempted")

    monkeypatch.setattr(parser.requests, "get", disabled)


class TestParser:
    _sample_dsa_data_ = "test-fixtures/input/DSA"
    _sample_json_data_ = "test-fixtures/input/debian.json"
    _sample_legacy_data = "test-fixtures/input/legacy/vulnerabilities-debian:7-0.json"

    def test_normalize_dsa_list(self, tmpdir, helpers, disable_get_requests):
        subject = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))

        mock_data_path = helpers.local_dir(self._sample_dsa_data_)
        shutil.copy(mock_data_path, subject.dsa_file_path)

        ns_cve_dsalist = subject._normalize_dsa_list()
        assert isinstance(ns_cve_dsalist, dict)

        assert len(ns_cve_dsalist) > 0

        for _ns, cve_dsalist in ns_cve_dsalist.items():
            assert isinstance(cve_dsalist, dict)
            assert len(cve_dsalist) > 0
            assert all(isinstance(x, list) and len(x) > 0 for x in cve_dsalist.values())

            # print("Number of CVEs in {}: {}".format(ns, len(cve_dsalist)))
            # more_dsas = {x: y for x, y in cve_dsalist.items() if len(y) > 1}
            # print("Number of CVEs with more than 1 DSA: {}".format(len(more_dsas)))
            # # for cve, dsalist in sub.items():
            # #     print('{} in debian:{} namespace is mapped to {} DSAs. {}'.format(cve, ns, len(dsalist), dsalist))
            # print("")

    def test_get_dsa_map(self, tmpdir, helpers, disable_get_requests):
        subject = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))

        mock_data_path = helpers.local_dir(self._sample_dsa_data_)
        shutil.copy(mock_data_path, subject.dsa_file_path)

        dsa_map = subject._get_dsa_map()
        # dsas = {dsa["id"] for dsa_collection in dsa_map.values() for dsa in (dsa_collection.cves + dsa_collection.nocves)}
        # print("")
        # print("Total number of dsas: {}".format(len(dsas)))

        no_cves = [dsa for dsa_collection in dsa_map.values() for dsa in dsa_collection.nocves]
        weird_dsas = [dsa for dsa in no_cves if not dsa["fixed_in"]]
        # print("")
        # print("Number of DSAs with neither fixes nor CVEs: {}".format(len(weird_dsas)))
        assert len(weird_dsas) == 3

        no_cve_dsas = [dsa for dsa in no_cves if dsa["fixed_in"]]
        # print("")
        # print("Number of DSAs with fixes and no CVEs: {}".format(len(no_cve_dsas)))
        assert len(no_cve_dsas) == 1

    def test_normalize_json(self, tmpdir, helpers, disable_get_requests):
        subject = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))

        dsa_mock_data_path = helpers.local_dir(self._sample_dsa_data_)
        json_mock_data_path = helpers.local_dir(self._sample_json_data_)
        shutil.copy(dsa_mock_data_path, subject.dsa_file_path)
        shutil.copy(json_mock_data_path, subject.json_file_path)

        ns_cve_dsalist = subject._normalize_dsa_list()
        vuln_records = subject._normalize_json(ns_cve_dsalist=ns_cve_dsalist)

        assert isinstance(vuln_records, dict)
        assert len(vuln_records) > 0

        for _rel, vuln_dict in vuln_records.items():
            assert isinstance(vuln_dict, dict)
            assert len(vuln_dict) > 0
            assert all("Vulnerability" in x for x in vuln_dict.values())

            assert all(x.get("Vulnerability", {}).get("Name") for x in vuln_dict.values())

            assert all(x.get("Vulnerability", {}).get("Description") is not None for x in vuln_dict.values())

    def test_get_legacy_records(self, tmpdir, helpers, disable_get_requests):
        subject = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))

        mock_data_path = helpers.local_dir("test-fixtures/input")
        shutil.copytree(mock_data_path, subject.workspace.input_path, dirs_exist_ok=True)

        legacy_records = subject._get_legacy_records()

        assert isinstance(legacy_records, dict)
        assert len(legacy_records) > 0
        assert "7" in legacy_records.keys()
        assert len(legacy_records["7"]) > 0

        for _rel, vuln_dict in legacy_records.items():
            assert isinstance(vuln_dict, dict)
            assert len(vuln_dict) > 0
            assert all("Vulnerability" in x for x in vuln_dict.values())

            assert all(x.get("Vulnerability", {}).get("Name") for x in vuln_dict.values())

            assert all(x.get("Vulnerability", {}).get("Description") is not None for x in vuln_dict.values())


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download_json", mock_download)
    monkeypatch.setattr(p.parser, "_download_dsa", mock_download)

    p.update(None)

    # 17 entries from the legacy records, 21 from the mock json data
    expected = 38
    assert workspace.num_result_entries() == expected
    assert workspace.result_schemas_valid(require_entries=True)
