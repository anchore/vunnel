from __future__ import annotations

import os.path
import shutil
from unittest.mock import MagicMock, patch

import pytest
from vunnel import result, workspace
from vunnel.providers.debian import Config, Provider, parser


@pytest.fixture()
def mock_legacy_db(mocker):
    mock_record = {
        "schema": "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
        "identifier": "debian:10/cve-2012-0833",
        "item": {
            "Vulnerability": {
                "Severity": "Negligible",
                "NamespaceName": "debian:10",
                "FixedIn": [],
                "Link": "https://security-tracker.debian.org/tracker/CVE-2012-0833",
                "Description": "The acllas__handle_group_entry function in servers/plugins/acl/acllas.c in 389 Directory Server before 1.2.10 does not properly handled access control instructions (ACIs) that use certificate groups, which allows remote authenticated LDAP users with a certificate group to cause a denial of service (infinite loop and CPU consumption) by binding to the server.",
                "Metadata": {},
                "Name": "CVE-2012-0833",
                "CVSS": [],
            }
        },
    }

    mock_records = [result.Envelope(**mock_record)]

    mocker.patch("vunnel.result.SQLiteReader.read_all", return_value=mock_records)


class TestParser:
    _sample_dsa_data_ = "test-fixtures/input/DSA"
    _sample_json_data_ = "test-fixtures/input/debian.json"

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
        subject.logger = MagicMock()

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
        assert not subject.logger.exception.called, "no exceptions should be logged"

    def test_get_legacy_records(self, tmpdir, helpers, disable_get_requests, mock_legacy_db):
        subject = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))

        mock_data_path = helpers.local_dir("test-fixtures/input")
        shutil.copytree(mock_data_path, subject.workspace.input_path, dirs_exist_ok=True)

        legacy_records = subject._get_legacy_records()

        assert isinstance(legacy_records, dict)
        assert len(legacy_records) > 0

        # from the feed service data dump
        assert "7" in legacy_records.keys()
        assert len(legacy_records["7"]) > 0
        assert "CVE-2004-1653" in legacy_records["7"].keys()
        assert len(legacy_records["7"]["CVE-2004-1653"]) > 0

        # from the DB
        assert "10" in legacy_records.keys()
        assert len(legacy_records["10"]) > 0
        assert "CVE-2012-0833" in legacy_records["10"].keys()
        assert len(legacy_records["10"]["CVE-2012-0833"]) > 0

        for _rel, vuln_dict in legacy_records.items():
            assert isinstance(vuln_dict, dict)
            assert len(vuln_dict) > 0
            assert all("Vulnerability" in x for x in vuln_dict.values())

            assert all(x.get("Vulnerability", {}).get("Name") for x in vuln_dict.values())

            assert all(x.get("Vulnerability", {}).get("Description") is not None for x in vuln_dict.values())


def test_provider_schema(helpers, disable_get_requests, monkeypatch, mock_legacy_db):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )

    c = Config()
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download_json", mock_download)
    monkeypatch.setattr(p.parser, "_download_dsa", mock_download)

    p.update(None)

    # 18 entries from the legacy FS records, 1 from legacy DB record, 21 from the mock json data
    expected = 39
    assert workspace.num_result_entries() == expected
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, mock_legacy_db):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )

    c = Config()
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    def mock_download():
        return None

    monkeypatch.setattr(p.parser, "_download_json", mock_download)
    monkeypatch.setattr(p.parser, "_download_dsa", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
