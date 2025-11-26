from __future__ import annotations

import json
import os

import pytest
from vunnel import result, workspace
from vunnel.providers.secureos import Config, Provider
from vunnel.providers.secureos.parser import Parser


class TestParser:
    @pytest.fixture()
    def mock_raw_data(self):
        """
        Returns stringified version of a sample secdb JSON
        """
        data = {
            "apkurl": "{{urlprefix}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk",
            "archs": ["x86_64", "aarch64"],
            "urlprefix": "https://apk.cve0.io",
            "distroversion": "v1",
            "packages": [
                {
                    "pkg": {
                        "name": "libcrypto3",
                        "secfixes": {
                            "0": ["CVE-2025-4575"]
                        }
                    }
                },
                {
                    "pkg": {
                        "name": "busybox",
                        "secfixes": {
                            "0": ["CVE-2025-46394"]
                        }
                    }
                },
                {
                    "pkg": {
                        "name": "redis-8.0",
                        "secfixes": {
                            "0": ["CVE-2022-0543", "CVE-2022-3734"],
                            "8.0.4": ["CVE-2025-49844"]
                        }
                    }
                },
            ],
        }

        return json.dumps(data)

    @pytest.fixture()
    def mock_parsed_data(self):
        """
        Returns the parsed output for mock_raw_data
        """
        release = "rolling"
        dbtype_data_dict = {
            "apkurl": "{{urlprefix}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk",
            "archs": ["x86_64", "aarch64"],
            "urlprefix": "https://apk.cve0.io",
            "distroversion": "v1",
            "packages": [
                {
                    "pkg": {
                        "name": "libcrypto3",
                        "secfixes": {
                            "0": ["CVE-2025-4575"]
                        }
                    }
                },
                {
                    "pkg": {
                        "name": "busybox",
                        "secfixes": {
                            "0": ["CVE-2025-46394"]
                        }
                    }
                },
                {
                    "pkg": {
                        "name": "redis-8.0",
                        "secfixes": {
                            "0": ["CVE-2022-0543", "CVE-2022-3734"],
                            "8.0.4": ["CVE-2025-49844"]
                        }
                    }
                },
            ],
        }
        return release, dbtype_data_dict

    def test_load(self, mock_raw_data, tmpdir):
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            url="https://security.secureos.io/v1/latest.json",
            namespace="secureos",
        )

        os.makedirs(p.secdb_dir_path, exist_ok=True)
        b = os.path.join(p.secdb_dir_path, "secdb.json")
        with open(b, "w") as fp:
            fp.write(mock_raw_data)

        # Set the filename since we're bypassing download
        p._db_filename = "secdb.json"

        counter = 0
        for release, dbtype_data_dict in p._load():
            counter += 1
            assert release == "rolling"
            assert isinstance(dbtype_data_dict, dict)
            assert "packages" in dbtype_data_dict

        assert counter == 1

    def test_normalize(self, mock_parsed_data, tmpdir, auto_fake_fixdate_finder):
        p = Parser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            url="https://security.secureos.io/v1/latest.json",
            namespace="secureos",
        )
        release = mock_parsed_data[0]
        dbtype_data_dict = mock_parsed_data[1]

        vuln_records = p._normalize(release, dbtype_data_dict)
        assert len(vuln_records) > 0
        assert all("Vulnerability" in x for x in vuln_records.values())
        assert sorted(vuln_records.keys()) == sorted(
            [
                "CVE-2025-4575",
                "CVE-2025-46394",
                "CVE-2022-0543",
                "CVE-2022-3734",
                "CVE-2025-49844",
            ]
        )


def test_provider_schema(helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    p.update(None)

    assert workspace.num_result_entries() == 155
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
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

    p.update(None)

    workspace.assert_result_snapshots()
