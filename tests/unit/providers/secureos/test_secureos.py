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

    assert workspace.num_result_entries() == 17
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


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        # plain versions and revisions
        ("9.3.2-r1", "9.3.2-r2"),
        ("9.3.2-r2", "9.3.10-r0"),
        ("8.0.4", "8.0.5"),
        # numeric segments carrying suffixes are compared as integers
        ("1.2_p1-r1", "1.10_p1-r1"),
        ("3.3.2_p1-r4", "3.3.10-r1"),
        ("1.9.5_p2-r1", "1.9.15_p5-r1"),
        # pre-release suffixes sort before the release, _p after it
        ("2.0.0_rc1-r1", "2.0.0-r1"),
        ("0.9_rc5-r1", "0.9-r0"),
        ("3.3.2-r9", "3.3.2_p1-r0"),
        ("1.0_alpha1", "1.0_beta1"),
        ("1.0_beta1", "1.0_pre1"),
        ("1.0_pre1", "1.0_rc1"),
        ("1.0_rc1", "1.0_rc2"),
        ("1.0_rc2", "1.0_rc10"),
        ("1.0_git1", "1.0_p1"),
        ("1.0_p1", "1.0_p2"),
        # letter after the digits
        ("1.2", "1.2a"),
        ("1.2a", "1.2b"),
        ("1.2z", "1.3"),
    ],
)
def test_compare_apk_versions(lower, higher):
    assert Parser._compare_apk_versions(lower, higher) == -1
    assert Parser._compare_apk_versions(higher, lower) == 1
    assert Parser._compare_apk_versions(lower, lower) == 0


def test_normalize_orders_apk_suffixed_fix_versions(tmpdir, auto_fake_fixdate_finder):
    p = Parser(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        url="https://security.secureos.io/v1/latest.json",
        namespace="secureos",
    )
    data = {
        "packages": [
            {"pkg": {"name": "openssl", "secfixes": {"1.10_p1-r1": ["CVE-2025-2222"], "1.2_p1-r1": ["CVE-2025-2222"]}}},
            {"pkg": {"name": "curl", "secfixes": {"2.0.0-r1": ["CVE-2025-3333"], "2.0.0_rc1-r1": ["CVE-2025-3333"]}}},
        ],
    }

    vuln_records = p._normalize("rolling", data)

    def fixed_in(vid):
        return [(f["Version"], f.get("VulnerableRange")) for f in vuln_records[vid]["Vulnerability"]["FixedIn"]]

    assert fixed_in("CVE-2025-2222") == [
        ("1.2_p1-r1", None),
        ("1.10_p1-r1", ">=1.10_p1-r0, <1.10_p1-r1"),
    ]
    assert fixed_in("CVE-2025-3333") == [
        ("2.0.0_rc1-r1", None),
        ("2.0.0-r1", ">=2.0.0-r0, <2.0.0-r1"),
    ]
