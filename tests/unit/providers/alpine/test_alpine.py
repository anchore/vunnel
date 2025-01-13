from __future__ import annotations

import os
import shutil

import pytest
from vunnel import result, workspace
from vunnel.providers.alpine import Config, Provider, parser
from vunnel.providers.alpine.parser import Parser, SecdbLandingParser


class TestAlpineProvider:
    @pytest.fixture()
    def mock_raw_data(self):
        return """
apkurl: '{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk'
archs:
- x86_64
- x86
- armhf
distroversion: v0.0
packages:
- pkg:
    name: apache2
    secfixes:
      2.4.26-r0:
      - CVE-2017-3167
      - CVE-2017-3169
      - CVE-2017-7659
      - CVE-2017-7668
      - CVE-2017-7679
      2.4.27-r0:
      - CVE-2017-9789
      2.4.27-r1:
      - CVE-2017-9798
- pkg:
    name: augeas
    secfixes:
      1.4.0-r5:
      - CVE-2017-7555
- pkg:
    name: bash
    secfixes:
      4.3.42-r5:
      - CVE-2016-9401
reponame: main
urlprefix: http://dl-cdn.alpinelinux.org/alpine
"""
    @pytest.fixture()
    def mock_parsed_data(self):
        """
        Returns the parsed output generated by AlpineDataProvider._load() for the mock_raw_data

        :return:
        """
        release = "0.0"
        dbtype_data_dict = {
            "main": {
                "apkurl": "{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk",
                "archs": ["x86_64", "x86", "armhf"],
                "distroversion": "v0.0",
                "packages": [
                    {
                        "pkg": {
                            "name": "apache2",
                            "secfixes": {
                                "2.4.26-r0": [
                                    "CVE-2017-3167",
                                    "CVE-2017-3169",
                                    "CVE-2017-7659",
                                    "CVE-2017-7668",
                                    "CVE-2017-7679",
                                ],
                                "2.4.27-r0": ["CVE-2017-9789"],
                                "2.4.27-r1": ["CVE-2017-9798"],
                            },
                        },
                    },
                    {
                        "pkg": {
                            "name": "augeas",
                            "secfixes": {"1.4.0-r5": ["CVE-2017-7555"]},
                        },
                    },
                    {
                        "pkg": {
                            "name": "bash",
                            "secfixes": {"4.3.42-r5": ["CVE-2016-9401"]},
                        },
                    },
                ],
                "reponame": "main",
                "urlprefix": "http://dl-cdn.alpinelinux.org/alpine",
            },
        }
        return release, dbtype_data_dict

    @pytest.mark.parametrize(
        ("release", "expected"),
        [
            ("v3.3", True),
            ("3.4", False),
            ("v.3.3", False),
            ("v3.101", True),
            ("v3.27", True),
        ],
    )
    def test_release_regex(self, release, expected):
        assert bool(Parser._release_regex_.match(release)) == expected

    def test_load(self, mock_raw_data, tmpdir):
        p = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        a = os.path.join(p.secdb_dir_path, "v0.0")
        os.makedirs(a, exist_ok=True)
        b = os.path.join(a, "main.yaml")
        with open(b, "w") as fp:
            fp.write(mock_raw_data)

        counter = 0
        for release, dbtype_data_dict in p._load():
            counter += 1
            print(f"got secdb data for release {release}, db types: {list(dbtype_data_dict.keys())}")
            assert release == "0.0"
            assert isinstance(dbtype_data_dict, dict)
            assert list(dbtype_data_dict.keys()) == ["main"]
            assert all("packages" in x for x in dbtype_data_dict.values())

        assert counter == 1

    def test_normalize(self, mock_parsed_data, tmpdir):
        p = Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        release = mock_parsed_data[0]
        dbtype_data_dict = mock_parsed_data[1]

        vuln_records = p._normalize(release, dbtype_data_dict)
        assert len(vuln_records) > 0
        assert all("Vulnerability" in x for x in vuln_records.values())
        assert sorted(vuln_records.keys()) == sorted(
            [
                "CVE-2017-3167",
                "CVE-2017-3169",
                "CVE-2017-7659",
                "CVE-2017-7668",
                "CVE-2017-7679",
                "CVE-2017-9789",
                "CVE-2017-9798",
                "CVE-2017-7555",
                "CVE-2016-9401",
            ],
        )

    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            pytest.param(
                '<html>\r\n<head><title>Index of /</title></head>\r\n<body>\r\n<h1>Index of /</h1><hr><pre><a href="../">../</a>\r\n<a href="v3.10/">v3.10/</a> 11-Jun-2020 20:17 -\r\n<a href="v3.11/">v3.11/</a> 11-Jun-2020 18:12 -\r\n</pre><hr></body>\r\n</html>\r\n',  # noqa: E501
                ["v3.10/", "v3.11/"],
                id="with-content",
            ),
            pytest.param('<a href=".">.</a>', [], id="href-."),
            pytest.param('<a href="../">../</a>', [], id="href-../"),
            pytest.param('<a href="foo/">foo/</a>', ["foo/"], id="href-foo/"),
        ],
    )
    def test_secdb_landing_parser(self, content, expected):
        parser = SecdbLandingParser()
        parser.feed(content)
        assert sorted(parser.links) == sorted(expected)

    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            pytest.param(
                '<html>\r\n<head><title>Index of /</title></head>\r\n<body>\r\n<h1>Index of /</h1><hr><pre><a href="../">../</a>\r\n<a href="v3.10/">v3.10/</a> 11-Jun-2020 20:17 -\r\n<a href="v3.11/">v3.11/</a> 11-Jun-2020 18:12 -\r\n</pre><hr></body>\r\n</html>\r\n',  # noqa: E501
                ["v3.10/", "v3.11/"],
                id="with-content",
            ),
            pytest.param('<a href=".">.</a>', [], id="href-."),
            pytest.param('<a href=    "../"   >../</a>', [], id="href-../+space"),
            pytest.param('<a href=  "foo/" >foo/</a>', ["foo/"], id="href-foo/+space"),
        ],
    )
    def test_link_finder_regex(self, content, expected):
        assert Parser._link_finder_regex_.findall(content) == expected


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
        return

    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    assert workspace.num_result_entries() == 16
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
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

    monkeypatch.setattr(p.parser, "_download", mock_download)
    monkeypatch.setattr(p.parser, "_download_metadata_url", mock_download)
    monkeypatch.setattr(p.parser, "_download_url", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
