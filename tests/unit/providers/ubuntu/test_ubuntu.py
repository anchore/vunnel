import json
import os
import shlex
import shutil
import subprocess
import sys

import pytest

from vunnel import workspace
from vunnel.providers import ubuntu
from vunnel.providers.ubuntu.parser import (
    Parser,
    check_merge,
    check_patch,
    map_parsed,
    parse_cve_file,
    parse_list,
    parse_multiline_keyvalue,
    parse_simple_keyvalue,
    patch_states,
    ubuntu_version_names,
)


class TestUbuntuParser:
    _location_ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__), "test-fixtures"))
    _data_ = os.path.join(_location_, "example_ubuntu_cve")
    _weird_data_ = os.path.join(_location_, "weird_example_cve")
    _workspace_ = "/tmp/ubuntu"

    # @classmethod
    # def setUpClass(cls):
    #     os.makedirs(cls._workspace_, exist_ok=True)

    # @classmethod
    # def tearDownClass(cls):
    #     shutil.rmtree(cls._workspace_)

    def test_reference_parser(self):
        data = {
            """References:
            https://cve.mitre.org/1/cvename.cgi?somecve
            https://cve.mitre.org/2/cvename2.cgi
            """: [
                "https://cve.mitre.org/1/cvename.cgi?somecve",
                "https://cve.mitre.org/2/cvename2.cgi",
            ],
            """References:
            https://cve.mitre.org/1/cvename.cgi?somecve
            https://cve.mitre.org/2/cvename2.cgi

            """: [
                "https://cve.mitre.org/1/cvename.cgi?somecve",
                "https://cve.mitre.org/2/cvename2.cgi",
            ],
            """References:

            https://cve.mitre.org/1/cvename.cgi?somecve
            https://cve.mitre.org/2/cvename2.cgi

            """: [],
        }

        header = "References"

        for input, result in data.items():
            split_lines = input.splitlines()
            got = parse_list(header, split_lines)

            assert got == result

    def test_simple_newline_parser(self):
        data = {
            "Header: somevalue\n": "somevalue",
            "Header:   somevalue2     \n\n\n": "somevalue2",
        }

        header = "Header"

        for input, result in data.items():
            split_lines = input.splitlines()
            got = parse_simple_keyvalue(header, split_lines)
            assert got == result

    def test_parse_cve(self):
        with open(self._data_) as f:
            data = f.readlines()

        print("Parsing")
        result = parse_cve_file(data)
        print("Complete")

        expected = {
            "Candidate": "CVE-2017-9996",
            # "PublicDate": dateutil.parser.parse("2017-06-28"),
            "References": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9996",
                "https://github.com/FFmpeg/FFmpeg/commit/1e42736b95065c69a7481d0cf55247024f54b660",
                "https://github.com/FFmpeg/FFmpeg/commit/e1b60aad77c27ed5d4dfc11e5e6a05a38c70489d",
                "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1378",
                "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1427",
            ],
            "Description": "The cdxl_decode_frame function in libavcodec/cdxl.c in FFmpeg 2.8.x before 2.8.12, 3.0.x before 3.0.8, 3.1.x before 3.1.8, 3.2.x before 3.2.5, and 3.3.x before 3.3.1 does not exclude the CHUNKY format, which allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted file.",
            # "Ubuntu-Description": "",
            "Priority": "medium",
            "patches": [
                {
                    "distro": "upstream",
                    "package": "libav",
                    "status": "needs-triage",
                    "version": None,
                },
                {
                    "distro": "precise/esm",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "trusty",
                    "package": "libav",
                    "status": "needed",
                    "version": None,
                },
                {
                    "distro": "vivid/ubuntu-core",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "xenial",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "yakkety",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "zesty",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "artful",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "devel",
                    "package": "libav",
                    "status": "DNE",
                    "version": None,
                },
                {
                    "distro": "upstream",
                    "package": "ffmpeg",
                    "status": "released",
                    "version": "7:3.2.5-1",
                    "priority": "low",
                },
                {
                    "distro": "precise/esm",
                    "package": "ffmpeg",
                    "status": "DNE",
                    "version": None,
                    "priority": "low",
                },
                {
                    "distro": "trusty",
                    "package": "ffmpeg",
                    "status": "DNE",
                    "version": None,
                    "priority": "low",
                },
                {
                    "distro": "vivid/ubuntu-core",
                    "package": "ffmpeg",
                    "status": "DNE",
                    "version": None,
                    "priority": "low",
                },
                {
                    "distro": "xenial",
                    "package": "ffmpeg",
                    "status": "needed",
                    "version": None,
                    "priority": "low",
                },
                {
                    "distro": "yakkety",
                    "package": "ffmpeg",
                    "status": "ignored",
                    "version": "reached end-of-life",
                    "priority": "low",
                },
                {
                    "distro": "zesty",
                    "package": "ffmpeg",
                    "status": "needed",
                    "version": None,
                    "priority": "low",
                },
                {
                    "distro": "artful",
                    "package": "ffmpeg",
                    "status": "not-affected",
                    "priority": "low",
                    "version": "7:3.2.6-1",
                },
                {
                    "distro": "devel",
                    "package": "ffmpeg",
                    "status": "not-affected",
                    "priority": "low",
                    "version": "7:3.2.6-1",
                },
            ],
        }

        # No longer parsing by default
        # self.assertEqual(expected['PublicDate'], result['PublicDate'])

        assert expected["Description"] == result["Description"]
        self.maxDiff = None
        assert expected["patches"] == result["patches"]
        assert expected == result

    def test_non_header_patches(self):
        with open(self._weird_data_) as f:
            data = f.readlines()

        print("Parsing")
        result = parse_cve_file(data)
        print("Complete")

        print(result)

    def test_simple_multiline_parser(self):
        data = {
            """Description:
             a
             b
             c
             d
             e
             f
            """: "a b c d e f",
            """Description:
             ab
             bc


            """: "ab bc",
            """Description:

             a
             b

            """: "",
        }

        header = "Description"

        for input, result in data.items():
            split_lines = input.splitlines()
            got = parse_multiline_keyvalue(header, split_lines)
            assert got == result

    def test_mapper(self):
        with open(self._data_) as f:
            parsed = parse_cve_file(f.readlines())

        parsed["Name"] = "CVE-TEST-123"
        vulns = map_parsed(parsed)
        for i in vulns:
            j = i.json()
            print(json.dumps(j))
            assert j != {"FixedIn": [{}, {}]}

    def test_checkers(self):
        check_data = [
            ({"distro": "natty", "status": "released", "version": "1.1"}, False),
            ({"distro": "blah", "status": "released", "version": "1.1"}, False),
            ({"distro": "lucid", "status": "released", "version": "1.1"}, False),
        ]

        # Try cross-product of states and releases
        for s, v in patch_states.items():
            for r in ubuntu_version_names:
                check_data.append(({"distro": r, "status": s, "version": "testversion"}, v))

        for data in check_data:
            assert check_patch(data[0]) == data[1]

    def test_check_merge(self):
        p = {
            "distro": "foo",
            "package": "bar",
            "status": "ignored ftw",
            "version": "end-of-life now but something else before",
        }
        assert check_merge(p) == True

        p["status"] = "ignored"
        p["version"] = "reached end-of-life"
        assert check_merge(p) == True

        p["status"] = "ignored"
        p["version"] = "end of life"
        assert check_merge(p) == True

        p["status"] = "ignored"
        p["version"] = "was pending now end-of-life"
        assert check_merge(p) == True

        p["status"] = "ignored"
        p["version"] = "end_of_life"
        assert check_merge(p) == False

        p["status"] = "ignored"
        p["version"] = "bleddyend-of-lifeas we know"
        assert check_merge(p) == False

        p["status"] = "ignored"
        p["version"] = "end times of all life"
        assert check_merge(p) == False

        p["status"] = "some invalid state"
        p["version"] = "end-of-life"
        assert check_merge(p) == False

        p["status"] = "ignored"
        p["version"] = "oh so end-of-lifed"
        assert check_merge(p) == False

    def test_reprocess_merged_cve(self, tmpdir):
        new_distro_patches = [
            {
                "distro": "madeup",
                "package": "mozjs38",
                "status": "DNE",
                "version": None,
            },
            {
                "distro": "madeup",
                "package": "mozjs52",
                "status": "needs-triage",
                "version": None,
            },
            {
                "distro": "madeup",
                "package": "mozjs60",
                "status": "ignored",
                "version": "end of life",
            },
        ]
        data = {
            "patches": [
                {
                    "distro": "trusty",
                    "package": "firefox",
                    "status": "ignored",
                    "version": "out of standard support",
                },
                {
                    "distro": "bionic",
                    "package": "firefox",
                    "status": "released",
                    "version": "82.0+build2-0ubuntu0.18.04.1",
                },
            ],
            "Candidate": "CVE-0000-0000",
            "References": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-0000-0000",
            ],
            "Description": "blah blah blah",
            "Priority": "medium",
            "Name": "CVE-0000-0000",
            "ignored_patches": [
                {
                    "distro": "devel",
                    "package": "mozjs52",
                    "status": "DNE",
                    "version": None,
                },
            ]
            + new_distro_patches,
            "git_last_processed_rev": "40a85b5b23bd905f8d5c6791d3f61108406ec372",
        }
        ws = workspace.Workspace(tmpdir, "test")
        udp = Parser(workspace=ws, additional_versions={"madeup": "00.00"}, enable_rev_history=False)

        os.makedirs(udp.norm_workspace, exist_ok=True)

        cve_id = "CVE-0000-0000"
        cvs_file = os.path.join(udp.norm_workspace, cve_id)

        with open(cvs_file, "w") as fp:
            json.dump(data, fp)

        result = udp._reprocess_merged_cve(cve_id, cvs_file)
        assert result.get("patches") == data.get("patches") + new_distro_patches


@pytest.fixture
def hydrate_git_repo(tmpdir, helpers):
    def run(cmd, **kwargs):
        subprocess.run(shlex.split(cmd), **kwargs, stderr=sys.stderr, stdout=sys.stdout)

    def apply(export_path):
        ws = workspace.Workspace(tmpdir, "ubuntu", create=True)
        repo_path = os.path.join(ws.input_path, "ubuntu-cve-tracker")

        shutil.rmtree(repo_path, ignore_errors=True)

        run("git init ubuntu-cve-tracker --initial-branch=main", cwd=ws.input_path)

        mock_data_path = helpers.local_dir(export_path)
        run("git fast-import", stdin=open(mock_data_path), cwd=repo_path)
        run("git checkout", cwd=repo_path)

        return tmpdir

    return apply


@pytest.mark.parametrize(
    "mock_data_path,expected_written_entries",
    [
        ("test-fixtures/repo-fast-export", 42),
        # this is 6 records distributed across multiple distros:
        # └── results
        #     ├── ubuntu:14.04
        #     │   ├── cve-2019-17185.json
        #     │   ├── cve-2021-4204.json
        #     │   ├── cve-2022-20566.json
        #     │   ├── cve-2022-41859.json
        #     │   ├── cve-2022-41860.json
        #     │   └── cve-2022-41861.json
        #     ├── ubuntu:16.04
        #     │   ├── cve-2019-17185.json
        #     │   ├── cve-2021-4204.json
        #     │   ├── cve-2022-20566.json
        #     │   ├── cve-2022-41859.json
        #     │   ├── cve-2022-41860.json
        #     │   └── cve-2022-41861.json
        #     ├── ubuntu:18.04
        #     │   ├── cve-2019-17185.json
        #     │   ├── cve-2021-4204.json
        #     │   ├── cve-2022-20566.json
        #     │   ├── cve-2022-41859.json
        #     │   ├── cve-2022-41860.json
        #     │   └── cve-2022-41861.json
        #     ├── ubuntu:19.10
        #     │   └── cve-2019-17185.json
        #     ├── ubuntu:20.04
        #     │   ├── cve-2019-17185.json
        #     │   ├── cve-2021-4204.json
        #     │   ├── cve-2022-20566.json
        #     │   ├── cve-2022-41859.json
        #     │   ├── cve-2022-41860.json
        #     │   └── cve-2022-41861.json
        #     ├── ubuntu:20.10
        #     │   └── cve-2019-17185.json
        #     ├── ubuntu:21.04
        #     │   ├── cve-2019-17185.json
        #     │   └── cve-2021-4204.json
        #     ├── ubuntu:21.10
        #     │   ├── cve-2019-17185.json
        #     │   └── cve-2021-4204.json
        #     ├── ubuntu:22.04
        #     │   ├── cve-2019-17185.json
        #     │   ├── cve-2021-4204.json
        #     │   ├── cve-2022-20566.json
        #     │   ├── cve-2022-41859.json
        #     │   ├── cve-2022-41860.json
        #     │   └── cve-2022-41861.json
        #     └── ubuntu:22.10
        #         ├── cve-2019-17185.json
        #         ├── cve-2021-4204.json
        #         ├── cve-2022-20566.json
        #         ├── cve-2022-41859.json
        #         ├── cve-2022-41860.json
        #         └── cve-2022-41861.json
    ],
)
def test_provider_schema(helpers, mock_data_path, hydrate_git_repo, expected_written_entries, mocker):
    path = hydrate_git_repo(mock_data_path)
    provider = ubuntu.Provider(root=path, config=ubuntu.Config())
    provider.parser.git_wrapper.init_repo = mocker.Mock()
    provider.update()

    ws = helpers.provider_workspace_helper("ubuntu", create=False)

    assert expected_written_entries == ws.num_result_entries()
    assert ws.result_schemas_valid(require_entries=expected_written_entries > 0)
