from __future__ import annotations

import os
import shutil
import unittest

import pytest
from vunnel.providers.ubuntu.git import GitRevision, GitWrapper


class TestGitWrapper(unittest.TestCase):
    """
    Unit tests for parsing utilities in GitWrapper

    """

    _workspace_ = "/tmp/ubuntu"
    _location_ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__), "test-fixtures"))

    _git_change_log_file_ = os.path.join(_location_, "git_commits_log")
    _commit_changes_ = [
        {
            "sha": "62187d18d026f17e05af808d95a8c85b7211dda2",
            "updated": {"CVE-2018-14625": "active/CVE-2018-14625"},
            "deleted": {},
        },
        {
            "sha": "eaf213c7cb9118a9bfb59e9b4b736d2d99808ae8",
            "updated": {
                "CVE-2013-7447": "active/CVE-2013-7447",
                "CVE-2017-14650": "retired/CVE-2017-14650",
            },
            "deleted": {},
        },
        {
            "sha": "c182f8269c5bad4201eea14cc185b8ba080374b2",
            "updated": {"CVE-2018-19655": "active/CVE-2018-19655"},
            "deleted": {"CVE-2017-16882": "retired/CVE-2017-16882"},
        },
        {
            "sha": "93c48181efd3a9f220b56715f68a550664425540",
            "updated": {},
            "deleted": {"CVE-2016-8641": "retired/CVE-2016-8641"},
        },
        {
            "sha": "78d22044df36a623b2513bf0e6eaf419c25aed50",
            "updated": {
                "CVE-2017-9773": "active/CVE-2017-9773",
                "CVE-2017-16882": "retired/CVE-2017-16882",
            },
            "deleted": {"CVE-2017-14650": "active/CVE-2017-14650"},
        },
    ]
    _overall_changes_ = {
        "modified": {
            "CVE-2018-14625": "active/CVE-2018-14625",
            "CVE-2013-7447": "active/CVE-2013-7447",
            "CVE-2017-14650": "retired/CVE-2017-14650",
            "CVE-2018-19655": "active/CVE-2018-19655",
            "CVE-2017-9773": "active/CVE-2017-9773",
        },
        "removed": {
            "CVE-2017-16882": "retired/CVE-2017-16882",
            "CVE-2016-8641": "retired/CVE-2016-8641",
        },
    }

    _git_rev_log_file_ = os.path.join(_location_, "git_rev_log")
    _rev_log_cve_ = "CVE-2017-15386"
    _revisions_ = [
        {
            "sha": "e061c9cee652f3347d679ca00b9e9c6c6033994e",
            "file": "retired/CVE-2017-15386",
            "status": "R092",
        },
        {
            "sha": "345fc246b38cb7ffae3e3faff368fbe1de45c6fc",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "9fb14c9c98f6701dcdc860355f83f8cea0ad0222",
            "file": "active/CVE-2017-15386",
            "status": "A",
        },
        {
            "sha": "2ab08fe597f4b56d4c505773061e1951f04c04cf",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "0059baff393020a6272adef1ddcd579b91b84e4f",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "c1dfef873cbc9d089ccefe890dfc645efebedc8c",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "8845fdd4ec5f551f20f3d74528f9954486ecfa09",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "7c53b57d6916b89338b1f30f23c3ab47c95b09ee",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "fec6a993b1d0a7c42cda1925165f922d4dfe9bc4",
            "file": "active/CVE-2017-15386",
            "status": "M",
        },
        {
            "sha": "eb10f42bc38d0fc4bc823472999ad4e129c0ae4b",
            "file": "active/CVE-2017-15386",
            "status": "C056",
        },
    ]

    @classmethod
    def setUpClass(cls):
        os.makedirs(cls._workspace_, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._workspace_)

    def test_parse_log(self):
        with open(self._git_change_log_file_) as f:
            git_commit_log = f.read()

        wrapper = GitWrapper(self._workspace_, "master", self._workspace_)

        commits = wrapper._parse_log(git_commit_log)

        assert len(commits) == len(self._commit_changes_)

        for got, expected in zip(commits, self._commit_changes_):
            assert got.sha in expected["sha"]
            assert got.updated == expected["updated"]
            assert got.deleted == expected["deleted"]
            print(got)

    def test_compute_change_set(self):
        with open(self._git_change_log_file_) as f:
            git_commit_log = f.read()

        wrapper = GitWrapper(self._workspace_, "master", self._workspace_)

        commits = wrapper._parse_log(git_commit_log)

        modified, removed = wrapper._compute_change_set(commits)

        assert modified == self._overall_changes_["modified"]
        assert removed == self._overall_changes_["removed"]
        print(f"Modified: {modified}")
        print(f"Removed: {removed}")


@pytest.mark.parametrize(
    ("git_log_output", "expected"),
    [
        pytest.param(
            """
567e50a45a53a6c32120926656a9b2af0eb10c5b (HEAD -> master, origin/master, origin/HEAD) Process cves run: triaged 2 CVEs, 58 Ignored, 2 Packages
A       active/CVE-2018-14628
A       active/CVE-2022-47630
721abff41afecaa0a499ea49ecaf6c11ac879679 Updating openssl status for trusty/xenial
M       active/CVE-2022-3996
721abff41afecaa0a499ea49ecaf6c11ac879678 update retired
M       retired/CVE-2013-4348
721abff41afecaa0a499ea49ecaf6c11ac879677 move to retired
R100       active/CVE-2013-4348    retired/CVE-2013-4348
721abff41afecaa0a499ea49ecaf6c11ac879676 update
M       active/CVE-2013-4348
721abff41afecaa0a499ea49ecaf6c11ac879675 added
A       active/CVE-2013-4348
    """,
            {
                "CVE-2018-14628": [GitRevision("567e50a45a53a6c32120926656a9b2af0eb10c5b", "active/CVE-2018-14628")],
                "CVE-2022-47630": [GitRevision("567e50a45a53a6c32120926656a9b2af0eb10c5b", "active/CVE-2022-47630")],
                "CVE-2022-3996": [GitRevision("721abff41afecaa0a499ea49ecaf6c11ac879679", "active/CVE-2022-3996")],
                "CVE-2013-4348": [
                    GitRevision("721abff41afecaa0a499ea49ecaf6c11ac879678", "retired/CVE-2013-4348"),
                    GitRevision("721abff41afecaa0a499ea49ecaf6c11ac879676", "active/CVE-2013-4348"),
                    GitRevision("721abff41afecaa0a499ea49ecaf6c11ac879675", "active/CVE-2013-4348"),
                ],
            },
            id="active-retired-active transition",
        ),
    ],
)
def test_parse_full_cve_revision_history(git_log_output: str, expected: dict[str, list[GitRevision]]):
    assert GitWrapper("", "master", "").parse_full_cve_revision_history(git_log_output) == expected
