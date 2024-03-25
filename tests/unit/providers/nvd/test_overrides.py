from __future__ import annotations

import tarfile
from unittest.mock import patch, MagicMock

import pytest
from vunnel import workspace
from vunnel.providers.nvd import overrides


@pytest.fixture
def overrides_tar(tmpdir):
    tar = tmpdir.join("overrides.tar.gz")

    with tarfile.open(tar, "w:gz") as f:
        f.add("tests/unit/providers/nvd/test-fixtures/single-entry.json", arcname="data/CVE-2011-0022.json")

    return tar


@pytest.fixture
def path_traversal_tar(tmpdir):
    tar = tmpdir.join("overrides.tar.gz")

    with tarfile.open(tar, "w:gz") as f:
        f.add("tests/unit/providers/nvd/test-fixtures/single-entry.json", arcname="data/../../CVE-2011-0022.json")

    return tar


@patch("requests.get")
def test_overrides_disabled(mock_requests, tmpdir):
    subject = overrides.NVDOverrides(
        enabled=False,
        url="http://localhost:8080/failed",
        workspace=workspace.Workspace(tmpdir, "test", create=True),
    )
    subject.__filepaths_by_cve__ = {"CVE-2020-0000": '{"fail": true}'}

    # ensure requests.get is not called
    subject.download()
    mock_requests.get.assert_not_called()

    # ensure cve returns None
    assert subject.cve("CVE-2020-0000") is None
    assert subject.cves() == []


@patch("requests.get")
def test_overrides_enabled(mock_requests, overrides_tar, tmpdir):
    mock_requests.return_value = MagicMock(status_code=200, iter_content=lambda: [open(overrides_tar, "rb").read()])
    subject = overrides.NVDOverrides(
        enabled=True,
        url="http://localhost:8080/failed",
        workspace=workspace.Workspace(tmpdir, "test", create=True),
    )

    subject.download()

    assert subject.cve("CVE-2011-0022") is not None
    assert subject.cves() == ["CVE-2011-0022"]
