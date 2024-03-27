import tempfile
import tarfile
import zstandard
from pathlib import Path
from unittest.mock import patch, MagicMock

from vunnel.utils import archive

import pytest


@pytest.mark.parametrize(
    "tar_info_name, allowed",
    [
        ("file.txt", True),
        ("./file.txt", True),
        ("some-dir/file.txt", True),
        ("../file.txt", False),
        ("/file.txt", False),
        ("some-dir/../../../../../../etc/passwd", False),
    ],
)
def test_filter_path_traversal(tar_info_name: str, allowed: bool):
    tar_info = tarfile.TarInfo(tar_info_name)
    actual = archive._filter_path_traversal(tar_info, "/some/path")
    if allowed:
        assert actual is not None
        assert actual.name == tar_info_name
    else:
        assert actual is None


def test_extract_tar_zst():
    # create a temporary directory with a file to compress
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = Path(tmp_dir) / "test_file.txt"
        file_path.write_text("Test content")

        # compress the file into a .tar.zst file
        tar_path = Path(tmp_dir) / "test_file.tar"
        zst_path = Path(tmp_dir) / "test_file.tar.zst"
        with tarfile.open(tar_path, "w") as tar:
            tar.add(file_path, arcname="test_file.txt")
        with open(tar_path, "rb") as tar, open(zst_path, "wb") as zst:
            cctx = zstandard.ZstdCompressor()
            cctx.copy_stream(tar, zst)

        # extract the .tar.zst file
        with tempfile.TemporaryDirectory() as extract_dir:
            archive._extract_tar_zst(zst_path, extract_dir)

            # check if the file was correctly extracted
            assert (Path(extract_dir) / "test_file.txt").read_text() == "Test content"


@patch("vunnel.utils.archive._extract_tar_zst")
@patch("vunnel.utils.archive._safe_extract_tar")
@patch("tarfile.open")
def test_extract(mock_tarfile_open, mock_safe_extract_tar, mock_extract_tar_zst):
    open_mock = MagicMock()
    mock_tarfile_open.return_value.__enter__.return_value = open_mock

    # call extract with a .tar.zst file
    archive.extract("file.tar.zst", "dest_dir")
    mock_extract_tar_zst.assert_called_once_with("file.tar.zst", "dest_dir")
    mock_safe_extract_tar.assert_not_called()
    mock_tarfile_open.assert_not_called()

    mock_extract_tar_zst.reset_mock()
    mock_safe_extract_tar.reset_mock()

    # call extract with a .tar file
    archive.extract("file.tar", "dest_dir")
    mock_safe_extract_tar.assert_called_once_with(open_mock, "dest_dir")
    mock_extract_tar_zst.assert_not_called()
