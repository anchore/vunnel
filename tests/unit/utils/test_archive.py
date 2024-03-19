import tarfile
from vunnel.utils.archive import filter_path_traversal

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
    actual = filter_path_traversal(tar_info, "/some/path")
    if allowed:
        assert actual is not None
        assert actual.name == tar_info_name
    else:
        assert actual is None
