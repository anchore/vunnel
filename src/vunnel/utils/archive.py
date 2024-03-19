import os
import tarfile
from pathlib import Path


def filter_path_traversal(tarinfo: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    # drop any path that would result in a write outside the destination dir
    # e.g.
    #   allowed: './some-dir/file.txt'
    #   not allowed: 'some-dir/../../../../../etc/passwd'
    dest_dir = Path(os.path.abspath(path))
    write_path = Path(os.path.normpath(os.path.join(dest_dir, tarinfo.name)))

    if dest_dir in write_path.parents:
        return tarinfo
    return None


def safe_extract_tar(tar: tarfile.TarFile, destination_dir: str) -> None:
    # explanation of noqa: S202
    # This function is a safe wrapper around tar.extractall.
    tar.extractall(destination_dir, filter=filter_path_traversal) # noqa: S202
