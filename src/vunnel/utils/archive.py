from __future__ import annotations

import os
import tarfile
import tempfile
from pathlib import Path

import zstandard


def extract(path: str, destination_dir: str) -> None:
    if path.endswith(".tar.zst"):
        return _extract_tar_zst(path, destination_dir)

    # open for reading with transparent compression (supports gz, bz2, and xz)
    with tarfile.open(path, mode="r:*") as tar:
        _safe_extract_tar(tar, destination_dir)

    return None


def _extract_tar_zst(path: str, unarchive_path: str) -> None:
    archive_path = Path(path).expanduser()
    dctx = zstandard.ZstdDecompressor(max_window_size=2147483648)

    with tempfile.TemporaryFile(suffix=".tar") as ofh:
        with archive_path.open("rb") as ifh:
            dctx.copy_stream(ifh, ofh)
        ofh.seek(0)
        with tarfile.open(fileobj=ofh, mode="r") as z:
            return _safe_extract_tar(z, unarchive_path)


def _safe_extract_tar(tar: tarfile.TarFile, destination_dir: str) -> None:
    # explanation of noqa: S202
    # This function is a safe wrapper around tar.extractall.
    tar.extractall(destination_dir, filter=_filter_path_traversal)  # noqa: S202


def _filter_path_traversal(tarinfo: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    # drop any path that would result in a write outside the destination dir
    # e.g.
    #   allowed: './some-dir/file.txt'
    #   not allowed: 'some-dir/../../../../../etc/passwd'
    dest_dir = Path(os.path.abspath(path))
    write_path = Path(os.path.normpath(os.path.join(dest_dir, tarinfo.name)))

    if dest_dir in write_path.parents:
        return tarinfo
    return None
