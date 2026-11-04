from __future__ import annotations

import io
import os
import tarfile

import pytest

from vunnel import workspace
from vunnel.providers.wolfi.parser import OSVParser

# valid CGA IDs must match OSVParser._cga_id_re: ^CGA(-[23456789cfghjmpqrvwx]{4}){3}$
REGULAR_IDS = [
    "CGA-2222-2222-2222",
    "CGA-3333-3333-3333",
    "CGA-4444-4444-4444",
    "CGA-5555-5555-5555",
    "CGA-6666-6666-6666",
    "CGA-7777-7777-7777",
    "CGA-8888-8888-8888",
    "CGA-9999-9999-9999",
]


def _write_archive(path: str, link_type: bytes, link_target: str) -> None:
    """write REGULAR_IDS as regular .json members, with one CGA-named link member third."""
    with tarfile.open(path, "w:gz") as tf:
        for i, vid in enumerate(REGULAR_IDS):
            if i == 2:
                link = tarfile.TarInfo(name="CGA-cccc-cccc-cccc.json")
                link.type = link_type
                link.linkname = link_target
                tf.addfile(link)
            content = f'{{"id": "{vid}"}}'.encode()
            info = tarfile.TarInfo(name=f"{vid}.json")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))


@pytest.mark.parametrize(
    ("link_type", "link_target"),
    [
        pytest.param(tarfile.SYMTYPE, f"{REGULAR_IDS[0]}.json", id="symlink-to-earlier-member"),
        pytest.param(tarfile.SYMTYPE, f"{REGULAR_IDS[-1]}.json", id="symlink-to-later-member"),
        pytest.param(tarfile.LNKTYPE, f"{REGULAR_IDS[0]}.json", id="hardlink-to-earlier-member"),
    ],
)
def test_load_reads_every_regular_member_when_archive_has_a_link(tmpdir, auto_fake_fixdate_finder, link_type, link_target):
    """a link member in the feed archive must not stop the regular members after it from loading."""
    p = OSVParser(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        url="https://packages.cgr.dev/chainguard/v2/osv/all.json",
        namespace="wolfi",
    )
    os.makedirs(p.input_dir_path, exist_ok=True)
    _write_archive(os.path.join(p.input_dir_path, p._tar_file), link_type, link_target)

    loaded = {data["id"] for _, data in p._load()}

    assert set(REGULAR_IDS) <= loaded


def test_load_skips_the_link_member(tmpdir, auto_fake_fixdate_finder):
    """the link member itself must not be yielded; set-based assertions cannot see a duplicate"""
    p = OSVParser(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        url="https://packages.cgr.dev/chainguard/v2/osv/all.json",
        namespace="wolfi",
    )
    os.makedirs(p.input_dir_path, exist_ok=True)
    _write_archive(os.path.join(p.input_dir_path, p._tar_file), tarfile.SYMTYPE, f"{REGULAR_IDS[0]}.json")

    loaded = [data["id"] for _, data in p._load()]

    assert sorted(loaded) == sorted(REGULAR_IDS)
