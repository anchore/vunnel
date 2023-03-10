from __future__ import annotations

import pytest
from vunnel.utils import rpm


@pytest.mark.parametrize(
    ("version1", "version2", "expected"),
    [
        # no epoch tests...
        ("1", "1", 0),
        ("4.19.0a-1.el7_5", "4.19.0c-1.el7", -1),
        ("4.19.0-1.el7_5", "4.21.0-1.el7", -1),
        ("4.19.01-1.el7_5", "4.19.10-1.el7_5", -1),
        ("4.19.0-1.el7_5", "4.19.0-1.el7", 1),
        ("4.19.0-1.el7_5", "4.17.0-1.el7", 1),
        ("4.19.01-1.el7_5", "4.19.1-1.el7_5", 0),
        ("4.19.1-1.el7_5", "4.19.1-01.el7_5", 0),
        ("4.19.1", "4.19.1", 0),
        ("1.2.3-el7_5~snapshot1", "1.2.3-3-el7_5", -1),
        # epoch tests...
        ("1:0", "0:1", 1),
        ("1:0", "1", -1),
        ("1:2", "1", 1),
        ("2:4.19.01-1.el7_5", "4.19.1-1.el7_5", 0),
        ("4.19.01-1.el7_5", "2:4.19.1-1.el7_5", 0),
        ("0:4.19.1-1.el7_5", "2:4.19.1-1.el7_5", -1),
        ("4.19.0-1.el7_5", "12:4.19.0-1.el7", 1),
        ("3:4.19.0-1.el7_5", "4.21.0-1.el7", -1),
        ("4:1.2.3-3-el7_5", "1.2.3-el7_5~snapshot1", 1),
    ],
)
def test_compare_versions(version1, version2, expected):
    assert expected == rpm.compare_versions(version1, version2)
