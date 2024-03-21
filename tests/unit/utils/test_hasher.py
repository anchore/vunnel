import hashlib

import xxhash
import pytest

from unittest.mock import mock_open, patch
from vunnel.utils.hasher import Method


@pytest.mark.parametrize(
    "method,data,label,expected",
    [
        (Method.SHA256, b"test data 1", True, "sha256:05e8fdb3598f91bcc3ce41a196e587b4592c8cdfc371c217274bfda2d24b1b4e"),
        (Method.SHA256, b"test data 2", False, "26637da1bd793f9011a3d304372a9ec44e36cc677d2bbfba32a2f31f912358fe"),
        (Method.XXH64, b"test data 1", True, "xxh64:7ccde767ab423322"),
    ],
)
def test_digest(method, data, label, expected):
    m = mock_open(read_data=data)
    with patch("builtins.open", m):
        assert method.digest("any path", label) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("sha256:05e8fdb3598f91bcc3ce41a196e587b4592c8cdfc371c217274bfda2d24b1b4e", Method.SHA256),
        ("sha256", Method.SHA256),
        ("sha-256", Method.SHA256),
        ("SHA256", Method.SHA256),
        ("xxh64", Method.XXH64),
        ("xXh64  ", Method.XXH64),
    ],
)
def test_parse(value, expected):
    assert Method.parse(value) == expected
