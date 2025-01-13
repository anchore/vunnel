import pytest

from vunnel.utils.oval_parser import _craft_os

@pytest.mark.parametrize("ns_name, fix_version, expected", [
    # go case
    (
        "rhel:package",
        "tigervnc-server-1.13.1-8.el9_4.3",
        {"ID": "rhel", "Version": "9.4.3"}
    ),
    # without minor version
    (
        "centos:package",
        "httpd-2.4.37-43.el8",
        {"ID": "centos", "Version": "8"}
    ),
    # namespace containing multiple colons
    (
        "rhel:security:package",
        "openssh-server-8.0p1-13.el7_9.2",
        {"ID": "rhel", "Version": "7.9.2"}
    ),
    # complex package name
    (
        "fedora:package",
        "kernel-core-5.14.0-284.30.1.el9_2",
        {"ID": "fedora", "Version": "9.2"}
    ),
    # different version format
    (
        "oracle:package",
        "bash-4.4.20-4.el8_6",
        {"ID": "oracle", "Version": "8.6"}
    ),
    # no underscore in version
    (
        "rocky:package",
        "nginx-1.20.1-10.el9",
        {"ID": "rocky", "Version": "9"}
    ),
])
def test_craft_os(ns_name: str, fix_version: str, expected: dict[str, str]):
    result = _craft_os(ns_name, fix_version)
    assert result == expected, f"Expected {expected}, but got {result}"
