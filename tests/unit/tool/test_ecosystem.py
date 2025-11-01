from __future__ import annotations

import pytest

from vunnel.tool.fixdate.ecosystem import normalize_package_name



class TestNormalizePackageName:
    """tests for package name normalization functionality"""

    def test_basic_normalization(self):
        """test basic normalization for all ecosystems"""
        tests = [
            {
                "name": "strip spaces",
                "input": "  curl  ",
                "ecosystem": "debian",
                "expected": "curl",
            },
            {
                "name": "preserve case",
                "input": "CURL",
                "ecosystem": "debian",
                "expected": "CURL",
            },
            {
                "name": "empty string",
                "input": "",
                "ecosystem": "debian",
                "expected": "",
            },
            {
                "name": "no changes needed",
                "input": "curl",
                "ecosystem": "debian",
                "expected": "curl",
            },
        ]

        for test in tests:
            result = normalize_package_name(test["input"], test["ecosystem"])
            assert result == test["expected"], f"test '{test['name']}' failed: got {result}, expected {test['expected']}"

    def test_python_ecosystem_normalization(self):
        """test Python-specific normalization rules"""
        tests = [
            {
                "name": "python ecosystem with underscores",
                "input": "my_package",
                "ecosystem": "python",
                "expected": "my-package",
            },
            {
                "name": "python ecosystem with dots",
                "input": "my.package",
                "ecosystem": "python",
                "expected": "my-package",
            },
            {
                "name": "python ecosystem mixed separators",
                "input": "my_package.name",
                "ecosystem": "python",
                "expected": "my-package-name",
            },
            {
                "name": "pypi ecosystem with underscores",
                "input": "my_package",
                "ecosystem": "pypi",
                "expected": "my-package",
            },
            {
                "name": "pypi ecosystem with dots",
                "input": "my.package",
                "ecosystem": "pypi",
                "expected": "my-package",
            },
            {
                "name": "python ecosystem preserve case",
                "input": "MY_Package.Name",
                "ecosystem": "python",
                "expected": "MY-Package-Name",
            },
            {
                "name": "python ecosystem with spaces",
                "input": "  my_package.name  ",
                "ecosystem": "python",
                "expected": "my-package-name",
            },
        ]

        for test in tests:
            result = normalize_package_name(test["input"], test["ecosystem"])
            assert result == test["expected"], f"test '{test['name']}' failed: got {result}, expected {test['expected']}"

    def test_non_python_ecosystems(self):
        """test that non-Python ecosystems only get basic normalization"""
        tests = [
            {
                "name": "debian with underscores unchanged",
                "input": "my_package",
                "ecosystem": "debian",
                "expected": "my_package",
            },
            {
                "name": "debian with dots unchanged",
                "input": "my.package",
                "ecosystem": "debian",
                "expected": "my.package",
            },
            {
                "name": "rhel with underscores unchanged",
                "input": "MY_Package",
                "ecosystem": "rhel:8",
                "expected": "MY_Package",
            },
            {
                "name": "alpine with dots unchanged",
                "input": "My.Package",
                "ecosystem": "alpine",
                "expected": "My.Package",
            },
            {
                "name": "npm with underscores unchanged",
                "input": "my_package",
                "ecosystem": "npm",
                "expected": "my_package",
            },
            {
                "name": "none ecosystem unchanged",
                "input": "my_package.name",
                "ecosystem": None,
                "expected": "my_package.name",
            },
        ]

        for test in tests:
            result = normalize_package_name(test["input"], test["ecosystem"])
            assert result == test["expected"], f"test '{test['name']}' failed: got {result}, expected {test['expected']}"
