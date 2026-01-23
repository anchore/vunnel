"""Test fixtures for tests/quality/configure.py tests."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Callable
from unittest.mock import mock_open

import pytest


@dataclass
class GitMockState:
    """State container for mocking git operations in configure.py tests.

    This allows tests to inject:
    - changed_files: list of files returned by `git diff --name-only`
    - base_file_contents: dict mapping file paths to their content in the base branch
    - local_file_contents: dict mapping local file paths to their content
    """

    changed_files: list[str] = field(default_factory=list)
    base_file_contents: dict[str, str] = field(default_factory=dict)
    local_file_contents: dict[str, str] = field(default_factory=dict)


@pytest.fixture
def git_mock_state() -> GitMockState:
    """Create a fresh GitMockState for each test."""
    return GitMockState()


@pytest.fixture
def mock_git_operations(monkeypatch, git_mock_state: GitMockState):
    """Mock git subprocess calls used by configure.py.

    This fixture intercepts:
    - `git diff --name-only <ref>` -> returns git_mock_state.changed_files
    - `git show <ref>:<path>` -> returns content from git_mock_state.base_file_contents

    Usage:
        def test_something(mock_git_operations, git_mock_state):
            git_mock_state.changed_files = ["src/foo.py", "tests/quality/config.yaml"]
            git_mock_state.base_file_contents = {
                "tests/quality/config.yaml": "old: content"
            }
            # Now calls to changes() will return the mocked files
    """
    original_check_output = subprocess.check_output

    def mock_check_output(cmd: list[str], **kwargs) -> bytes:
        if not isinstance(cmd, list) or len(cmd) < 2:
            return original_check_output(cmd, **kwargs)

        if cmd[0] != "git":
            return original_check_output(cmd, **kwargs)

        # git diff --name-only <ref>
        if cmd[1] == "diff" and "--name-only" in cmd:
            return "\n".join(git_mock_state.changed_files).encode("utf-8")

        # git show <ref>:<path>
        if cmd[1] == "show" and len(cmd) >= 3:
            ref_path = cmd[2]  # e.g., "origin/main:tests/quality/config.yaml"
            if ":" in ref_path:
                _, file_path = ref_path.split(":", 1)
                if file_path in git_mock_state.base_file_contents:
                    return git_mock_state.base_file_contents[file_path].encode("utf-8")
                # File doesn't exist in base branch
                raise subprocess.CalledProcessError(1, cmd)

        return original_check_output(cmd, **kwargs)

    monkeypatch.setattr(subprocess, "check_output", mock_check_output)
    return git_mock_state


@pytest.fixture
def mock_local_files(monkeypatch, git_mock_state: GitMockState):
    """Mock local file reads for configure.py tests.

    This allows tests to control what content is returned when configure.py
    reads local files (e.g., config.yaml).

    Usage:
        def test_something(mock_git_operations, mock_local_files, git_mock_state):
            git_mock_state.local_file_contents = {
                "config.yaml": "new: content"
            }
            # Now open("config.yaml") will return the mocked content
    """
    original_open = open

    def patched_open(file, mode="r", *args, **kwargs):
        if mode == "r" or mode == "rt":
            file_str = str(file)
            if file_str in git_mock_state.local_file_contents:
                return mock_open(read_data=git_mock_state.local_file_contents[file_str])()
        return original_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", patched_open)
    return git_mock_state


@pytest.fixture
def configure_test_harness(mock_git_operations, mock_local_files, git_mock_state):
    """Combined fixture that sets up all mocks for configure.py testing.

    This is the main fixture to use for testing configure.py functions.
    It combines git operation mocking, local file mocking, and environment mocking.

    Usage:
        def test_config_yaml_changes(configure_test_harness):
            state = configure_test_harness

            # Setup: config.yaml changed with provider-specific change
            state.changed_files = ["tests/quality/config.yaml"]
            state.base_file_contents = {
                "tests/quality/config.yaml": '''
                    yardstick:
                      default_max_year: 2021
                    tests:
                      - provider: alpine
                        images: ["old-image"]
                '''
            }
            state.local_file_contents = {
                "config.yaml": '''
                    yardstick:
                      default_max_year: 2021
                    tests:
                      - provider: alpine
                        images: ["new-image"]
                '''
            }

            # Test
            from configure import config_yaml_changes
            global_change, providers = config_yaml_changes(state.changed_files)

            assert not global_change
            assert providers == {"alpine"}
    """
    return git_mock_state


@dataclass
class ConfigFixture:
    """Helper for creating config.yaml content for tests."""

    yardstick: dict = field(default_factory=lambda: {"default_max_year": 2021})
    grype_db: dict = field(default_factory=lambda: {"version": "main"})
    x_ref: dict | None = None
    tests: list[dict] = field(default_factory=list)

    def to_yaml(self) -> str:
        """Convert to YAML string."""
        import yaml

        data = {
            "yardstick": self.yardstick,
            "grype_db": self.grype_db,
            "tests": self.tests,
        }
        if self.x_ref is not None:
            data["x-ref"] = self.x_ref
        return yaml.dump(data, default_flow_style=False)

    def with_provider(self, name: str, **kwargs) -> "ConfigFixture":
        """Add a provider test configuration."""
        test = {"provider": name, **kwargs}
        self.tests.append(test)
        return self


@pytest.fixture
def config_fixture() -> Callable[[], ConfigFixture]:
    """Factory fixture for creating ConfigFixture instances.

    Usage:
        def test_something(config_fixture):
            old_config = config_fixture().with_provider("alpine", images=["img1"])
            new_config = config_fixture().with_provider("alpine", images=["img2"])

            # Use old_config.to_yaml() and new_config.to_yaml() in your test
    """

    def factory() -> ConfigFixture:
        return ConfigFixture()

    return factory
