"""Unit tests for tests/quality/configure.py."""

from __future__ import annotations

import pytest

from tests.quality.conftest import ConfigFixture


class TestGetBaseRef:
    """Tests for get_base_ref() function."""

    def test_default_returns_origin_main(self, monkeypatch):
        """When GITHUB_BASE_REF is not set, returns origin/main."""
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)

        from tests.quality.configure import get_base_ref

        assert get_base_ref() == "origin/main"

    def test_uses_github_base_ref_env(self, monkeypatch):
        """Uses GITHUB_BASE_REF when set."""
        monkeypatch.setenv("GITHUB_BASE_REF", "develop")

        from tests.quality.configure import get_base_ref

        assert get_base_ref() == "origin/develop"

    def test_handles_empty_github_base_ref(self, monkeypatch):
        """Falls back to origin/main when GITHUB_BASE_REF is empty string."""
        monkeypatch.setenv("GITHUB_BASE_REF", "")

        from tests.quality.configure import get_base_ref

        assert get_base_ref() == "origin/main"

    def test_preserves_full_ref_with_slash(self, monkeypatch):
        """When GITHUB_BASE_REF already has slash, doesn't add origin/ prefix."""
        monkeypatch.setenv("GITHUB_BASE_REF", "upstream/feature")

        from tests.quality.configure import get_base_ref

        assert get_base_ref() == "upstream/feature"


class TestConfigYamlChanges:
    """Tests for config_yaml_changes() function."""

    def test_no_config_change_returns_empty(self, configure_test_harness):
        """When config.yaml not in changed files, returns (False, empty set)."""
        state = configure_test_harness
        state.changed_files = ["src/vunnel/providers/alpine/parser.py"]

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is False
        assert providers == set()

    def test_new_config_file_triggers_global_change(self, configure_test_harness):
        """When config.yaml is new (doesn't exist in base), returns global change."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]
        # Don't set base_file_contents - simulates file not existing in base branch
        state.local_file_contents = {"config.yaml": "yardstick:\n  default_max_year: 2021\n"}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is True

    def test_missing_local_config_triggers_global_change(self, configure_test_harness):
        """When config.yaml doesn't exist locally, returns global change."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]
        state.base_file_contents = {
            "tests/quality/config.yaml": "yardstick:\n  default_max_year: 2021\n"
        }
        # Don't set local_file_contents - simulates file not found

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is True

    def test_yardstick_change_triggers_global(self, configure_test_harness, config_fixture):
        """When yardstick settings change, all providers are affected."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.yardstick = {"default_max_year": 2021}

        new_config = config_fixture()
        new_config.yardstick = {"default_max_year": 2022}  # Changed!

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is True

    def test_grype_db_change_triggers_global(self, configure_test_harness, config_fixture):
        """When grype_db settings change, all providers are affected."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.grype_db = {"version": "main"}

        new_config = config_fixture()
        new_config.grype_db = {"version": "v1.0.0"}  # Changed!

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is True

    def test_xref_change_triggers_global(self, configure_test_harness, config_fixture):
        """When x-ref (YAML anchors) change, all providers are affected."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.x_ref = {"default-validations": {"max_f1_regression": 0.0}}

        new_config = config_fixture()
        new_config.x_ref = {"default-validations": {"max_f1_regression": 0.1}}  # Changed!

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is True

    def test_provider_specific_change_returns_provider(self, configure_test_harness, config_fixture):
        """When only a provider's config changes, only that provider is returned."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.with_provider("alpine", images=["old-image:v1"])
        old_config.with_provider("amazon", images=["amazon-image:v1"])

        new_config = config_fixture()
        new_config.with_provider("alpine", images=["new-image:v2"])  # Changed!
        new_config.with_provider("amazon", images=["amazon-image:v1"])  # Unchanged

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is False
        assert providers == {"alpine"}

    def test_new_provider_returns_that_provider(self, configure_test_harness, config_fixture):
        """When a new provider is added, it's returned in the set."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.with_provider("alpine", images=["alpine-image:v1"])

        new_config = config_fixture()
        new_config.with_provider("alpine", images=["alpine-image:v1"])
        new_config.with_provider("amazon", images=["amazon-image:v1"])  # New!

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is False
        assert providers == {"amazon"}

    def test_removed_provider_not_returned(self, configure_test_harness, config_fixture):
        """When a provider is removed, it's not in the returned set (no testing needed)."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.with_provider("alpine", images=["alpine-image:v1"])
        old_config.with_provider("amazon", images=["amazon-image:v1"])

        new_config = config_fixture()
        new_config.with_provider("alpine", images=["alpine-image:v1"])
        # amazon removed

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is False
        assert providers == set()  # Removed provider doesn't need testing

    def test_multiple_provider_changes(self, configure_test_harness, config_fixture):
        """When multiple providers change, all are returned."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        old_config = config_fixture()
        old_config.with_provider("alpine", images=["alpine:v1"])
        old_config.with_provider("amazon", images=["amazon:v1"])
        old_config.with_provider("debian", images=["debian:v1"])

        new_config = config_fixture()
        new_config.with_provider("alpine", images=["alpine:v2"])  # Changed
        new_config.with_provider("amazon", images=["amazon:v2"])  # Changed
        new_config.with_provider("debian", images=["debian:v1"])  # Unchanged

        state.base_file_contents = {"tests/quality/config.yaml": old_config.to_yaml()}
        state.local_file_contents = {"config.yaml": new_config.to_yaml()}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is False
        assert providers == {"alpine", "amazon"}

    def test_semantically_equivalent_yaml_returns_empty(self, configure_test_harness):
        """When YAML parses to identical structure despite textual differences, no providers are affected."""
        state = configure_test_harness
        state.changed_files = ["tests/quality/config.yaml"]

        # Different text, same parsed structure (extra whitespace, different quote styles)
        old_yaml = """yardstick:
  default_max_year: 2021
tests:
  - provider: alpine
    images:
      - img1
"""
        new_yaml = """yardstick:
  default_max_year:   2021
tests:
  - provider:   "alpine"
    images: ['img1']
"""

        state.base_file_contents = {"tests/quality/config.yaml": old_yaml}
        state.local_file_contents = {"config.yaml": new_yaml}

        from tests.quality.configure import config_yaml_changes

        global_change, providers = config_yaml_changes(state.changed_files)

        assert global_change is False
        assert providers == set()


class TestYardstickVersionChanged:
    """Tests for yardstick_version_changed() function."""

    def test_no_yardstick_change(self, configure_test_harness):
        """When yardstick git reference is not in diff, returns False."""
        state = configure_test_harness
        state.diff_output = """
diff --git a/src/vunnel/provider.py b/src/vunnel/provider.py
--- a/src/vunnel/provider.py
+++ b/src/vunnel/provider.py
@@ -1,3 +1,4 @@
+# some comment
 import os
"""

        from tests.quality.configure import yardstick_version_changed

        assert yardstick_version_changed() is False

    def test_yardstick_version_added(self, configure_test_harness):
        """When yardstick git reference is added, returns True."""
        state = configure_test_harness
        state.diff_output = """
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -10,6 +10,7 @@
+yardstick = { git = "https://github.com/anchore/yardstick", branch = "main" }
"""

        from tests.quality.configure import yardstick_version_changed

        assert yardstick_version_changed() is True

    def test_yardstick_version_removed(self, configure_test_harness):
        """When yardstick git reference is removed, returns True."""
        state = configure_test_harness
        state.diff_output = """
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -10,7 +10,6 @@
-yardstick = { git = "https://github.com/anchore/yardstick", branch = "main" }
"""

        from tests.quality.configure import yardstick_version_changed

        assert yardstick_version_changed() is True

    def test_yardstick_in_context_not_detected(self, configure_test_harness):
        """Yardstick reference in context (not +/-) is not detected as change."""
        state = configure_test_harness
        state.diff_output = """
diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -10,6 +10,7 @@
 yardstick = { git = "https://github.com/anchore/yardstick", branch = "main" }
+some_other_dep = "1.0.0"
"""

        from tests.quality.configure import yardstick_version_changed

        assert yardstick_version_changed() is False
