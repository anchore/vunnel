from __future__ import annotations

import os

import pytest

from vunnel import workspace
from vunnel.providers.alpine.rejections import SecurityRejections


class TestSecurityRejections:
    @pytest.fixture()
    def mock_main_yaml(self):
        """Sample main.yaml content for security-rejections."""
        return """dnsmasq:
  - CVE-2021-45951
  - CVE-2021-45952
  - CVE-2021-45953
nginx:
  - CVE-2020-12345
"""

    @pytest.fixture()
    def mock_community_yaml(self):
        """Sample community.yaml content for security-rejections."""
        return """some-package:
  - CVE-2022-11111
  - CVE-2022-22222
"""

    def test_load_parses_yaml_correctly(self, tmpdir, mock_main_yaml, mock_community_yaml):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        # Create the rejections directory and files manually
        os.makedirs(rejections._rejections_dir, exist_ok=True)
        with open(os.path.join(rejections._rejections_dir, "main.yaml"), "w") as fp:
            fp.write(mock_main_yaml)
        with open(os.path.join(rejections._rejections_dir, "community.yaml"), "w") as fp:
            fp.write(mock_community_yaml)

        # Test get() which should lazy-load the data
        main_rejections = rejections.get("main")
        assert "dnsmasq" in main_rejections
        assert main_rejections["dnsmasq"] == ["CVE-2021-45951", "CVE-2021-45952", "CVE-2021-45953"]
        assert "nginx" in main_rejections
        assert main_rejections["nginx"] == ["CVE-2020-12345"]

        community_rejections = rejections.get("community")
        assert "some-package" in community_rejections
        assert community_rejections["some-package"] == ["CVE-2022-11111", "CVE-2022-22222"]

    def test_get_returns_empty_for_missing_file(self, tmpdir):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        # Create the rejections directory but no files
        os.makedirs(rejections._rejections_dir, exist_ok=True)

        # Should return empty dicts when files don't exist
        assert rejections.get("main") == {}
        assert rejections.get("community") == {}

    def test_get_returns_empty_for_unknown_dbtype(self, tmpdir, mock_main_yaml):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        os.makedirs(rejections._rejections_dir, exist_ok=True)
        with open(os.path.join(rejections._rejections_dir, "main.yaml"), "w") as fp:
            fp.write(mock_main_yaml)

        # Unknown db_type should return empty dict
        assert rejections.get("unknown") == {}

    def test_load_handles_malformed_yaml_gracefully(self, tmpdir):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        os.makedirs(rejections._rejections_dir, exist_ok=True)
        with open(os.path.join(rejections._rejections_dir, "main.yaml"), "w") as fp:
            fp.write("invalid: yaml: content: [")

        # Should not raise, just return empty
        result = rejections.get("main")
        assert result == {}

    def test_load_handles_unexpected_format(self, tmpdir):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        # YAML with non-list value for a package
        yaml_content = """dnsmasq: not-a-list
nginx:
  - CVE-2020-12345
"""
        os.makedirs(rejections._rejections_dir, exist_ok=True)
        with open(os.path.join(rejections._rejections_dir, "main.yaml"), "w") as fp:
            fp.write(yaml_content)

        # Should handle gracefully - skip malformed entries but keep valid ones
        result = rejections.get("main")
        assert "dnsmasq" not in result  # skipped due to bad format
        assert "nginx" in result
        assert result["nginx"] == ["CVE-2020-12345"]

    def test_load_handles_empty_yaml(self, tmpdir):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        os.makedirs(rejections._rejections_dir, exist_ok=True)
        with open(os.path.join(rejections._rejections_dir, "main.yaml"), "w") as fp:
            fp.write("")

        result = rejections.get("main")
        assert result == {}

    def test_download_creates_directory(self, tmpdir, monkeypatch):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        # Mock the HTTP get to avoid actual network calls
        class MockResponse:
            def iter_content(self):
                return [b"dnsmasq:\n  - CVE-2021-45951\n"]

        def mock_get(*args, **kwargs):
            return MockResponse()

        from vunnel.utils import http_wrapper

        monkeypatch.setattr(http_wrapper, "get", mock_get)

        rejections.download()

        assert os.path.exists(rejections._rejections_dir)
        assert os.path.exists(os.path.join(rejections._rejections_dir, "main.yaml"))
        assert os.path.exists(os.path.join(rejections._rejections_dir, "community.yaml"))

    def test_download_failure_logs_warning_but_continues(self, tmpdir, monkeypatch, caplog):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com",
            workspace=ws,
        )

        def mock_get_fail(*args, **kwargs):
            raise Exception("Network error")

        from vunnel.utils import http_wrapper

        monkeypatch.setattr(http_wrapper, "get", mock_get_fail)

        # Should not raise
        rejections.download()

        # Check that warning was logged
        assert any("failed to download security-rejections" in record.message for record in caplog.records)

    def test_url_trailing_slash_stripped(self, tmpdir):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        rejections = SecurityRejections(
            url="https://example.com/path/",
            workspace=ws,
        )

        assert rejections.url == "https://example.com/path"
