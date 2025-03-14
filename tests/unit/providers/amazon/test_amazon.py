from __future__ import annotations

import shutil
from requests.exceptions import HTTPError
from unittest.mock import Mock

import pytest
from vunnel import result, workspace
from vunnel.utils.http_wrapper import requests
from vunnel.providers.amazon import Config, Provider, parser


class TestParser:
    def test_rss_parsing(self, tmpdir, helpers):
        mock_data_path = helpers.local_dir("test-fixtures/mock_rss")
        p = parser.Parser(workspace=workspace.Workspace(tmpdir, "test", create=True))
        summaries = p._parse_rss(mock_data_path)

        assert isinstance(summaries, list)
        assert len(summaries) > 0  # TODO: what is the right answer?

        for alas in summaries:
            assert isinstance(alas, parser.AlasSummary)
            assert alas.id is not None
            assert alas.url is not None
            assert alas.sev.lower() in parser.severity_map

        # TODO: beef up these assertions (should cover the full data shape)

    def test_html_parsing(self, helpers):
        new_packages = [
            "java-1.8.0-openjdk-javadoc-1.8.0.161-0.b14.amzn2.noarch",
            "java-1.8.0-openjdk-javadoc-zip-1.8.0.161-0.b14.amzn2.noarch",
            "java-1.8.0-openjdk-javadoc-debug-1.8.0.161-0.b14.amzn2.noarch",
            "java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.161-0.b14.amzn2.noarch",
            "java-1.8.0-openjdk-1.8.0.161-0.b14.amzn2.src",
            "java-1.8.0-openjdk-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-debug-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-headless-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-headless-debug-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-devel-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-devel-debug-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-demo-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-demo-debug-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-src-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-src-debug-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-accessibility-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-accessibility-debug-1.8.0.161-0.b14.amzn2.x86_64",
            "java-1.8.0-openjdk-debuginfo-1.8.0.161-0.b14.amzn2.x86_64",
        ]

        mock_data_path = helpers.local_dir("test-fixtures/mock_html")
        with open(mock_data_path) as fp:
            html_content = fp.read()

        p = parser.PackagesHTMLParser()
        p.feed(html_content)

        assert p.fixes is not None
        assert new_packages == p.fixes
        assert p.issue_overview_text is not None
        # TODO: beef up these assertions (should cover the full data shape)

    def test_get_pkg_name_version(self):
        f = parser.Parser.get_package_name_version("java-1.8.0-openjdk-javadoc-1.8.0.161-0.b14.amzn2.noarch")
        assert f.pkg == "java-1.8.0-openjdk-javadoc"
        assert f.ver == "1.8.0.161-0.b14.amzn2"

        f = parser.Parser.get_package_name_version("java-1.8.0-openjdk-1.8.0.161-0.b14.amzn2.src")
        assert f.pkg == "java-1.8.0-openjdk"
        assert f.ver == "1.8.0.161-0.b14.amzn2"

        f = parser.Parser.get_package_name_version("java-1.8.0-openjdk-debug-1.8.0.161-0.b14.amzn2.x86_64")
        assert f.pkg == "java-1.8.0-openjdk-debug"
        assert f.ver == "1.8.0.161-0.b14.amzn2"

        a = parser.Parser.get_package_name_version("java-1.8.0-openjdk-1.8.0.161-0.b14.amzn2.src")
        b = parser.Parser.get_package_name_version("java-1.8.0-openjdk-1.8.0.161-0.b14.amzn2.x86_64")
        assert a == b

    def test_get_alas_html_403(self, helpers, monkeypatch, tmpdir):
        # write a mock such that any http.get call will return a response with status code 403
        def mock_get(*args, **kwargs):
            return Mock(status_code=403)

        monkeypatch.setattr(requests, "get", mock_get)

        alas_file = tmpdir.join("alas.html")

        p = parser.Parser(workspace=workspace.Workspace(helpers.local_dir("test-fixtures"), "test", create=True))
        alas = p._get_alas_html("https://example.com", alas_file)
        assert alas is None

    def test_get_alas_html_raises_over_threshold(self, helpers, monkeypatch, tmpdir):
        # write a mock such that any http.get call will return a response with status code 403
        url = "https://example.com"

        def mock_get(*args, **kwargs):
            return Mock(status_code=403, url=url)

        monkeypatch.setattr(requests, "get", mock_get)

        alas_file = tmpdir.join("alas.html")

        p = parser.Parser(workspace=workspace.Workspace(helpers.local_dir("test-fixtures"), "test", create=True))
        p.max_allowed_alas_http_403 = 2

        # assert does not raise when at the threshold
        p.alas_403s = ["something"]
        p._get_alas_html(url, alas_file)
        assert p.alas_403s == ["something", url]

        # assert raises when above the threshold
        with pytest.raises(ValueError):
            p._get_alas_html(url, alas_file)

        assert p.alas_403s == ["something", url, url]


def test_provider_schema(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)

    mock_data_path = helpers.local_dir("test-fixtures/input")
    shutil.copytree(mock_data_path, workspace.input_dir, dirs_exist_ok=True)

    def mock_download(self, *args, **kwargs):
        pass

    monkeypatch.setattr(p.parser, "_download_rss", mock_download)

    p.update(None)

    assert 3 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
    )

    c = Config()
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )

    def mock_download(_url, _file):
        return None

    monkeypatch.setattr(p.parser, "_download_rss", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()
