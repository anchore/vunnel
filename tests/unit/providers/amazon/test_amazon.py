from __future__ import annotations

import shutil

import pytest
from vunnel import result, workspace
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


@pytest.fixture()
def disable_get_requests(monkeypatch):
    def disabled(*args, **kwargs):
        raise RuntimeError("requests disabled but HTTP GET attempted")

    monkeypatch.setattr(parser.requests, "get", disabled)


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
