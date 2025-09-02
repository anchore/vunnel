from __future__ import annotations

import json
from unittest.mock import Mock, patch, mock_open

import pytest

from vunnel.providers.chainguard_libraries.openvex_parser import OpenVEXParser


@pytest.fixture
def mock_workspace():
    workspace = Mock()
    workspace.input_path = "/tmp/test"
    return workspace


@pytest.fixture
def mock_logger():
    return Mock()


@pytest.fixture
def openvex_parser(mock_workspace, mock_logger):
    return OpenVEXParser(
        workspace=mock_workspace,
        url="https://packages.cgr.dev/chainguard/vex/all.json",
        namespace="chainguard",
        download_timeout=60,
        logger=mock_logger,
        security_reference_url="https://images.chainguard.dev/security"
    )


class TestOpenVEXParser:
    def test_init_default_values(self, mock_workspace, mock_logger):
        parser = OpenVEXParser(
            workspace=mock_workspace,
            url="https://packages.cgr.dev/chainguard/vex/all.json",
            namespace="chainguard",
            logger=mock_logger
        )

        assert parser.namespace == "chainguard"
        assert parser.download_timeout == 125  # default value
        assert parser.url == "https://packages.cgr.dev/chainguard/vex/all.json"
        assert parser._base_url == "https://packages.cgr.dev/chainguard/vex/"
        assert parser._index_filename == "all.json"
        assert parser.output_path == "/tmp/test/openvex"

    def test_init_custom_values(self, mock_workspace, mock_logger):
        custom_url = "https://custom.example.com/vex/index.json/"
        custom_security_url = "https://custom.security.com/"

        parser = OpenVEXParser(
            workspace=mock_workspace,
            url=custom_url,
            namespace="custom",
            download_timeout=30,
            logger=mock_logger,
            security_reference_url=custom_security_url
        )

        assert parser.namespace == "custom"
        assert parser.download_timeout == 30
        assert parser.url == "https://custom.example.com/vex/index.json"
        assert parser.security_reference_url == "https://custom.security.com"
        assert parser._index_filename == "index.json"

    def test_extract_filename_from_url(self):
        assert OpenVEXParser._extract_filename_from_url("https://example.com/path/file.json") == "file.json"
        assert OpenVEXParser._extract_filename_from_url("https://example.com/file.json") == "file.json"
        assert OpenVEXParser._extract_filename_from_url("/local/path/file.json") == "file.json"

    def test_build_reference_links(self, openvex_parser):
        with patch('vunnel.providers.chainguard_libraries.openvex_parser.vulnerability.build_reference_links') as mock_build:
            mock_build.return_value = ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"]

            links = openvex_parser.build_reference_links("CVE-2023-1234")

            assert "https://images.chainguard.dev/security/CVE-2023-1234" in links
            assert "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234" in links
            mock_build.assert_called_once_with("CVE-2023-1234")

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.chainguard_libraries.openvex_parser.http.get')
    @patch('builtins.open', new_callable=mock_open)
    def test_download_success(self, mock_file, mock_http_get, mock_exists, mock_makedirs, openvex_parser):
        mock_exists.return_value = False
        mock_response = Mock()
        mock_response.iter_content.return_value = [b'test data']
        mock_http_get.return_value = mock_response

        openvex_parser._download("test.json")

        mock_makedirs.assert_called_with("/tmp/test/openvex", exist_ok=True)
        mock_http_get.assert_called_once_with(
            "https://packages.cgr.dev/chainguard/vex/test.json",
            openvex_parser.logger,
            stream=True,
            timeout=60
        )
        mock_file.assert_called_once_with("/tmp/test/openvex/test.json", "wb+")

    @patch('os.makedirs')
    @patch('os.path.exists')
    @patch('vunnel.providers.chainguard_libraries.openvex_parser.http.get')
    def test_download_handles_exception(self, mock_http_get, mock_exists, mock_makedirs, openvex_parser):
        mock_exists.return_value = True
        mock_http_get.side_effect = Exception("Network error")

        # Should not raise exception
        openvex_parser._download("test.json")

        openvex_parser.logger.exception.assert_called_once()

    def test_load_skips_index_file(self, openvex_parser, helpers):
        openvex_parser.output_path = helpers.local_dir("test-fixtures/input/openvex")
        files = [f for f in openvex_parser._load()]
        assert len(files) == 2  # java/jenkins.openvex.json and php/php.openvex.json

        # Verify both files are loaded and index file (all.json) is skipped
        file_names = [f[0] for f in files]
        assert "java" in file_names
        assert "php" in file_names

    def test_normalize(self, openvex_parser):
        foo = {'vulnerability': {'name': 'foo'}, "products": [{'identifiers': {'purl': 'pkg:pypi/chainguard/foo@1.0+cgr.1'}}]}
        bar = {'vulnerability': {'name': 'bar'}, "products": [{'identifiers': {'purl': 'pkg:pypi/chainguard/foo@1.2'}}]}
        test_data = {"test": "data", "statements": [foo, bar, {'vuln': 2}]}
        # strips invalid entries and non-chainguard products
        assert {'foo': foo, 'bar': {'vulnerability': {'name': 'bar'}, "products": []}} == openvex_parser._normalize(test_data)

    @patch.object(OpenVEXParser, '_download')
    @patch.object(OpenVEXParser, '_load')
    @patch.object(OpenVEXParser, '_normalize')
    @patch('builtins.open', new_callable=mock_open)
    def test_get_integration(self, mock_file, mock_normalize, mock_load, mock_download, openvex_parser):
        # Mock index file content
        index_data = {
            "entries": [
                {"id": "file1.json", "modified": "2023-01-01T00:00:00Z"},
                {"id": "subdir/file2.json", "modified": "2023-01-02T00:00:00Z"}
            ]
        }
        mock_file.return_value.read.return_value = json.dumps(index_data).encode()

        # Mock load and normalize
        mock_load.return_value = [("rolling", {"test": "data"})]
        mock_normalize.return_value = [{"normalized": "data"}]

        results = list(openvex_parser.get())

        # Verify downloads
        assert mock_download.call_count == 3  # index + 2 entries
        mock_download.assert_any_call("all.json")
        mock_download.assert_any_call("file1.json")
        mock_download.assert_any_call("subdir/file2.json")

        # Verify results
        assert len(results) == 1
        release, normalized_data = results[0]
        assert release == "rolling"
        assert list(normalized_data) == [{"normalized": "data"}]

    def test_init_with_no_url(self, mock_workspace, mock_logger):
        with pytest.raises(ValueError, match="openvex url must be provided"):
            OpenVEXParser(
                workspace=mock_workspace,
                url=None,  # type: ignore
                namespace="test",
                logger=mock_logger
            )

        with pytest.raises(ValueError, match="openvex url must be provided"):
            OpenVEXParser(
                workspace=mock_workspace,
                url="",
                namespace="test",
                logger=mock_logger
            )

    def test_init_creates_default_logger(self, mock_workspace):
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger

            parser = OpenVEXParser(
                workspace=mock_workspace,
                url="https://test.com/vex/all.json",
                namespace="test"
            )

            assert parser.logger == mock_logger
            mock_get_logger.assert_called_once_with("OpenVEXParser")
