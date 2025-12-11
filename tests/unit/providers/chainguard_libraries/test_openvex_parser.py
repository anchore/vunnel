from __future__ import annotations

import datetime
import json
from unittest.mock import Mock, patch, mock_open

import pytest

from vunnel.providers.chainguard_libraries.openvex_parser import OpenVEXParser
from vunnel import workspace




@pytest.fixture
def mock_logger():
    return Mock()


@pytest.fixture
def openvex_parser(tmpdir, mock_logger, auto_fake_fixdate_finder):

    return OpenVEXParser(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        url="https://libraries.cgr.dev/openvex/v1/all.json",
        namespace="chainguard",
        download_timeout=60,
        logger=mock_logger,
        security_reference_url="https://images.chainguard.dev/security"
    )


class TestOpenVEXParser:
    def test_init_default_values(self, tmpdir, mock_logger, auto_fake_fixdate_finder):
        parser = OpenVEXParser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
            url="https://libraries.cgr.dev/openvex/v1/all.json",
            namespace="chainguard",
            logger=mock_logger
        )

        assert parser.namespace == "chainguard"
        assert parser.download_timeout == 125  # default value
        assert parser.url == "https://libraries.cgr.dev/openvex/v1/all.json"
        assert parser._base_url == "https://libraries.cgr.dev/openvex/v1/"
        assert parser._index_filename == "all.json"
        assert parser.output_path == str(tmpdir / "test" / "input" / "openvex")

    def test_init_custom_values(self, tmpdir, mock_logger, auto_fake_fixdate_finder):
        custom_url = "https://custom.example.com/vex/index.json/"
        custom_security_url = "https://custom.security.com/"

        parser = OpenVEXParser(
            workspace=workspace.Workspace(tmpdir, "test", create=True),
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
    def test_download_success(self, mock_file, mock_http_get, mock_exists, mock_makedirs, openvex_parser, auto_fake_fixdate_finder):
        mock_exists.return_value = False
        mock_response = Mock()
        mock_response.iter_content.return_value = [b'test data']
        mock_http_get.return_value = mock_response

        openvex_parser._download("test.json")

        mock_makedirs.assert_called_with( openvex_parser.workspace.input_path +  "/openvex", exist_ok=True)
        mock_http_get.assert_called_once_with(
            "https://libraries.cgr.dev/openvex/v1/test.json",
            openvex_parser.logger,
            stream=True,
            timeout=60,
            user_agent=None,
        )
        # oras will use this too, so we only need to make certain it was called at least once with the correct path
        mock_file.assert_called_with(openvex_parser.workspace.input_path + "/openvex/test.json", "wb+")

    @patch('os.path.exists')
    @patch('vunnel.providers.chainguard_libraries.openvex_parser.http.get')
    def test_download_handles_exception(self, mock_http_get, mock_exists, openvex_parser, auto_fake_fixdate_finder):
        mock_exists.return_value = True
        mock_http_get.side_effect = Exception("Network error")

        # Should raise exception
        with pytest.raises(Exception, match="Network error"):
            openvex_parser._download("test.json")

    def test_load_skips_index_file(self, openvex_parser, helpers):
        openvex_parser.output_path = helpers.local_dir("test-fixtures/input/openvex")
        files = [f for f in openvex_parser._load()]
        assert len(files) == 2  # pypi/joblib.openvex.json and urllib3.openvex.json

        # Verify both files are loaded and index file (all.json) is skipped
        file_names = [f[0] for f in files]
        assert "pypi" in file_names

    @pytest.mark.parametrize(
        "test_data,expected",
        [
            pytest.param(
                {"test": "data", "statements": [
                    {'vulnerability': {'name': 'foo'}, "products": [{'identifiers': {'purl': 'pkg:pypi/chainguard/foo@1.0+cgr.1'}}]}
                ]},
                {'foo': {'document': {'vulnerability': {'name': 'foo'}, "products": [{'identifiers': {'purl': 'pkg:pypi/chainguard/foo@1.0+cgr.1'}}]}, 'fixes': [{'product': 'pkg:pypi/chainguard/foo@1.0+cgr.1', 'available': {'date': datetime.date(2024, 1, 1), 'kind': 'first-observed'}}]}},
                id="good-purl-with-plus",
            ),
            pytest.param(
                {"test": "data", "statements": [
                    {'vulnerability': {'name': 'baz'}, "products": [{'identifiers': {'purl': 'pkg:pypi/joblib@1.0.0'}}]}
                ]},
                {'baz': {'document': {'vulnerability': {'name': 'baz'}, "products": []}, 'fixes': []}},
                id="ignore-non-chainguard-purls",
            ),
            pytest.param(
                {"test": "data", "statements": [
                    {'vulnerability': {'name': 'baz'}, "products": [{'identifiers': {'purl': 'pkg:pypi/joblib@1.0.0%2Bcgr.1'}}]}
                ]},
                {'baz': {'document': {'vulnerability': {'name': 'baz'}, "products": [{'identifiers': {'purl': 'pkg:pypi/joblib@1.0.0%2Bcgr.1'}}]}, 'fixes': [{'product': 'pkg:pypi/joblib@1.0.0%2Bcgr.1', 'available': {'date': datetime.date(2024, 1, 1), 'kind': 'first-observed'}}]}},
                id="encoded-purl-without-plus",
            ),
        ],
    )
    def test_normalize(self, openvex_parser, test_data, expected, auto_fake_fixdate_finder):
        assert expected == openvex_parser._finalize(test_data)

    @patch.object(OpenVEXParser, '_download')
    @patch.object(OpenVEXParser, '_load')
    @patch.object(OpenVEXParser, '_finalize')
    @patch('builtins.open', new_callable=mock_open)
    def test_get_integration(self, mock_file, mock_finalize, mock_load, mock_download, openvex_parser, auto_fake_fixdate_finder):
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
        mock_finalize.return_value = [{"normalized": "data"}]

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

    def test_init_with_no_url(self, tmpdir, mock_logger, auto_fake_fixdate_finder):
        with pytest.raises(ValueError, match="openvex url must be provided"):
            OpenVEXParser(
                workspace=workspace.Workspace(tmpdir, "test", create=True),
                url=None,  # type: ignore
                namespace="test",
                logger=mock_logger
            )

        with pytest.raises(ValueError, match="openvex url must be provided"):
            OpenVEXParser(
                workspace=workspace.Workspace(tmpdir, "test", create=True),
                url="",
                namespace="test",
                logger=mock_logger
            )

    def test_init_creates_default_logger(self, tmpdir, auto_fake_fixdate_finder):
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger

            parser = OpenVEXParser(
                workspace=workspace.Workspace(tmpdir, "test", create=True),
                url="https://test.com/vex/all.json",
                namespace="test"
            )

            assert parser.logger == mock_logger
            mock_get_logger.assert_called_with("OpenVEXParser")
