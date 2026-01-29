from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from vunnel import workspace
from vunnel.tool.fixdate.first_observed import Store
from vunnel.tool.fixdate.finder import Result


class TestStore:
    """tests for the composite Store class in first_observed.py"""

    def test_store_initialization(self, tmpdir):
        """test that the Store initializes correctly with both sub-stores"""
        # create workspace
        name = "test-workspace"
        ws = workspace.Workspace(tmpdir, name, create=True)

        # create store instance
        store = Store(ws)

        # verify initialization
        assert store.workspace == ws
        assert store.logger.name == "grype-db-fixes-" + name
        assert store.grype_db_store is not None
        assert store.vunnel_store is not None

    def test_context_manager_entry(self, tmpdir):
        """test that context manager entry delegates to both stores"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock both stores' __enter__ methods
        store.grype_db_store.__enter__ = Mock(return_value=store.grype_db_store)
        store.vunnel_store.__enter__ = Mock(return_value=store.vunnel_store)

        # test context manager entry
        result = store.__enter__()

        # verify both stores were called
        store.grype_db_store.__enter__.assert_called_once()
        store.vunnel_store.__enter__.assert_called_once()
        assert result is store

    def test_context_manager_exit(self, tmpdir):
        """test that context manager exit delegates to both stores"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock both stores' __exit__ methods
        store.grype_db_store.__exit__ = Mock()
        store.vunnel_store.__exit__ = Mock()

        exc_type, exc_val, exc_tb = Exception, Exception("test"), None

        # test context manager exit
        store.__exit__(exc_type, exc_val, exc_tb)

        # verify both stores were called with correct arguments
        store.grype_db_store.__exit__.assert_called_once_with(exc_type, exc_val, exc_tb)
        store.vunnel_store.__exit__.assert_called_once_with(exc_type, exc_val, exc_tb)

    def test_download_delegates_to_grype_db_store(self, tmpdir):
        """test that download() only delegates to grype_db_store"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock the download method
        store.grype_db_store.download = Mock()

        # call download
        store.download()

        # verify grype_db_store download was called
        store.grype_db_store.download.assert_called_once()

    def test_get_changed_vuln_ids_since_delegates_to_grype_db(self, tmpdir):
        """test that get_changed_vuln_ids_since() delegates to grype_db_store"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock the method
        expected_ids = {"CVE-2023-0001", "CVE-2023-0002"}
        store.grype_db_store.get_changed_vuln_ids_since = Mock(return_value=expected_ids)

        since_date = datetime(2023, 1, 1)

        # call method
        result = store.get_changed_vuln_ids_since(since_date)

        # verify grype_db_store method was called with correct argument
        store.grype_db_store.get_changed_vuln_ids_since.assert_called_once_with(since_date)
        assert result == expected_ids

    def test_find_vunnel_first_returns_vunnel_results(self, tmpdir):
        """test that find() returns vunnel results when available"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # create expected vunnel results
        vunnel_results = [
            Result(
                date=date(2023, 1, 15),
                kind="first-observed",
                version="1.0.0",
                source="vunnel",
            )
        ]

        # mock vunnel store to return results
        store.vunnel_store.find = Mock(return_value=vunnel_results)
        store.grype_db_store.find = Mock(return_value=[])

        # call find
        results = store.find("CVE-2023-0001", "test-package", "1.0.0", "debian")

        # verify vunnel store was called first and its results returned
        store.vunnel_store.find.assert_called_once_with("CVE-2023-0001", "test-package", "1.0.0", "debian")
        # grype_db should not be called when vunnel has results
        store.grype_db_store.find.assert_not_called()
        assert results == vunnel_results

    def test_find_falls_back_to_grype_db_when_no_vunnel_results(self, tmpdir):
        """test that find() falls back to grype_db when vunnel has no results"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # create expected grype_db results
        grype_db_results = [
            Result(
                date=date(2023, 2, 10),
                kind="first-observed",
                version="1.0.0",
                source="grype-db",
            )
        ]

        # mock vunnel to return empty, grype_db to return results
        store.vunnel_store.find = Mock(return_value=[])
        store.grype_db_store.find = Mock(return_value=grype_db_results)

        # call find
        results = store.find("CVE-2023-0001", "test-package", "1.0.0", "debian")

        # verify both stores were called in order
        store.vunnel_store.find.assert_called_once_with("CVE-2023-0001", "test-package", "1.0.0", "debian")
        store.grype_db_store.find.assert_called_once_with("CVE-2023-0001", "test-package", "1.0.0", "debian")
        assert results == grype_db_results

    @patch("vunnel.tool.fixdate.first_observed.datetime")
    def test_find_creates_new_entry_when_no_results_found(self, mock_datetime, tmpdir):
        """test that find() creates new vunnel entry when no results found"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock datetime.now(UTC).date() to return specific date
        test_date = date(2023, 5, 15)
        mock_datetime.now.return_value.date.return_value = test_date

        # mock both stores to return empty results
        store.vunnel_store.find = Mock(return_value=[])
        store.grype_db_store.find = Mock(return_value=[])
        store.vunnel_store.add = Mock()

        # call find
        results = store.find("CVE-2023-0001", "test-package", "1.0.0", "debian")

        # verify both stores were queried
        store.vunnel_store.find.assert_called_once_with("CVE-2023-0001", "test-package", "1.0.0", "debian")
        store.grype_db_store.find.assert_called_once_with("CVE-2023-0001", "test-package", "1.0.0", "debian")

        # verify new entry was added to vunnel with mocked date
        store.vunnel_store.add.assert_called_once()
        add_call_args = store.vunnel_store.add.call_args[0]
        assert add_call_args[0] == test_date
        assert add_call_args[1] == "CVE-2023-0001"
        assert add_call_args[2] == "test-package"
        assert add_call_args[3] == "1.0.0"
        assert add_call_args[4] == "debian"

        # verify result is returned with mocked date
        assert len(results) == 1
        result = results[0]
        assert isinstance(result, Result)
        assert result.date == test_date
        assert result.kind == "first-observed"
        assert result.version == "1.0.0"
        assert result.source == "vunnel"

    def test_find_with_all_parameters(self, tmpdir):
        """test find() with all parameter variations"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock both stores
        store.vunnel_store.find = Mock(return_value=[])
        store.grype_db_store.find = Mock(return_value=[])
        store.vunnel_store.add = Mock()

        # test with all parameters
        store.find("CVE-2023-0001", "test-package", "1.0.0", "debian")

        # verify both stores called with all parameters
        store.vunnel_store.find.assert_called_with("CVE-2023-0001", "test-package", "1.0.0", "debian")
        store.grype_db_store.find.assert_called_with("CVE-2023-0001", "test-package", "1.0.0", "debian")

    def test_find_with_optional_ecosystem_none(self, tmpdir):
        """test find() with ecosystem=None"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock both stores
        store.vunnel_store.find = Mock(return_value=[])
        store.grype_db_store.find = Mock(return_value=[])
        store.vunnel_store.add = Mock()

        # test with ecosystem=None
        store.find("CVE-2023-0001", "test-package", "1.0.0", None)

        # verify both stores called with ecosystem=None
        store.vunnel_store.find.assert_called_with("CVE-2023-0001", "test-package", "1.0.0", None)
        store.grype_db_store.find.assert_called_with("CVE-2023-0001", "test-package", "1.0.0", None)

    def test_find_with_cpe_input(self, tmpdir):
        """test find() with CPE as cpe_or_package parameter"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock both stores
        store.vunnel_store.find = Mock(return_value=[])
        store.grype_db_store.find = Mock(return_value=[])
        store.vunnel_store.add = Mock()

        cpe = "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*"

        # test with CPE
        store.find("CVE-2023-0001", cpe, "2.4.42")

        # verify both stores called with CPE
        store.vunnel_store.find.assert_called_with("CVE-2023-0001", cpe, "2.4.42", None)
        store.grype_db_store.find.assert_called_with("CVE-2023-0001", cpe, "2.4.42", None)

    def test_find_returns_expected_result_structure(self, tmpdir):
        """test that find() always returns list of Result objects"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        test_cases = [
            {
                "name": "vunnel has results",
                "vunnel_results": [Result(date(2023, 1, 1), "first-observed", "1.0.0", source="vunnel")],
                "grype_db_results": [],
                "expected_count": 1,
            },
            {
                "name": "grype_db has results",
                "vunnel_results": [],
                "grype_db_results": [Result(date(2023, 1, 2), "first-observed", "1.0.0", source="grype-db")],
                "expected_count": 1,
            },
            {
                "name": "no results creates new entry",
                "vunnel_results": [],
                "grype_db_results": [],
                "expected_count": 1,
            },
        ]

        for test_case in test_cases:
            # mock stores
            store.vunnel_store.find = Mock(return_value=test_case["vunnel_results"])
            store.grype_db_store.find = Mock(return_value=test_case["grype_db_results"])
            store.vunnel_store.add = Mock()

            # call find
            results = store.find("CVE-2023-0001", "test-package", "1.0.0")

            # verify result structure
            assert isinstance(results, list), f"test '{test_case['name']}' failed: results should be list"
            assert len(results) == test_case["expected_count"], f"test '{test_case['name']}' failed: expected {test_case['expected_count']} results, got {len(results)}"

            for result in results:
                assert isinstance(result, Result), f"test '{test_case['name']}' failed: all results should be Result objects"
                assert result.kind == "first-observed", f"test '{test_case['name']}' failed: all results should have kind='first-observed'"

    @patch("vunnel.tool.fixdate.first_observed.datetime")
    def test_find_uses_current_date_for_new_entries(self, mock_datetime, tmpdir):
        """test that find() uses today's date when creating new entries"""
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws)

        # mock datetime.now(UTC).date() to return specific date
        test_date = date(2023, 5, 15)
        mock_datetime.now.return_value.date.return_value = test_date

        # mock both stores to return empty results
        store.vunnel_store.find = Mock(return_value=[])
        store.grype_db_store.find = Mock(return_value=[])
        store.vunnel_store.add = Mock()

        # call find
        results = store.find("CVE-2023-0001", "test-package", "1.0.0")

        # verify add was called with mocked date
        store.vunnel_store.add.assert_called_once_with(test_date, "CVE-2023-0001", "test-package", "1.0.0", None)

        # verify returned result has the mocked date
        assert len(results) == 1
        assert results[0].date == test_date

    def test_context_manager_integration(self, tmpdir):
        """test Store can be used as context manager"""
        ws = workspace.Workspace(tmpdir, "test", create=True)

        # mock both stores' context manager methods
        with patch.object(Store, '__init__', return_value=None):
            store = Store.__new__(Store)
            store.workspace = ws
            store.grype_db_store = Mock()
            store.vunnel_store = Mock()

            store.grype_db_store.__enter__ = Mock(return_value=store.grype_db_store)
            store.grype_db_store.__exit__ = Mock(return_value=None)
            store.vunnel_store.__enter__ = Mock(return_value=store.vunnel_store)
            store.vunnel_store.__exit__ = Mock(return_value=None)

            # test context manager usage
            with store as ctx_store:
                assert ctx_store is store
                # verify __enter__ was called on both stores
                store.grype_db_store.__enter__.assert_called_once()
                store.vunnel_store.__enter__.assert_called_once()

            # verify __exit__ was called on both stores after exiting
            store.grype_db_store.__exit__.assert_called_once()
            store.vunnel_store.__exit__.assert_called_once()
