from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from vunnel import workspace
from vunnel.tool.fixdate.first_observed import Store, normalize_package_name
from vunnel.tool.fixdate.finder import Result


class TestStore:

    def test_store_initialization(self, tmpdir):
        # create a workspace
        name = "test-db"
        ws = workspace.Workspace(tmpdir, name, create=True)

        # create store instance
        store = Store(ws)

        # verify initialization
        assert store.workspace == ws
        assert store.provider == name
        assert store.db_path == Path(ws.input_path) / "fix-dates" / f"{name}.db"
        assert store.logger.name == f"fixes-{name}"

    def test_setup(self, tmpdir):
        # create a workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # ensure db directory exists
        store.db_path.parent.mkdir(parents=True, exist_ok=True)

        # create the fixdates table that the Store expects
        self._create_test_database(store.db_path)

        # mark as downloaded to avoid runtime error
        store._downloaded = True

        # verify can query the database
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )
        assert len(results) == 1

    @patch("oras.client.OrasClient")
    def test_download_success(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client
        mock_client = Mock()
        mock_oras_client_class.return_value = mock_client

        # run download
        store.download()

        # verify ORAS client was called correctly
        mock_oras_client_class.assert_called_once()
        mock_client.pull.assert_called_once_with(
            target="ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest",
            outdir=str(store.db_path.parent),
        )

        # verify directory was created
        assert store.db_path.parent.exists()

    @patch("oras.client.OrasClient")
    def test_download_failure(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client to raise an exception
        mock_client = Mock()
        mock_client.pull.side_effect = Exception("Download failed")
        mock_oras_client_class.return_value = mock_client

        # verify download raises the exception
        with pytest.raises(Exception, match="Download failed"):
            store.download()

    @patch("oras.client.OrasClient")
    def test_download_not_found(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client to raise a "not found" ValueError
        mock_client = Mock()
        mock_client.pull.side_effect = ValueError("repository not found")
        mock_oras_client_class.return_value = mock_client

        # verify download doesn't raise exception but sets _not_found flag
        store.download()

        assert store._not_found is True
        assert store._downloaded is True

    def test_download_creates_directories(self, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # ensure directory doesn't exist initially
        assert not store.db_path.parent.exists()

        with patch("oras.client.OrasClient") as mock_oras_client_class:
            mock_client = Mock()
            mock_oras_client_class.return_value = mock_client

            store.download()

            # verify directory was created
            assert store.db_path.parent.exists()

    @patch("oras.client.OrasClient")
    def test_get_after_not_found_download(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client to raise a "not found" ValueError
        mock_client = Mock()
        mock_client.pull.side_effect = ValueError("repository not found")
        mock_oras_client_class.return_value = mock_client

        # download to trigger not found behavior
        store.download()

        # verify get returns empty list (no error)
        results = store.get(
            vuln_id="CVE-2023-0001",
            cpe_or_package="test",
            fix_version="1.0.0",
        )
        assert results == []

    @patch("oras.client.OrasClient")
    def test_find_after_not_found_download(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client to raise a "not found" ValueError
        mock_client = Mock()
        mock_client.pull.side_effect = ValueError("repository not found")
        mock_oras_client_class.return_value = mock_client

        # download to trigger not found behavior
        store.download()

        # verify find returns empty list (no error)
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="test",
            fix_version="1.0.0",
        )
        assert results == []

    @patch("oras.client.OrasClient")
    def test_get_changed_vuln_ids_since_after_not_found(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client to raise a "not found" ValueError
        mock_client = Mock()
        mock_client.pull.side_effect = ValueError("repository not found")
        mock_oras_client_class.return_value = mock_client

        # download to trigger not found behavior
        store.download()

        # verify get_changed_vuln_ids_since returns empty set (no error)
        from datetime import datetime
        result_ids = store.get_changed_vuln_ids_since(datetime(2023, 1, 1))
        assert result_ids == set()

    def test_get_without_download_raises_error(self, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # verify calling get without download raises RuntimeError
        with pytest.raises(RuntimeError, match="fix date database has not been downloaded"):
            store.get(
                vuln_id="CVE-2023-0001",
                cpe_or_package="test",
                fix_version="1.0.0",
            )

    @patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token'})
    @patch("oras.client.OrasClient")
    def test_download_with_github_token(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock the ORAS client
        mock_client = Mock()
        mock_oras_client_class.return_value = mock_client

        # run download
        store.download()

        # verify login was called with GitHub token
        mock_client.login.assert_called_once_with(
            hostname="ghcr.io",
            username="token",
            password="test-token",
        )

        # verify pull was still called
        mock_client.pull.assert_called_once_with(
            target="ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest",
            outdir=str(store.db_path.parent),
        )

    def test_get_by_cpe(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        self._create_test_database(store.db_path)
        store._downloaded = True

        # test CPE-based query
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]
        assert isinstance(result, Result)
        assert result.kind == "first-observed"
        from datetime import date
        assert result.date == date(2023, 1, 15)

    def test_get_by_package_name(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        self._create_test_database(store.db_path)
        store._downloaded = True

        # test package name-based query
        results = store.find(
            vuln_id="CVE-2023-0002",
            cpe_or_package="curl",
            fix_version="7.68.0-1ubuntu2.15",
            ecosystem="debian:11",
        )

        assert len(results) == 1
        result = results[0]
        assert isinstance(result, Result)
        assert result.kind == "first-observed"
        from datetime import date
        assert result.date == date(2023, 2, 20)

    def test_get_with_ecosystem(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        self._create_test_database(store.db_path)
        store._downloaded = True

        # test query with ecosystem filter
        results = store.find(
            vuln_id="CVE-2023-0002",
            cpe_or_package="curl",
            fix_version=None,
            ecosystem="debian:11",
        )

        assert len(results) == 2  # should return both with and without fix_version
        # verify all results are Result objects with correct kind
        for result in results:
            assert isinstance(result, Result)
            assert result.kind == "first-observed"

    def test_find_returns_result_objects(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        self._create_test_database(store.db_path)
        store._downloaded = True

        # get results
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]

        # verify it's a Result object with correct types
        assert isinstance(result, Result)
        assert result.kind == "first-observed"
        from datetime import date
        assert result.date == date(2023, 1, 15)

    def test_find_empty_results(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        self._create_test_database(store.db_path)
        store._downloaded = True

        # test query that should return no results
        results = store.find(
            vuln_id="CVE-9999-9999",
            cpe_or_package="nonexistent",
            fix_version=None,
        )

        assert len(results) == 0

    def test_get_changed_vuln_ids_since(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with runs table
        self._create_test_database_with_runs(store.db_path)
        store._downloaded = True

        # test getting changed vuln IDs since a specific date
        since_date = datetime(2023, 2, 15)  # should return CVE-2023-0002 and CVE-2023-0003
        result_ids = store.get_changed_vuln_ids_since(since_date)

        assert isinstance(result_ids, set)
        assert len(result_ids) == 2
        assert "CVE-2023-0002" in result_ids
        assert "CVE-2023-0003" in result_ids
        assert "CVE-2023-0001" not in result_ids  # this was from run_id=1 (2023-01-10)

    def test_get_changed_vuln_ids_since_no_results(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with runs table
        self._create_test_database_with_runs(store.db_path)
        store._downloaded = True

        # test getting changed vuln IDs since a future date
        since_date = datetime(2024, 1, 1)  # should return no results
        result_ids = store.get_changed_vuln_ids_since(since_date)

        assert isinstance(result_ids, set)
        assert len(result_ids) == 0

    def test_package_name_case_insensitive_matching(self, tmpdir, helpers):
        """test that package name matching is case insensitive"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with mixed case package names
        self._create_test_database_with_case_variations(store.db_path)
        store._downloaded = True

        # test case insensitive matching
        test_cases = [
            ("curl", "debian:11", 1),  # lowercase input
            ("CURL", "debian:11", 1),  # uppercase input
            ("Curl", "debian:11", 1),  # mixed case input
            ("CuRl", "debian:11", 1),  # random case input
        ]

        for package_name, ecosystem, expected_count in test_cases:
            results = store.find(
                vuln_id="CVE-2023-0002",
                cpe_or_package=package_name,
                fix_version=None,
                ecosystem=ecosystem,
            )
            assert len(results) == expected_count, f"Case insensitive test failed for '{package_name}': got {len(results)}, expected {expected_count}"

    def test_python_package_normalization_matching(self, tmpdir, helpers):
        """test that Python package name normalization works end-to-end"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with python packages stored with underscores
        self._create_test_database_with_python_packages(store.db_path)
        store._downloaded = True

        # test that we can find packages using different separator formats
        test_cases = [
            ("my_package", "python", 1),     # exact match
            ("my-package", "python", 1),     # normalized input should match stored underscore version
            ("My_Package", "python", 1),     # case insensitive + normalization
            ("MY.PACKAGE", "python", 1),     # case + dot normalization
            ("my.package", "pypi", 1),       # pypi ecosystem
            ("MY_package.TEST", "python", 1), # complex case + mixed separators
        ]

        for package_name, ecosystem, expected_count in test_cases:
            results = store.find(
                vuln_id="CVE-2023-9001",
                cpe_or_package=package_name,
                fix_version=None,
                ecosystem=ecosystem,
            )
            assert len(results) == expected_count, f"Python normalization test failed for '{package_name}' in {ecosystem}: got {len(results)}, expected {expected_count}"

    def test_cpe_queries_unaffected_by_normalization(self, tmpdir, helpers):
        """test that CPE-based queries are not affected by package name normalization"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        self._create_test_database(store.db_path)
        store._downloaded = True

        # test CPE query (should work exactly as before)
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]
        assert result.kind == "first-observed"
        from datetime import date
        assert result.date == date(2023, 1, 15)

    def _create_test_database_with_case_variations(self, db_path: Path):
        """helper method to create test database with case variation test data"""
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(db_path) as conn:
            # create databases table
            conn.execute("""
                CREATE TABLE databases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    schema_version INTEGER NOT NULL,
                    build_date TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    vulnerability_count INTEGER,
                    run_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
            """)

            # insert default database record
            conn.execute("""
                INSERT INTO databases (id, url, schema_version, build_date, filename, status, vulnerability_count, created_at)
                VALUES (1, 'test://db', 1, '2023-01-01', 'test.db', 'completed', 1, '2023-01-01T00:00:00')
            """)

            # create table schema with COLLATE NOCASE
            conn.execute("""
                CREATE TABLE fixdates (
                    vuln_id TEXT,
                    provider TEXT,
                    package_name TEXT COLLATE NOCASE,
                    full_cpe TEXT,
                    ecosystem TEXT,
                    fix_version TEXT,
                    first_observed_date TEXT,
                    resolution TEXT,
                    source TEXT,
                    run_id INTEGER,
                    database_id INTEGER
                )
            """)

            # insert test data with mixed case package names
            test_data = [
                # package stored with lowercase
                (
                    "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                    "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1,
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                test_data,
            )

    def _create_test_database_with_python_packages(self, db_path: Path):
        """helper method to create test database with Python package test data"""
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(db_path) as conn:
            # create databases table
            conn.execute("""
                CREATE TABLE databases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    schema_version INTEGER NOT NULL,
                    build_date TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    vulnerability_count INTEGER,
                    run_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
            """)

            # insert default database record
            conn.execute("""
                INSERT INTO databases (id, url, schema_version, build_date, filename, status, vulnerability_count, created_at)
                VALUES (1, 'test://db', 1, '2023-01-01', 'test.db', 'completed', 3, '2023-01-01T00:00:00')
            """)

            # create table schema with COLLATE NOCASE
            conn.execute("""
                CREATE TABLE fixdates (
                    vuln_id TEXT,
                    provider TEXT,
                    package_name TEXT COLLATE NOCASE,
                    full_cpe TEXT,
                    ecosystem TEXT,
                    fix_version TEXT,
                    first_observed_date TEXT,
                    resolution TEXT,
                    source TEXT,
                    run_id INTEGER,
                    database_id INTEGER
                )
            """)

            # insert test data with python packages stored in normalized form
            test_data = [
                # python package stored with normalized form (hyphens)
                (
                    "CVE-2023-9001", "test-db", "my-package", "", "python",
                    "1.0.0", "2023-02-20", "fixed", "grype-db", None, 1,
                ),
                (
                    "CVE-2023-9001", "test-db", "my-package", "", "pypi",
                    "1.0.0", "2023-02-20", "fixed", "grype-db", None, 1,
                ),
                # another test package with mixed separators in storage (normalized)
                (
                    "CVE-2023-9001", "test-db", "my-package-test", "", "python",
                    "2.0.0", "2023-02-21", "fixed", "grype-db", None, 1,
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                test_data,
            )

    def _create_test_database(self, db_path: Path):
        """helper method to create test database with sample data"""
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(db_path) as conn:
            # create databases table
            conn.execute("""
                CREATE TABLE databases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    schema_version INTEGER NOT NULL,
                    build_date TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    vulnerability_count INTEGER,
                    run_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
            """)

            # insert default database record
            conn.execute("""
                INSERT INTO databases (id, url, schema_version, build_date, filename, status, vulnerability_count, created_at)
                VALUES (1, 'test://db', 1, '2023-01-01', 'test.db', 'completed', 4, '2023-01-01T00:00:00')
            """)

            # create table schema
            conn.execute("""
                CREATE TABLE fixdates (
                    vuln_id TEXT,
                    provider TEXT,
                    package_name TEXT COLLATE NOCASE,
                    full_cpe TEXT,
                    ecosystem TEXT,
                    fix_version TEXT,
                    first_observed_date TEXT,
                    resolution TEXT,
                    source TEXT,
                    run_id INTEGER,
                    database_id INTEGER
                )
            """)

            # insert test data
            test_data = [
                # CPE-based record
                (
                    "CVE-2023-0001", "test-db", "",
                    "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                    "2.4.42", "2023-01-15", "fixed", "grype-db", None, 1,
                ),
                # package name-based records
                (
                    "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                    "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1,
                ),
                (
                    "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                    None, "2023-02-18", "wont-fix", "grype-db", None, 1,
                ),
                # additional test record
                (
                    "CVE-2023-0003", "rhel", "openssl", "", "rhel:8",
                    "1.1.1k-7.el8_6", "2023-03-10", "fixed", "grype-db", None, 1,
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                test_data,
            )

    def _create_test_database_with_runs(self, db_path: Path):
        """helper method to create test database with runs table and run_id column"""
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(db_path) as conn:
            # create databases table
            conn.execute("""
                CREATE TABLE databases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    schema_version INTEGER NOT NULL,
                    build_date TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    vulnerability_count INTEGER,
                    run_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
            """)

            # insert default database record
            conn.execute("""
                INSERT INTO databases (id, url, schema_version, build_date, filename, status, vulnerability_count, created_at)
                VALUES (1, 'test://db', 1, '2023-01-01', 'test.db', 'completed', 4, '2023-01-01T00:00:00')
            """)

            # create runs table
            conn.execute("""
                CREATE TABLE runs (
                    id INTEGER PRIMARY KEY,
                    source TEXT NOT NULL,
                    resolution TEXT NOT NULL,
                    provider TEXT,
                    first_date TEXT NOT NULL,
                    last_date TEXT NOT NULL,
                    total_dbs_planned INTEGER NOT NULL,
                    total_dbs_completed INTEGER NOT NULL,
                    total_dbs_failed INTEGER NOT NULL,
                    run_timestamp TEXT NOT NULL
                )
            """)

            # create fixdates table with run_id column
            conn.execute("""
                CREATE TABLE fixdates (
                    vuln_id TEXT,
                    provider TEXT,
                    package_name TEXT COLLATE NOCASE,
                    full_cpe TEXT,
                    ecosystem TEXT,
                    fix_version TEXT,
                    first_observed_date TEXT,
                    resolution TEXT,
                    source TEXT,
                    run_id INTEGER,
                    database_id INTEGER
                )
            """)

            # insert test runs
            runs_data = [
                (1, "test", "fixed", "nvd", "2023-01-01T00:00:00", "2023-01-01T23:59:59", 1, 1, 0, "2023-01-10T12:00:00"),
                (2, "test", "fixed", "debian", "2023-02-01T00:00:00", "2023-02-01T23:59:59", 1, 1, 0, "2023-02-20T12:00:00"),
                (3, "test", "fixed", "rhel", "2023-03-01T00:00:00", "2023-03-01T23:59:59", 1, 1, 0, "2023-03-10T12:00:00"),
            ]
            conn.executemany(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                runs_data,
            )

            # insert test fixdate data with run_id
            test_data = [
                # run_id=1 (2023-01-10) - should not be included when filtering since 2023-02-15
                (
                    "CVE-2023-0001", "nvd", "",
                    "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                    "2.4.42", "2023-01-15T10:30:00", "fixed", "grype-db", 1, 1,
                ),
                # run_id=2 (2023-02-20) - should be included
                (
                    "CVE-2023-0002", "debian", "curl", "", "debian:11",
                    "7.68.0-1ubuntu2.15", "2023-02-20T14:45:00", "fixed", "grype-db", 2, 1,
                ),
                (
                    "CVE-2023-0002", "debian", "curl", "", "debian:11",
                    None, "2023-02-18T09:15:00", "wont-fix", "grype-db", 2, 1,
                ),
                # run_id=3 (2023-03-10) - should be included
                (
                    "CVE-2023-0003", "rhel", "openssl", "", "rhel:8",
                    "1.1.1k-7.el8_6", "2023-03-10T16:00:00", "fixed", "grype-db", 3, 1,
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                test_data,
            )


class TestNormalizePackageName:
    """tests for package name normalization functionality"""

    def test_basic_normalization(self):
        """test basic normalization for all ecosystems"""
        tests = [
            {
                "name": "no case conversion",
                "input": "CURL",
                "ecosystem": "debian",
                "expected": "CURL",
            },
            {
                "name": "strip spaces",
                "input": "  curl  ",
                "ecosystem": "debian",
                "expected": "curl",
            },
            {
                "name": "strip spaces preserve case",
                "input": "  CURL  ",
                "ecosystem": None,
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
                "name": "python ecosystem with case and separators preserved",
                "input": "MY_Package.Name",
                "ecosystem": "python",
                "expected": "MY-Package-Name",
            },
            {
                "name": "python ecosystem with spaces and separators",
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
                "name": "rhel with underscores and case unchanged",
                "input": "MY_Package",
                "ecosystem": "rhel:8",
                "expected": "MY_Package",
            },
            {
                "name": "alpine with dots and case unchanged",
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
                "name": "none ecosystem with separators unchanged",
                "input": "my_package.name",
                "ecosystem": None,
                "expected": "my_package.name",
            },
        ]

        for test in tests:
            result = normalize_package_name(test["input"], test["ecosystem"])
            assert result == test["expected"], f"test '{test['name']}' failed: got {result}, expected {test['expected']}"
