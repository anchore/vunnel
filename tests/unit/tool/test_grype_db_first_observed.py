from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import zstandard

from vunnel import workspace
from vunnel.tool.fixdate.finder import Result
from vunnel.tool.fixdate.grype_db_first_observed import Store


class DatabaseFixture:
    """Centralized test database fixture for creating consistent test databases"""

    def __init__(self, db_path: Path, *, include_runs: bool = False):
        self.create_tables(db_path, include_runs=include_runs)

    @staticmethod
    def create_tables(db_path: Path, *, include_runs: bool = False) -> None:
        """Create all database tables with standard schema

        Args:
            db_path: Path to the database file
            include_runs: Whether to include runs table
        """
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(db_path) as conn:
            # Create databases table
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

            # Insert default database record
            conn.execute("""
                INSERT INTO databases (id, url, schema_version, build_date, filename, status, vulnerability_count, created_at, updated_at)
                VALUES (1, 'test://db', 1, '2023-01-01', 'test.db', 'completed', 4, '2023-01-01T00:00:00', '2023-01-01T00:00:00')
            """)

            # Create fixdates table
            conn.execute("""
                CREATE TABLE fixdates (
                    vuln_id TEXT COLLATE NOCASE,
                    provider TEXT COLLATE NOCASE,
                    package_name TEXT COLLATE NOCASE,
                    full_cpe TEXT COLLATE NOCASE,
                    ecosystem TEXT COLLATE NOCASE,
                    fix_version TEXT COLLATE NOCASE,
                    first_observed_date TEXT COLLATE NOCASE,
                    resolution TEXT COLLATE NOCASE,
                    source TEXT COLLATE NOCASE,
                    run_id INTEGER,
                    database_id INTEGER,
                    updated_at TEXT
                )
            """)

            # Create runs table if requested
            if include_runs:
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

    @staticmethod
    def insert_standard_data(db_path: Path) -> None:
        """Insert standard test data for basic functionality tests"""
        with sqlite3.connect(db_path) as conn:
            test_data = [
                # CPE-based record
                (
                    "CVE-2023-0001", "test-db", "",
                    "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                    "2.4.42", "2023-01-15", "fixed", "grype-db", None, 1, "2023-01-15T00:00:00",
                ),
                # package name-based records
                (
                    "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                    "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00",
                ),
                (
                    "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                    None, "2023-02-18", "wont-fix", "grype-db", None, 1, "2023-02-18T00:00:00",
                ),
                # additional test record
                (
                    "CVE-2023-0003", "rhel", "openssl", "", "rhel:8",
                    "1.1.1k-7.el8_6", "2023-03-10", "fixed", "grype-db", None, 1, "2023-03-10T00:00:00",
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                test_data,
            )

    @staticmethod
    def insert_runs_data(db_path: Path) -> None:
        """Insert test data for runs table and related fixdates"""
        with sqlite3.connect(db_path) as conn:
            # Insert runs data
            runs_data = [
                (1, "test", "fixed", "nvd", "2023-01-01T00:00:00", "2023-01-01T23:59:59", 1, 1, 0, "2023-01-10T12:00:00"),
                (2, "test", "fixed", "debian", "2023-02-01T00:00:00", "2023-02-01T23:59:59", 1, 1, 0, "2023-02-20T12:00:00"),
                (3, "test", "fixed", "rhel", "2023-03-01T00:00:00", "2023-03-01T23:59:59", 1, 1, 0, "2023-03-10T12:00:00"),
            ]
            conn.executemany(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                runs_data,
            )

            # Insert fixdate data with run_id for testing changed vuln IDs
            fixdate_data = [
                # run_id=1 (2023-01-10) - should not be included when filtering since 2023-02-15
                (
                    "CVE-2023-0001", "nvd", "",
                    "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                    "2.4.42", "2023-01-15T10:30:00", "fixed", "grype-db", 1, 1, "2023-01-15T10:30:00",
                ),
                # run_id=2 (2023-02-20) - should be included
                (
                    "CVE-2023-0002", "debian", "curl", "", "debian:11",
                    "7.68.0-1ubuntu2.15", "2023-02-20T14:45:00", "fixed", "grype-db", 2, 1, "2023-02-20T14:45:00",
                ),
                (
                    "CVE-2023-0002", "debian", "curl", "", "debian:11",
                    None, "2023-02-18T09:15:00", "wont-fix", "grype-db", 2, 1, "2023-02-18T09:15:00",
                ),
                # run_id=3 (2023-03-10) - should be included
                (
                    "CVE-2023-0003", "rhel", "openssl", "", "rhel:8",
                    "1.1.1k-7.el8_6", "2023-03-10T16:00:00", "fixed", "grype-db", 3, 1, "2023-03-10T16:00:00",
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                fixdate_data,
            )

    @staticmethod
    def insert_custom_data(db_path: Path, data: list[tuple], vulnerability_count: int | None = None) -> None:
        """Insert custom fixdate data

        Args:
            db_path: Path to the database file
            data: Custom fixdate data to insert
            vulnerability_count: Override vulnerability count in databases table
        """
        with sqlite3.connect(db_path) as conn:
            if vulnerability_count is not None:
                conn.execute(
                    "UPDATE databases SET vulnerability_count = ? WHERE id = 1",
                    (vulnerability_count,),
                )

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                data,
            )


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
        assert store.db_path == Path(ws.input_path) / "grype-db-observed-fix-dates.db"
        assert store.logger.name == f"grype-db-fixes-{name}"

    def test_setup(self, tmpdir):
        # create a workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # ensure db directory exists
        store.db_path.parent.mkdir(parents=True, exist_ok=True)

        # create the fixdates table that the Store expects
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)

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
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_success(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

        # mock the ORAS client for pull
        mock_client = Mock()
        mock_oras_client_class.return_value = mock_client

        # create the expected zstd-compressed download file
        download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
        download_zst_path.parent.mkdir(parents=True, exist_ok=True)
        # compress "dummy db content" with zstd
        cctx = zstandard.ZstdCompressor()
        download_zst_path.write_bytes(cctx.compress(b"dummy db content"))

        # run download
        store.download()

        # verify ORAS client was called correctly
        mock_oras_client_class.assert_called_once()
        mock_client.pull.assert_called_once()
        # verify pull was called with one of the expected tags (fallback may occur)
        call_kwargs = mock_client.pull.call_args[1]
        assert call_kwargs["target"] in [
            "ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest-zstd",
            "ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest",
        ]
        assert call_kwargs["outdir"] == str(download_zst_path.parent)

        # verify directory was created
        assert store.db_path.parent.exists()
        # verify the file was moved to the correct location
        assert store.db_path.exists()
        # verify the decompressed content is correct
        assert store.db_path.read_bytes() == b"dummy db content"
        # verify the zstd file was removed
        assert not download_zst_path.exists()

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_failure(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

        # mock the ORAS client to raise an exception
        mock_client = Mock()
        mock_client.pull.side_effect = Exception("Download failed")
        mock_oras_client_class.return_value = mock_client

        # verify download raises the exception
        with pytest.raises(Exception, match="Download failed"):
            store.download()

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_not_found(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

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

        # remove the db path parent to test directory creation
        import shutil
        if store.db_path.parent.exists():
            shutil.rmtree(store.db_path.parent)

        # ensure directory doesn't exist initially
        assert not store.db_path.parent.exists()

        with (
            patch("oras.client.OrasClient") as mock_oras_client_constructor,
            patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient") as mock_oras_client_class,
        ):
            # mock oras client for _get_remote_digest
            mock_digest_client = Mock()
            mock_oras_client_constructor.return_value = mock_digest_client
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
            mock_digest_client.do_request.return_value = mock_response

            mock_client = Mock()
            mock_oras_client_class.return_value = mock_client

            # create the expected zstd-compressed download file after pull is called
            def side_effect(*args, **kwargs):
                download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
                download_zst_path.parent.mkdir(parents=True, exist_ok=True)
                cctx = zstandard.ZstdCompressor()
                download_zst_path.write_bytes(cctx.compress(b"dummy db content"))

            mock_client.pull.side_effect = side_effect

            store.download()

            # verify directory was created
            assert store.db_path.parent.exists()

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_get_after_not_found_download(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

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
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_find_after_not_found_download(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

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
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_get_changed_vuln_ids_since_after_not_found(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

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

    @patch("oras.client.OrasClient")
    @patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"})
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_with_github_token(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest (returns a digest so download proceeds)
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

        # mock the ORAS client for pull
        mock_client = Mock()
        mock_oras_client_class.return_value = mock_client

        # create the expected zstd-compressed download file
        download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
        download_zst_path.parent.mkdir(parents=True, exist_ok=True)
        cctx = zstandard.ZstdCompressor()
        download_zst_path.write_bytes(cctx.compress(b"dummy db content"))

        # run download
        store.download()

        # verify login was called with GitHub token on the digest client
        mock_digest_client.login.assert_called_with(
            hostname="ghcr.io",
            username="token",
            password="test-token",
        )

        # verify login was called with GitHub token on the pull client
        mock_client.login.assert_called_once_with(
            hostname="ghcr.io",
            username="token",
            password="test-token",
        )

        # verify pull was called (tag may vary due to fallback logic)
        mock_client.pull.assert_called_once()
        call_kwargs = mock_client.pull.call_args[1]
        assert call_kwargs["target"] in [
            "ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest-zstd",
            "ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest",
        ]
        assert call_kwargs["outdir"] == str(download_zst_path.parent)

    def test_get_by_cpe(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)
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
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)
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
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)
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
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)
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
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)
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
        db = DatabaseFixture(store.db_path, include_runs=True)
        db.insert_runs_data(store.db_path)
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
        db = DatabaseFixture(store.db_path, include_runs=True)
        db.insert_runs_data(store.db_path)
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
        case_variation_data = [
            ("CVE-2023-0002", "test-db", "curl", "", "debian:11",
             "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00"),
        ]
        db = DatabaseFixture(store.db_path)
        db.insert_custom_data(store.db_path, case_variation_data, vulnerability_count=1)
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
        python_package_data = [
            ("CVE-2023-9001", "test-db", "my-package", "", "python",
             "1.0.0", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00"),
            ("CVE-2023-9001", "test-db", "my-package", "", "pypi",
             "1.0.0", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00"),
            ("CVE-2023-9001", "test-db", "my-package-test", "", "python",
             "2.0.0", "2023-02-21", "fixed", "grype-db", None, 1, "2023-02-21T00:00:00"),
        ]
        db = DatabaseFixture(store.db_path)
        db.insert_custom_data(store.db_path, python_package_data, vulnerability_count=3)
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
        db = DatabaseFixture(store.db_path)
        db.insert_standard_data(store.db_path)
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

    def test_vuln_id_case_insensitive_matching(self, tmpdir, helpers):
        """test that vuln_id matching is case insensitive"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with mixed case vulnerability IDs
        case_variation_data = [
            ("CVE-2023-0002", "test-db", "curl", "", "debian:11",
             "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00"),
        ]
        db = DatabaseFixture(store.db_path)
        db.insert_custom_data(store.db_path, case_variation_data, vulnerability_count=1)
        store._downloaded = True

        # test case insensitive matching for vuln_id
        test_cases = [
            ("cve-2023-0002", 1),  # lowercase input
            ("CVE-2023-0002", 1),  # uppercase input
            ("Cve-2023-0002", 1),  # mixed case input
            ("CvE-2023-0002", 1),  # random case input
        ]

        for vuln_id, expected_count in test_cases:
            results = store.find(
                vuln_id=vuln_id,
                cpe_or_package="curl",
                fix_version=None,
                ecosystem="debian:11",
            )
            assert len(results) == expected_count, f"Case insensitive vuln_id test failed for '{vuln_id}': got {len(results)}, expected {expected_count}"

    def test_provider_case_insensitive_matching(self, tmpdir, helpers):
        """test that provider matching is case insensitive"""
        ws = workspace.Workspace(tmpdir, "Test-DB", create=True)  # mixed case provider
        store = Store(ws)

        # create test database
        mixed_case_provider_data = [
            ("CVE-2023-0002", "Test-DB", "curl", "", "debian:11",
             "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00"),
        ]
        db = DatabaseFixture(store.db_path)
        db.insert_custom_data(store.db_path, mixed_case_provider_data, vulnerability_count=1)
        store._downloaded = True

        # test that queries work regardless of how provider was stored
        results = store.find(
            vuln_id="CVE-2023-0002",
            cpe_or_package="curl",
            fix_version=None,
            ecosystem="debian:11",
        )
        assert len(results) == 1, f"Provider case insensitive test failed: got {len(results)}, expected 1"

    def test_ecosystem_case_insensitive_matching(self, tmpdir, helpers):
        """test that ecosystem matching is case insensitive"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with mixed case ecosystems
        case_variation_data = [
            ("CVE-2023-0002", "test-db", "curl", "", "debian:11",
             "7.68.0-1ubuntu2.15", "2023-02-20", "fixed", "grype-db", None, 1, "2023-02-20T00:00:00"),
        ]
        db = DatabaseFixture(store.db_path)
        db.insert_custom_data(store.db_path, case_variation_data, vulnerability_count=1)
        store._downloaded = True

        # test case insensitive matching for ecosystem
        test_cases = [
            ("debian:11", 1),     # lowercase input
            ("DEBIAN:11", 1),     # uppercase input
            ("Debian:11", 1),     # mixed case input
            ("DeBiAn:11", 1),     # random case input
        ]

        for ecosystem, expected_count in test_cases:
            results = store.find(
                vuln_id="CVE-2023-0002",
                cpe_or_package="curl",
                fix_version=None,
                ecosystem=ecosystem,
            )
            assert len(results) == expected_count, f"Case insensitive ecosystem test failed for '{ecosystem}': got {len(results)}, expected {expected_count}"

    def test_full_cpe_case_insensitive_matching(self, tmpdir, helpers):
        """test that full_cpe matching is case insensitive"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with mixed case CPEs
        mixed_case_cpe_data = [
            ("CVE-2023-0001", "test-db", "",
             "CPE:2.3:A:Apache:HttpD:2.4.41:*:*:*:*:*:*:*", "",  # Mixed case CPE in storage
             "2.4.42", "2023-01-15", "fixed", "grype-db", None, 1, "2023-01-15T00:00:00"),
        ]
        db = DatabaseFixture(store.db_path)
        db.insert_custom_data(store.db_path, mixed_case_cpe_data, vulnerability_count=1)
        store._downloaded = True

        # test case insensitive matching for full_cpe
        test_cases = [
            ("cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", 1),       # lowercase input
            ("CPE:2.3:A:APACHE:HTTPD:2.4.41:*:*:*:*:*:*:*", 1),       # uppercase input
            ("Cpe:2.3:A:Apache:Httpd:2.4.41:*:*:*:*:*:*:*", 1),       # mixed case input
            ("CPe:2.3:a:Apache:HTTPD:2.4.41:*:*:*:*:*:*:*", 1),       # random case input
        ]

        for cpe, expected_count in test_cases:
            results = store.find(
                vuln_id="CVE-2023-0001",
                cpe_or_package=cpe,
                fix_version="2.4.42",
            )
            assert len(results) == expected_count, f"Case insensitive full_cpe test failed for '{cpe}': got {len(results)}, expected {expected_count}"

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_with_digest_caching_skips_when_unchanged(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        """test that download is skipped when digest matches"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # setup existing database and digest file
        store.db_path.parent.mkdir(parents=True, exist_ok=True)
        store.db_path.write_text("existing db")
        test_digest = "sha256:abc123def456"
        store.digest_path.write_text(test_digest)

        # mock oras client for _get_remote_digest (returns same digest)
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": test_digest}
        mock_digest_client.do_request.return_value = mock_response

        # mock oras client for pull (should not be called)
        mock_pull_client = Mock()
        mock_oras_client_class.return_value = mock_pull_client

        # run download
        store.download()

        # verify do_request was called for digest resolution
        mock_digest_client.do_request.assert_called_once()

        # verify oras pull was NOT called (download skipped)
        mock_pull_client.pull.assert_not_called()

        # verify database file unchanged
        assert store.db_path.read_text() == "existing db"

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_with_digest_caching_downloads_when_changed(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        """test that download proceeds when digest changes"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # setup existing database and digest file
        store.db_path.parent.mkdir(parents=True, exist_ok=True)
        store.db_path.write_text("old db")
        old_digest = "sha256:old123"
        store.digest_path.write_text(old_digest)

        # mock oras client for _get_remote_digest (returns new digest)
        new_digest = "sha256:new456"
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": new_digest}
        mock_digest_client.do_request.return_value = mock_response

        # mock oras client for pull
        mock_pull_client = Mock()
        mock_oras_client_class.return_value = mock_pull_client

        # create the expected zstd-compressed download file
        download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
        download_zst_path.parent.mkdir(parents=True, exist_ok=True)
        cctx = zstandard.ZstdCompressor()
        download_zst_path.write_bytes(cctx.compress(b"new db content"))

        # run download
        store.download()

        # verify do_request was called for digest resolution
        mock_digest_client.do_request.assert_called_once()

        # verify oras pull WAS called (download happened)
        mock_pull_client.pull.assert_called_once()

        # verify new digest was saved
        assert store.digest_path.read_text().strip() == new_digest
        assert store.db_path.read_bytes() == b"new db content"

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_with_digest_resolution_failure_proceeds_normally(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        """test that download works when digest resolution fails"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest (returns 404)
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.headers = {}
        mock_digest_client.do_request.return_value = mock_response

        # mock oras client for pull
        mock_pull_client = Mock()
        mock_oras_client_class.return_value = mock_pull_client

        # create the expected zstd-compressed download file
        download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
        download_zst_path.parent.mkdir(parents=True, exist_ok=True)
        cctx = zstandard.ZstdCompressor()
        download_zst_path.write_bytes(cctx.compress(b"db content"))

        # run download
        store.download()

        # verify oras pull WAS called (download proceeded without digest check)
        mock_pull_client.pull.assert_called_once()

        # verify database file exists
        assert store.db_path.read_bytes() == b"db content"

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_with_missing_digest_file_downloads(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        """test that download proceeds when digest file is missing"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # setup existing database but NO digest file
        store.db_path.parent.mkdir(parents=True, exist_ok=True)
        store.db_path.write_text("existing db")

        # mock oras client for _get_remote_digest
        test_digest = "sha256:abc123"
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": test_digest}
        mock_digest_client.do_request.return_value = mock_response

        # mock oras client for pull
        mock_pull_client = Mock()
        mock_oras_client_class.return_value = mock_pull_client

        # create the expected zstd-compressed download file
        download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
        download_zst_path.parent.mkdir(parents=True, exist_ok=True)
        cctx = zstandard.ZstdCompressor()
        download_zst_path.write_bytes(cctx.compress(b"new db content"))

        # run download
        store.download()

        # verify oras pull WAS called (no digest file means download)
        mock_pull_client.pull.assert_called_once()

        # verify digest file was created
        assert store.digest_path.read_text().strip() == test_digest

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_with_oras_resolve_exception_downloads(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        """test that download proceeds when oras resolve raises exception"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest to raise exception
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_digest_client.do_request.side_effect = Exception("connection error")

        # mock oras client for pull
        mock_pull_client = Mock()
        mock_oras_client_class.return_value = mock_pull_client

        # create the expected zstd-compressed download file
        download_zst_path = Path(ws.input_path) / "fix-dates" / "test-db.db.zst"
        download_zst_path.parent.mkdir(parents=True, exist_ok=True)
        cctx = zstandard.ZstdCompressor()
        download_zst_path.write_bytes(cctx.compress(b"db content"))

        # run download
        store.download()

        # verify oras pull WAS called (resolve failure means download)
        mock_pull_client.pull.assert_called_once()

        # verify database file exists
        assert store.db_path.exists()

    @patch("oras.client.OrasClient")
    @patch("vunnel.tool.fixdate.grype_db_first_observed._ProgressLoggingOrasClient")
    def test_download_uncompressed_db_file(self, mock_oras_client_class, mock_oras_client_constructor, tmpdir):
        """test that download handles uncompressed .db file (no .zst)"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Docker-Content-Digest": "sha256:test123"}
        mock_digest_client.do_request.return_value = mock_response

        # mock the ORAS client for pull
        mock_client = Mock()
        mock_oras_client_class.return_value = mock_client

        # create uncompressed db file (no .zst)
        download_dir = Path(ws.input_path) / "fix-dates"
        download_dir.mkdir(parents=True, exist_ok=True)
        (download_dir / "test-db.db").write_text("uncompressed db content")

        # run download
        store.download()

        # verify ORAS client was called
        mock_oras_client_class.assert_called_once()
        mock_client.pull.assert_called_once()

        # verify database file exists with correct content
        assert store.db_path.exists()
        assert store.db_path.read_text() == "uncompressed db content"

    @patch("oras.client.OrasClient")
    def test_resolve_image_ref_fallback(self, mock_oras_client_constructor, tmpdir):
        """test that _resolve_image_ref falls back from latest-zstd to latest"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # mock oras client for _get_remote_digest
        mock_digest_client = Mock()
        mock_oras_client_constructor.return_value = mock_digest_client

        # first call (latest-zstd) fails with non-200, second call (latest) succeeds
        mock_response_fail = Mock()
        mock_response_fail.status_code = 404
        mock_response_fail.headers = {}

        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.headers = {"Docker-Content-Digest": "sha256:latest123"}

        mock_digest_client.do_request.side_effect = [
            mock_response_fail,
            mock_response_success,
        ]

        # run _resolve_image_ref
        image_ref, digest = store._resolve_image_ref("ghcr.io/anchore/grype-db-observed-fix-date/test-db")

        # verify it returned the latest tag
        assert image_ref == "ghcr.io/anchore/grype-db-observed-fix-date/test-db:latest"
        assert digest == "sha256:latest123"

        # verify both tags were tried
        assert mock_digest_client.do_request.call_count == 2
