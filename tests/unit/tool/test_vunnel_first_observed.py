from __future__ import annotations

import sqlite3
import threading
from datetime import date
from pathlib import Path

import pytest

from vunnel import workspace
import sqlalchemy
from vunnel.tool.fixdate.vunnel_first_observed import Store, FixDate
from vunnel.tool.fixdate.finder import Result


class DatabaseFixture:
    """helper for creating test databases for VunnelFirstObserved Store"""

    def __init__(self, db_path: Path, provider: str = "test-db"):
        self.create_tables(db_path, provider)

    @staticmethod
    def create_tables(db_path: Path, provider: str = "test-db") -> None:
        """create the fixdates table using the same method as Store._create_tables()"""
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # create a temporary workspace and store to use _create_tables()
        # Calculate the workspace path such that results_path points to the db parent dir
        workspace_path = db_path.parent.parent  # Go up one more level since results_path = workspace.path + '/results'
        ws = workspace.Workspace(workspace_path, provider, create=False)
        store = Store(ws)
        store.db_path = db_path

        # use Store's _create_tables() method to ensure consistency
        store.engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
        store._create_tables()

    @staticmethod
    def insert_test_data(db_path: Path, data: list[tuple]) -> None:
        """insert custom test data"""
        with sqlite3.connect(db_path) as conn:
            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                data,
            )


class TestStore:
    """tests for the VunnelFirstObserved Store class"""

    def test_store_initialization(self, tmpdir):
        """test that the Store initializes correctly"""
        # create workspace
        name = "test-workspace"
        ws = workspace.Workspace(tmpdir, name, create=True)

        # create store instance
        store = Store(ws)

        # verify initialization
        assert store.workspace == ws
        assert store.provider == name
        assert store.db_path == Path(ws.results_path) / "observed-fix-dates.db"
        assert store.logger.name == "fixes-" + name
        assert store.engine is None
        assert hasattr(store, "_thread_local")

    def test_add_cpe_based_entry(self, tmpdir):
        """test adding a CPE-based vulnerability entry"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        db = DatabaseFixture(store.db_path)

        # test data
        first_observed_date = date(2023, 1, 15)
        vuln_id = "CVE-2023-0001"
        cpe = "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*"
        fix_version = "2.4.42"

        # add entry
        store.add(first_observed_date, vuln_id, cpe, fix_version)

        # manually commit the transaction (VunnelFirstObserved doesn't auto-commit)
        conn, table = store._get_connection()
        conn.commit()

        # verify entry was added correctly
        with sqlite3.connect(store.db_path) as conn:
            cursor = conn.execute(
                "SELECT vuln_id, provider, package_name, full_cpe, ecosystem, fix_version, first_observed_date FROM fixdates"
            )
            row = cursor.fetchone()

        assert row is not None
        assert row[0] == vuln_id  # vuln_id
        assert row[1] == "test-db"  # provider
        assert row[2] == ""  # package_name (empty for CPE)
        assert row[3] == cpe  # full_cpe
        assert row[4] == ""  # ecosystem (empty for CPE)
        assert row[5] == fix_version  # fix_version
        assert row[6] == first_observed_date.isoformat()  # first_observed_date

    def test_add_package_based_entry(self, tmpdir):
        """test adding a package-based vulnerability entry"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        db = DatabaseFixture(store.db_path)

        # test data
        first_observed_date = date(2023, 2, 20)
        vuln_id = "CVE-2023-0002"
        package_name = "curl"
        fix_version = "7.68.0-1ubuntu2.15"
        ecosystem = "debian:11"

        # add entry
        store.add(first_observed_date, vuln_id, package_name, fix_version, ecosystem)

        # manually commit the transaction (VunnelFirstObserved doesn't auto-commit)
        conn, table = store._get_connection()
        conn.commit()

        # verify entry was added correctly
        with sqlite3.connect(store.db_path) as conn:
            cursor = conn.execute(
                "SELECT vuln_id, provider, package_name, full_cpe, ecosystem, fix_version, first_observed_date FROM fixdates"
            )
            row = cursor.fetchone()

        assert row is not None
        assert row[0] == vuln_id  # vuln_id
        assert row[1] == "test-db"  # provider
        assert row[2] == package_name  # package_name
        assert row[3] == ""  # full_cpe (empty for package)
        assert row[4] == ecosystem  # ecosystem
        assert row[5] == fix_version  # fix_version
        assert row[6] == first_observed_date.isoformat()  # first_observed_date

    def test_add_python_package_normalization(self, tmpdir):
        """test that Python package names are normalized when adding"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        db = DatabaseFixture(store.db_path)

        # test data with underscores and dots
        first_observed_date = date(2023, 3, 1)
        vuln_id = "CVE-2023-0003"
        package_name = "my_package.name"  # should be normalized to "my-package-name"
        fix_version = "1.0.0"
        ecosystem = "python"

        # add entry
        store.add(first_observed_date, vuln_id, package_name, fix_version, ecosystem)

        # manually commit the transaction (VunnelFirstObserved doesn't auto-commit)
        conn, table = store._get_connection()
        conn.commit()

        # verify entry was added with normalized package name
        with sqlite3.connect(store.db_path) as conn:
            cursor = conn.execute("SELECT package_name FROM fixdates")
            row = cursor.fetchone()

        assert row is not None
        assert row[0] == "my-package-name"  # normalized package name

    def test_get_by_cpe(self, tmpdir):
        """test retrieving entries by CPE"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with data
        db = DatabaseFixture(store.db_path)
        test_data = [
            (
                "CVE-2023-0001", "test-db", "",
                "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                "2.4.42", "2023-01-15",
                "2023-01-15T10:30:00"
            ),
        ]
        db.insert_test_data(store.db_path, test_data)

        # get results
        results = store.get(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]
        assert isinstance(result, FixDate)
        assert result.vuln_id == "CVE-2023-0001"
        assert result.provider == "test-db"
        assert result.full_cpe == "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*"
        assert result.package_name == ""
        assert result.fix_version == "2.4.42"
        assert result.first_observed_date == date(2023, 1, 15)

    def test_get_by_package_name(self, tmpdir):
        """test retrieving entries by package name"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with data
        db = DatabaseFixture(store.db_path)
        test_data = [
            (
                "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                "7.68.0-1ubuntu2.15", "2023-02-20",
                "2023-02-20T14:45:00"
            ),
        ]
        db.insert_test_data(store.db_path, test_data)

        # get results
        results = store.get(
            vuln_id="CVE-2023-0002",
            cpe_or_package="curl",
            fix_version="7.68.0-1ubuntu2.15",
            ecosystem="debian:11",
        )

        assert len(results) == 1
        result = results[0]
        assert isinstance(result, FixDate)
        assert result.vuln_id == "CVE-2023-0002"
        assert result.provider == "test-db"
        assert result.package_name == "curl"
        assert result.full_cpe == ""
        assert result.ecosystem == "debian:11"
        assert result.fix_version == "7.68.0-1ubuntu2.15"
        assert result.first_observed_date == date(2023, 2, 20)

    def test_get_with_ecosystem_filter(self, tmpdir):
        """test retrieving entries with ecosystem filtering"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with multiple ecosystem entries
        db = DatabaseFixture(store.db_path)
        test_data = [
            (
                "CVE-2023-0002", "test-db", "curl", "", "debian:11",
                "7.68.0-1ubuntu2.15", "2023-02-20",
                "2023-02-20T14:45:00"
            ),
            (
                "CVE-2023-0002", "test-db", "curl", "", "ubuntu:20.04",
                "7.68.0-1ubuntu2.15", "2023-02-21",
                "2023-02-21T14:45:00"
            ),
        ]
        db.insert_test_data(store.db_path, test_data)

        # get results with ecosystem filter
        results = store.get(
            vuln_id="CVE-2023-0002",
            cpe_or_package="curl",
            fix_version="7.68.0-1ubuntu2.15",
            ecosystem="debian:11",
        )

        assert len(results) == 1
        result = results[0]
        assert result.ecosystem == "debian:11"

    def test_get_empty_results(self, tmpdir):
        """test that get returns empty list when no matches found"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create empty test database
        db = DatabaseFixture(store.db_path)

        # get results for non-existent entry
        results = store.get(
            vuln_id="CVE-9999-9999",
            cpe_or_package="nonexistent",
            fix_version="1.0.0",
        )

        assert len(results) == 0

    def test_find_returns_result_objects(self, tmpdir):
        """test that find method returns Result objects"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with data
        db = DatabaseFixture(store.db_path)
        test_data = [
            (
                "CVE-2023-0001", "test-db", "",
                "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                "2.4.42", "2023-01-15",
                "2023-01-15T10:30:00"
            ),
        ]
        db.insert_test_data(store.db_path, test_data)

        # find results
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]
        assert isinstance(result, Result)
        assert result.date == date(2023, 1, 15)
        assert result.kind == "first-observed"
        assert result.version == "2.4.42"
        assert result.accurate is True  # accurate flag is always True now

    def test_find_accurate_flag_always_true(self, tmpdir):
        """test that find method always sets accurate flag to True"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database with data
        db = DatabaseFixture(store.db_path)
        test_data = [
            (
                "CVE-2023-0001", "test-db", "",
                "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                "2.4.42", "2023-01-15",
                "2023-01-15T10:30:00"
            ),
        ]
        db.insert_test_data(store.db_path, test_data)

        # find results
        results = store.find(
            vuln_id="CVE-2023-0001",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]
        assert result.accurate is True  # accurate flag is always True now

    def test_thread_local_connection_management(self, tmpdir):
        """test that database connections are managed per thread"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        db = DatabaseFixture(store.db_path)

        # get connection from main thread
        conn1, table1 = store._get_connection()
        conn1_id = id(conn1)

        # get connection again from same thread (should be same)
        conn2, table2 = store._get_connection()
        conn2_id = id(conn2)

        assert conn1_id == conn2_id  # same connection object
        assert table1 is table2  # same table object

        # test that different threads get different connections
        results = []

        def worker():
            conn, table = store._get_connection()
            results.append(id(conn))

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        thread_conn_id = results[0]
        assert thread_conn_id != conn1_id  # different connection for different thread

    def test_cleanup_thread_connections(self, tmpdir):
        """test that thread connections are properly cleaned up"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)

        # create test database
        db = DatabaseFixture(store.db_path)

        # get connection to establish thread-local storage
        store._get_connection()

        # verify thread-local storage exists
        assert hasattr(store._thread_local, "conn")
        assert hasattr(store._thread_local, "table")

        # cleanup connections
        store.cleanup_thread_connections()

        # verify thread-local storage is cleared
        assert not hasattr(store._thread_local, "conn")
        assert not hasattr(store._thread_local, "table")

    def test_batch_commit_performance(self, tmpdir, mocker):
        """test that commits are batched for performance"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)

        # Use small batch size for testing
        store = Store(ws, batch_size=5)
        db = DatabaseFixture(store.db_path)

        # Mock commit to count calls
        conn, _ = store._get_connection()
        original_commit = conn.commit
        commit_count = [0]

        def tracked_commit():
            commit_count[0] += 1
            return original_commit()

        conn.commit = tracked_commit

        # Add 12 entries (should trigger 2 auto-flushes at 5 and 10, plus final flush)
        for i in range(12):
            store.add(
                first_observed_date=date(2023, 1, 1),
                vuln_id=f"CVE-2023-{i:04d}",
                cpe_or_package=f"cpe:2.3:a:vendor:product:{i}:*:*:*:*:*:*:*",
                fix_version="1.0.0",
            )

        # Flush remaining
        store.flush()

        # Should have committed 3 times: at 5, at 10, and final flush
        assert commit_count[0] == 3, f"Expected 3 commits but got {commit_count[0]}"

        # Verify all records were saved
        results = store.find("CVE-2023-0000", "cpe:2.3:a:vendor:product:0:*:*:*:*:*:*:*", "1.0.0")
        assert len(results) == 1

        results = store.find("CVE-2023-0011", "cpe:2.3:a:vendor:product:11:*:*:*:*:*:*:*", "1.0.0")
        assert len(results) == 1
