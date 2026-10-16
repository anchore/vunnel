from __future__ import annotations

import sqlite3
import threading
import time
from datetime import date, datetime, timedelta
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


def _committed_row_count(store: Store) -> int:
    """rows a separate connection sees, i.e. committed ones"""
    with sqlite3.connect(store.db_path) as conn:
        (count,) = conn.execute("SELECT COUNT(*) FROM fixdates").fetchone()
    return count


def _outside_write_errors(store: Store) -> list[Exception]:
    """write one row from a separate connection with a zero busy timeout, so a held lock fails at once"""
    errors: list[Exception] = []
    conn = sqlite3.connect(store.db_path, timeout=0)
    try:
        conn.execute(
            "INSERT INTO fixdates (vuln_id, provider, package_name, full_cpe, ecosystem, "
            "fix_version, first_observed_date, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ("CVE-2023-9999", "test-db", "other", "", "alpine", "2.0.0", "2023-01-01", None),
        )
        conn.commit()
    except Exception as e:  # noqa: BLE001
        errors.append(e)
    finally:
        conn.close()
    return errors


def _add_poison_trigger(db_path: Path) -> None:
    """make any INSERT of vuln_id CVE-POISON fail"""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TRIGGER fail_on_poison BEFORE INSERT ON fixdates "
            "WHEN NEW.vuln_id = 'CVE-POISON' BEGIN SELECT RAISE(ABORT, 'poison'); END",
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
        assert store._conn is None

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

        # add() buffers the row in memory; flush() writes and commits the batch
        store.flush()

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

        # add() buffers the row in memory; flush() writes and commits the batch
        store.flush()

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

        # add() buffers the row in memory; flush() writes and commits the batch
        store.flush()

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

    def test_threads_share_one_connection(self, tmpdir):
        """every thread reads and writes through the same connection"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)
        DatabaseFixture(store.db_path)

        with store._lock:
            conn1, table1 = store._get_connection()
            conn2, table2 = store._get_connection()
        assert conn1 is conn2
        assert table1 is table2

        results = []

        def worker():
            with store._lock:
                results.append(store._get_connection()[0])

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        assert results == [conn1]

    def test_close(self, tmpdir):
        """close() releases the connection and the engine"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws)
        DatabaseFixture(store.db_path)

        with store._lock:
            store._get_connection()
        assert store._conn is not None
        assert store._table is not None

        store.close()

        assert store._conn is None
        assert store._table is None
        assert store.engine is None

    @pytest.mark.parametrize("failing_step", ["commit", "vacuum"])
    def test_close_closes_the_connection_when_a_step_fails(self, tmpdir, mocker, failing_step):
        """a failure in the pre-VACUUM commit or in VACUUM must not leave the connection open"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.get("CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        conn = store._conn
        error = sqlalchemy.exc.OperationalError(failing_step, {}, Exception("boom"))
        if failing_step == "commit":
            mocker.patch.object(conn, "commit", side_effect=error)
        else:
            mocker.patch.object(conn, "execute", side_effect=error)

        store.close()

        assert conn.closed
        assert store._conn is None
        assert store._table is None

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

    def test_read_your_writes_before_flush(self, tmpdir):
        """an added row is visible to get() before it is committed"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 5, 4), "CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")

        # not committed yet - another connection does not see it
        assert _committed_row_count(store) == 0

        found = store.get("CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")
        assert len(found) == 1
        assert found[0].first_observed_date == date(2023, 5, 4)

        # a non-matching lookup must not pick the buffered row up
        assert store.get("CVE-2023-1234", "openssl", "9.9.9", ecosystem="alpine") == []
        assert store.get("CVE-2023-1234", "zlib", "1.1.1", ecosystem="alpine") == []
        assert store.get("CVE-2023-0000", "openssl", "1.1.1", ecosystem="alpine") == []

        # and the row must not be double-counted once it lands on disk
        store.flush()
        assert len(store.get("CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")) == 1

    def test_updated_at_is_a_datetime_before_and_after_flush(self, tmpdir):
        """an uncommitted row and the same row after commit report updated_at the same way"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 1, 1), "CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")
        (buffered,) = store.get("CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")
        store.flush()
        (on_disk,) = store.get("CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")

        assert isinstance(buffered.updated_at, datetime)
        assert on_disk.updated_at == buffered.updated_at

    def test_get_returns_one_row_for_a_key_added_twice_before_flush(self, tmpdir):
        """the second add of a key is ignored (the first observation wins), even before commit"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 1, 1), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        store.add(date(2023, 2, 2), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        assert store._uncommitted_rows == 1

        before = store.get("CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        store.flush()
        after = store.get("CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")

        assert [r.first_observed_date for r in before] == [date(2023, 1, 1)]
        assert [r.first_observed_date for r in after] == [date(2023, 1, 1)]

    def test_get_does_not_duplicate_a_key_already_on_disk(self, tmpdir):
        """re-adding a key that is already committed does not add a second row"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 1, 1), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        store.flush()
        store.add(date(2023, 2, 2), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")

        results = store.get("CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")

        assert [r.first_observed_date for r in results] == [date(2023, 1, 1)]

    def test_threads_do_not_lock_each_other_out(self, tmpdir):
        """regression test for the RHEL "database is locked" failure (#970).

        That failure came from per-thread connections: one thread's uncommitted INSERT held the
        sqlite write lock, and another thread's INSERT on its own connection could not get it.
        With one shared connection, a second thread writes into the same open transaction. This
        is asserted directly, with a zero busy timeout so any lock contention fails at once,
        rather than by timing.
        """
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 1, 1), "CVE-2023-0001", "pkg-1", "1.0.0", ecosystem="alpine")
        with store._lock:
            store._conn.exec_driver_sql("PRAGMA busy_timeout=0")

        errors: list[Exception] = []

        def other_thread() -> None:
            try:
                store.get("CVE-2023-0002", "pkg-2", "1.0.0", ecosystem="alpine")
                store.add(date(2023, 1, 1), "CVE-2023-0002", "pkg-2", "1.0.0", ecosystem="alpine")
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join()

        assert not errors, f"one thread's open batch blocked another thread: {errors}"

        store.flush()
        assert _committed_row_count(store) == 2

    def test_flush_releases_the_write_lock(self, tmpdir):
        """between batches the store holds no sqlite lock, so an outside writer is not blocked"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        for i in range(10):
            store.get(f"CVE-2023-{i:04d}", f"pkg-{i}", "1.0.0", ecosystem="alpine")
            store.add(date(2023, 1, 1), f"CVE-2023-{i:04d}", f"pkg-{i}", "1.0.0", ecosystem="alpine")
        store.flush()

        assert not _outside_write_errors(store), "the store kept the database locked after a flush"
        assert _committed_row_count(store) == 11

    def test_failed_add_keeps_the_rows_around_it(self, tmpdir):
        """an INSERT that fails rolls back only itself: earlier and later rows are still committed"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)
        _add_poison_trigger(store.db_path)

        for i in range(3):
            store.add(date(2023, 1, 1), f"CVE-2023-{i:04d}", "pkg", "1.0.0", ecosystem="alpine")
        with pytest.raises(sqlalchemy.exc.IntegrityError, match="poison"):
            store.add(date(2023, 1, 1), "CVE-POISON", "pkg", "1.0.0", ecosystem="alpine")
        store.add(date(2023, 1, 1), "CVE-2023-0003", "pkg", "1.0.0", ecosystem="alpine")
        store.flush()

        assert _committed_row_count(store) == 4

    def test_failed_commit_leaves_no_write_lock(self, tmpdir, mocker):
        """if the commit fails, the batch is rolled back rather than left holding the write lock"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        for i in range(3):
            store.add(date(2023, 1, 1), f"CVE-2023-{i:04d}", "pkg", "1.0.0", ecosystem="alpine")
        mocker.patch.object(store._conn, "commit", side_effect=sqlalchemy.exc.OperationalError("commit", {}, Exception("boom")))

        with pytest.raises(sqlalchemy.exc.OperationalError, match="boom"):
            store.flush()

        assert store._uncommitted_rows == 0
        assert not _outside_write_errors(store), "a failed commit left the database locked"
        assert _committed_row_count(store) == 1  # just the outside writer's row

    def test_flush_keeps_the_first_observation_of_a_duplicate_key(self, tmpdir):
        """a key that is already on disk is skipped by the flush, so the earlier date wins"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 1, 1), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        store.flush()
        store.add(date(2023, 2, 2), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        store.add(date(2023, 1, 1), "CVE-2023-0002", "openssl", "1.0.0", ecosystem="alpine")
        store.flush()

        with sqlite3.connect(store.db_path) as conn:
            rows = conn.execute("SELECT vuln_id, first_observed_date FROM fixdates ORDER BY vuln_id").fetchall()
        assert rows == [("CVE-2023-0001", "2023-01-01"), ("CVE-2023-0002", "2023-01-01")]

    @pytest.mark.parametrize(
        ("first_observed_date", "vuln_id", "error"),
        [
            pytest.param(date(2023, 1, 1), None, sqlalchemy.exc.IntegrityError, id="missing vuln_id"),
            pytest.param(None, "CVE-2023-0002", AttributeError, id="missing date"),
            pytest.param("2023-01-01", "CVE-2023-0002", AttributeError, id="date as a string"),
        ],
    )
    def test_add_raises_on_a_row_it_cannot_write(self, tmpdir, first_observed_date, vuln_id, error):
        """a bad row fails the add() that offers it, not a later flush, and the good rows survive.
        A NOT NULL violation must raise rather than vanish (ON CONFLICT DO NOTHING, unlike OR
        IGNORE, ignores only primary-key conflicts)."""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=2)
        DatabaseFixture(store.db_path)

        store.add(date(2023, 1, 1), "CVE-2023-0001", "openssl", "1.0.0", ecosystem="alpine")
        with pytest.raises(error):
            store.add(first_observed_date, vuln_id, "zlib", "1.0.0", ecosystem="alpine")  # type: ignore[arg-type]
        assert store._uncommitted_rows == 1

        # the next good add reaches batch_size and commits both good rows
        store.add(date(2023, 1, 1), "CVE-2023-0003", "curl", "1.0.0", ecosystem="alpine")
        assert store._uncommitted_rows == 0

        with sqlite3.connect(store.db_path) as conn:
            rows = conn.execute("SELECT vuln_id FROM fixdates ORDER BY vuln_id").fetchall()
        assert rows == [("CVE-2023-0001",), ("CVE-2023-0003",)]

    @staticmethod
    def _store_whose_commit_fails(tmpdir, mocker) -> Store:
        """a store with an uncommitted row whose next commit fails."""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)
        store.add(date(2023, 1, 1), "CVE-2023-0001", "pkg", "1.0.0", ecosystem="alpine")
        mocker.patch.object(store._conn, "commit", side_effect=sqlalchemy.exc.OperationalError("commit", {}, Exception("boom")))
        return store

    def test_exit_cleans_up_when_flush_fails(self, tmpdir, mocker):
        """a failing final flush is raised, but the connection is still released"""
        store = self._store_whose_commit_fails(tmpdir, mocker)

        with pytest.raises(sqlalchemy.exc.OperationalError, match="boom"), store:
            pass

        assert store._conn is None
        assert store.engine is None

    def test_exit_keeps_the_original_exception_when_flush_fails(self, tmpdir, mocker):
        """a failing final flush must not replace the exception the provider is raising"""
        store = self._store_whose_commit_fails(tmpdir, mocker)

        # raised from a function so the asserts below are not unreachable to static analysis
        # (which does not know pytest.raises suppresses the exception)
        def provider_fails() -> None:
            raise RuntimeError("provider failed")

        with pytest.raises(RuntimeError, match="provider failed"), store:
            provider_fails()

        assert store._conn is None
        assert store.engine is None

    def test_concurrent_reads_and_writes(self, tmpdir):
        """concurrency smoke test: several threads interleave get() and add() against one Store.

        None of them may see an OperationalError, and every row must survive. (This passes
        with per-thread connections too; test_threads_do_not_lock_each_other_out is the #970
        regression test.)
        """
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=25)
        DatabaseFixture(store.db_path)

        thread_count = 8
        per_thread = 200
        errors: list[Exception] = []
        barrier = threading.Barrier(thread_count)

        def worker(worker_id: int) -> None:
            try:
                barrier.wait()
                if worker_id == 0:
                    store.add(date(2023, 1, 1), "CVE-2023-000000", "shared-pkg", "1.0.0", ecosystem="alpine")
                for i in range(per_thread):
                    vuln_id = f"CVE-2023-{worker_id:02d}{i:04d}"
                    package = f"pkg-{worker_id}-{i}"
                    # the read-then-write access pattern of first_observed.Store.find()
                    existing = store.get(vuln_id, package, "1.0.0", ecosystem="alpine")
                    if not existing:
                        store.add(date(2023, 1, 1), vuln_id, package, "1.0.0", ecosystem="alpine")
                    # every thread also reads a key that worker 0 writes (whether the read
                    # sees it depends on timing; only the absence of errors matters)
                    store.get("CVE-2023-000000", "shared-pkg", "1.0.0", ecosystem="alpine")
                store.flush()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(thread_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"concurrent access raised: {errors[:3]}"

        with sqlite3.connect(store.db_path) as conn:
            (count,) = conn.execute("SELECT COUNT(*) FROM fixdates").fetchone()
        assert count == thread_count * per_thread + 1  # + the shared key

    def test_flush_drains_rows_from_finished_threads(self, tmpdir):
        """rows added by a worker thread that never reached a flush must still be written"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        def worker(worker_id: int) -> None:
            for i in range(5):
                store.add(date(2023, 1, 1), f"CVE-2023-{worker_id}{i:03d}", f"pkg-{worker_id}-{i}", "1.0.0")
            # deliberately no flush() - the thread just ends

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        store.flush()

        with sqlite3.connect(store.db_path) as conn:
            (count,) = conn.execute("SELECT COUNT(*) FROM fixdates").fetchone()
        assert count == 15

    def test_uncommitted_rows_are_visible_to_other_threads(self, tmpdir):
        """a row one thread added must be returned by get() on another thread before it is committed"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        def writer() -> None:
            store.add(date(2023, 5, 4), "CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")

        t = threading.Thread(target=writer)
        t.start()
        t.join()

        # not committed yet - another connection does not see it
        assert _committed_row_count(store) == 0

        seen: list[list[FixDate]] = []

        def reader() -> None:
            seen.append(store.get("CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine"))

        t = threading.Thread(target=reader)
        t.start()
        t.join()

        assert len(seen) == 1
        assert len(seen[0]) == 1
        assert seen[0][0].first_observed_date == date(2023, 5, 4)

        store.flush()

        assert len(store.get("CVE-2023-1234", "openssl", "1.1.1", ecosystem="alpine")) == 1

    def test_many_threads_agree_on_the_first_observation(self, tmpdir):
        """stress test: 64 threads race find-then-add (first_observed.Store's access pattern) on a
        shared set of keys, each offering its own date. Exactly one date may win per key, and once
        any thread has read a key, every later read of it must return that same date."""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=50)
        DatabaseFixture(store.db_path)

        thread_count = 64
        keys = [(f"CVE-2023-{k:04d}", f"pkg-{k}") for k in range(200)]
        errors: list[Exception] = []
        seen: dict[tuple[str, str], set[date]] = {key: set() for key in keys}
        seen_lock = threading.Lock()
        barrier = threading.Barrier(thread_count)

        def worker(worker_id: int) -> None:
            offered = date(2023, 1, 1) + timedelta(days=worker_id)
            try:
                barrier.wait()
                for i in range(len(keys)):
                    vuln_id, package = keys[(i + worker_id * 7) % len(keys)]
                    existing = store.get(vuln_id, package, "1.0.0", ecosystem="alpine")
                    if not existing:
                        store.add(offered, vuln_id, package, "1.0.0", ecosystem="alpine")
                        existing = store.get(vuln_id, package, "1.0.0", ecosystem="alpine")
                    with seen_lock:
                        seen[(vuln_id, package)].update(fd.first_observed_date for fd in existing)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        # daemon threads, so a hung worker fails the test instead of keeping the process alive
        threads = [threading.Thread(target=worker, args=(w,), daemon=True) for w in range(thread_count)]
        for t in threads:
            t.start()
        # unsynchronized use of the shared connection can hang rather than raise
        deadline = time.monotonic() + 60
        for t in threads:
            t.join(timeout=max(0.0, deadline - time.monotonic()))
        assert not any(t.is_alive() for t in threads), "worker threads hung"
        store.flush()

        assert not errors, f"concurrent access raised: {errors[:3]}"
        disagreements = {key: dates for key, dates in seen.items() if len(dates) != 1}
        assert not disagreements, f"threads read different first-observed dates: {list(disagreements.items())[:3]}"

        with sqlite3.connect(store.db_path) as conn:
            on_disk = {(v, p): date.fromisoformat(d) for v, p, d in conn.execute("SELECT vuln_id, package_name, first_observed_date FROM fixdates")}
        assert on_disk == {key: next(iter(dates)) for key, dates in seen.items()}

    def test_get_order_does_not_depend_on_commit(self, tmpdir):
        """an ecosystem-less lookup matching rows from several ecosystems returns them in the same
        order whether or not they are committed yet, since Finder.best takes the first match"""
        ws = workspace.Workspace(tmpdir, "test-db", create=True)
        store = Store(ws, batch_size=1000)
        DatabaseFixture(store.db_path)

        store.add(date(2024, 5, 1), "CVE-1", "pkg", "1.0", ecosystem="npm")
        store.flush()
        store.add(date(2024, 1, 1), "CVE-1", "pkg", "1.0", ecosystem=None)

        before = [(r.ecosystem, r.first_observed_date) for r in store.get("CVE-1", "pkg", "1.0", ecosystem=None)]
        store.flush()
        after = [(r.ecosystem, r.first_observed_date) for r in store.get("CVE-1", "pkg", "1.0", ecosystem=None)]

        assert before == after == [("", date(2024, 1, 1)), ("npm", date(2024, 5, 1))]
