from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from vunnel import workspace
from vunnel.tool.fixdate.grypedb import FixDate, Store


class TestStore:

    def test_store_initialization(self, tmpdir):
        # create a workspace
        ws = workspace.Workspace(tmpdir, "test", create=True)
        name = "test-db"

        # create store instance
        store = Store(ws, name)

        # verify initialization
        assert store.workspace == ws
        assert store.name == name
        assert store.db_path == Path(ws.input_path) / "fix-dates" / f"{name}.db"
        assert store.logger.name == f"fixes-{name}"

    def test_setup(self, tmpdir):
        # create a workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # ensure db directory exists
        store.db_path.parent.mkdir(parents=True, exist_ok=True)

        # create the fixdates table that the Store expects
        self._create_test_database(store.db_path)

        # run setup
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(store.setup())
        finally:
            loop.close()

        # verify setup completed without errors and can query the database
        results = store.get(
            vuln_id="CVE-2023-0001",
            provider="nvd",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )
        assert len(results) == 1

    @patch("oras.client.OrasClient")
    def test_download_success(self, mock_oras_client_class, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

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
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # mock the ORAS client to raise an exception
        mock_client = Mock()
        mock_client.pull.side_effect = Exception("Download failed")
        mock_oras_client_class.return_value = mock_client

        # verify download raises the exception
        with pytest.raises(Exception, match="Download failed"):
            store.download()

    def test_download_creates_directories(self, tmpdir):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # ensure directory doesn't exist initially
        assert not store.db_path.parent.exists()

        with patch("oras.client.OrasClient") as mock_oras_client_class:
            mock_client = Mock()
            mock_oras_client_class.return_value = mock_client

            store.download()

            # verify directory was created
            assert store.db_path.parent.exists()

    def test_get_by_cpe(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # create test database
        self._create_test_database(store.db_path)

        # test CPE-based query
        results = store.get(
            vuln_id="CVE-2023-0001",
            provider="nvd",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]
        assert result.vuln_id == "CVE-2023-0001"
        assert result.provider == "nvd"
        assert result.full_cpe == "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*"
        assert result.fix_version == "2.4.42"
        assert result.package_name == ""

    def test_get_by_package_name(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # create test database
        self._create_test_database(store.db_path)

        # test package name-based query
        results = store.get(
            vuln_id="CVE-2023-0002",
            provider="debian",
            cpe_or_package="curl",
            fix_version="7.68.0-1ubuntu2.15",
            ecosystem="debian:11",
        )

        assert len(results) == 1
        result = results[0]
        assert result.vuln_id == "CVE-2023-0002"
        assert result.provider == "debian"
        assert result.package_name == "curl"
        assert result.ecosystem == "debian:11"
        assert result.full_cpe == ""

    def test_get_with_ecosystem(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # create test database
        self._create_test_database(store.db_path)

        # test query with ecosystem filter
        results = store.get(
            vuln_id="CVE-2023-0002",
            provider="debian",
            cpe_or_package="curl",
            fix_version=None,
            ecosystem="debian:11",
        )

        assert len(results) == 2  # should return both with and without fix_version

    def test_get_without_fix_version(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # create test database
        self._create_test_database(store.db_path)

        # test query without fix_version
        results = store.get(
            vuln_id="CVE-2023-0002",
            provider="debian",
            cpe_or_package="curl",
            fix_version=None,
            ecosystem="debian:11",
        )

        assert len(results) == 2  # both records should match

    def test_get_returns_fixdate_objects(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # create test database
        self._create_test_database(store.db_path)

        # get results
        results = store.get(
            vuln_id="CVE-2023-0001",
            provider="nvd",
            cpe_or_package="cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*",
            fix_version="2.4.42",
        )

        assert len(results) == 1
        result = results[0]

        # verify it's a FixDate object with correct types
        assert isinstance(result, FixDate)
        assert isinstance(result.first_observed_date, datetime)
        assert result.resolution == "fixed"
        assert result.source == "grype-db"

    def test_get_empty_results(self, tmpdir, helpers):
        # create workspace and store
        ws = workspace.Workspace(tmpdir, "test", create=True)
        store = Store(ws, "test-db")

        # create test database
        self._create_test_database(store.db_path)

        # test query that should return no results
        results = store.get(
            vuln_id="CVE-9999-9999",
            provider="nonexistent",
            cpe_or_package="nonexistent",
            fix_version=None,
        )

        assert len(results) == 0

    def _create_test_database(self, db_path: Path):
        """helper method to create test database with sample data"""
        db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(db_path) as conn:
            # create table schema
            conn.execute("""
                CREATE TABLE fixdates (
                    vuln_id TEXT,
                    provider TEXT,
                    package_name TEXT,
                    full_cpe TEXT,
                    ecosystem TEXT,
                    fix_version TEXT,
                    first_observed_date TEXT,
                    resolution TEXT,
                    source TEXT
                )
            """)

            # insert test data
            test_data = [
                # CPE-based record
                (
                    "CVE-2023-0001", "nvd", "",
                    "cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*", "",
                    "2.4.42", "2023-01-15T10:30:00", "fixed", "grype-db",
                ),
                # package name-based records
                (
                    "CVE-2023-0002", "debian", "curl", "", "debian:11",
                    "7.68.0-1ubuntu2.15", "2023-02-20T14:45:00", "fixed", "grype-db",
                ),
                (
                    "CVE-2023-0002", "debian", "curl", "", "debian:11",
                    None, "2023-02-18T09:15:00", "wont-fix", "grype-db",
                ),
                # additional test record
                (
                    "CVE-2023-0003", "rhel", "openssl", "", "rhel:8",
                    "1.1.1k-7.el8_6", "2023-03-10T16:00:00", "fixed", "grype-db",
                ),
            ]

            conn.executemany(
                "INSERT INTO fixdates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                test_data,
            )
