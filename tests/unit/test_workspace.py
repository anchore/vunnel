from __future__ import annotations

import datetime
import os
import sqlite3

import pytest

from vunnel import result, schema, workspace


def assert_directory(path: str, exists: bool = True, empty: bool = False):
    if not exists and not empty:
        raise ValueError("cannot assert directory does not exist and is not empty")

    if exists:
        assert os.path.exists(path), f"directory does not exist (but should): {path}"
        if empty:
            assert len(os.listdir(path)) == 0, f"directory is not empty (but should be): {path}"
        else:
            assert len(os.listdir(path)) > 0, f"directory is empty (but should not be): {path}"
    else:
        assert not os.path.exists(path), f"directory exists (but should not): {path}"


def test_clear_input(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)

    # create a dummy files
    dummy_file(ws.input_path)
    dummy_file(ws.results_path)

    assert_directory(ws.input_path, exists=True, empty=False)
    assert_directory(ws.results_path, exists=True, empty=False)

    # clear the input
    ws.clear_input()

    assert_directory(ws.input_path, exists=True, empty=True)
    assert_directory(ws.results_path, exists=True, empty=False)


def test_clear_results(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)

    # create a dummy files
    dummy_file(ws.input_path)
    dummy_file(ws.results_path)

    urls = ["http://localhost:8000/dummy-input-1.json"]
    store = result.StoreStrategy.FLAT_FILE
    ws.record_state(urls=urls, store=store.value, timestamp=datetime.datetime(2021, 1, 1), version=1, distribution_version=1)

    assert_directory(ws.input_path, exists=True, empty=False)
    assert_directory(ws.results_path, exists=True, empty=False)

    # clear the results
    ws.clear_results()

    assert_directory(ws.input_path, exists=True, empty=False)
    assert_directory(ws.results_path, exists=True, empty=True)

    # ensure the URLs are still populated
    new_state = workspace.State.read(root=ws.path)
    assert urls == new_state.urls


def test_record_state(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)

    # create a dummy files
    dummy_file(ws.input_path, "dummt-input-1.json")
    dummy_file(ws.results_path, "dummy-00000.json")

    urls = ["http://localhost:8000/dummy-input-1.json"]
    store = result.StoreStrategy.FLAT_FILE
    ws.record_state(urls=urls, store=store.value, timestamp=datetime.datetime(2021, 1, 1), version=1, distribution_version=1)

    current_state = workspace.State.read(root=ws.path)

    # ignore timestamp (make certain it exists)
    assert current_state.timestamp is not None
    current_state.timestamp = None

    expected_state = workspace.State(
        store=result.StoreStrategy.FLAT_FILE.value,
        provider="dummy",
        urls=["http://localhost:8000/dummy-input-1.json"],
        listing=workspace.File(digest="63b7adef165e430a", algorithm="xxh64", path="checksums"),
        timestamp=None,
        schema=schema.ProviderStateSchema(),
    )

    assert current_state == expected_state


def test_record_state_urls_persisted_across_runs(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)

    # create a dummy files
    dummy_file(ws.input_path, "dummt-input-1.json")
    dummy_file(ws.results_path, "dummy-00000.json")

    urls = ["http://localhost:8000/dummy-input-1.json"]
    store = result.StoreStrategy.FLAT_FILE
    ws.record_state(urls=urls, store=store.value, timestamp=datetime.datetime(2021, 1, 1), version=1, distribution_version=1)

    # this call should not clear the URLs
    ws.record_state(urls=None, store=store.value, timestamp=datetime.datetime(2021, 1, 1), version=1, distribution_version=1)

    current_state = workspace.State.read(root=ws.path)

    # ignore timestamp (make certain it exists)
    assert current_state.timestamp is not None
    current_state.timestamp = None

    expected_state = workspace.State(
        store=store,
        provider="dummy",
        urls=["http://localhost:8000/dummy-input-1.json"],
        listing=workspace.File(digest="63b7adef165e430a", algorithm="xxh64", path="checksums"),
        timestamp=None,
        schema=schema.ProviderStateSchema(),
    )

    assert current_state == expected_state


def test_state_schema(tmpdir, dummy_file, helpers):
    name = "dummy"
    ws = workspace.Workspace(root=tmpdir, name=name, create=True)

    # create a dummy files
    dummy_file(ws.input_path, "dummt-input-1.json")
    dummy_file(ws.results_path, "dummy-00000.json")

    urls = ["http://localhost:8000/dummy-input-1.json"]
    store = result.StoreStrategy.FLAT_FILE
    ws.record_state(urls=urls, store=store.value, timestamp=datetime.datetime(2021, 1, 1), version=1, distribution_version=1)

    ws_helper = helpers.provider_workspace_helper(name=name, create=False)

    assert ws_helper.metadata_schema_valid()


def test_replace_results(tmpdir, dummy_file):
    # make 2 workspaces
    ws1_dir = tmpdir.mkdir("ws1")
    ws1 = workspace.Workspace(root=ws1_dir, name="old", create=True)
    dummy_file(ws1.input_path, "old-input-1.json")
    dummy_file(ws1.results_path, "old-00000.json")
    urls = ["http://localhost:8000/old_workspace.json"]
    store = result.StoreStrategy.FLAT_FILE
    ws1.record_state(urls=urls, store=store.value, timestamp=datetime.datetime(2021, 1, 1), version=1, distribution_version=1)

    ws2_dir = tmpdir.mkdir("ws2")
    ws2 = workspace.Workspace(root=ws2_dir, name="new", create=True)
    dummy_file(ws2.input_path, "new-input-2.json")
    urls = ["http://localhost:8000/new_workspace.json"]
    store = result.StoreStrategy.FLAT_FILE
    dummy_file(ws2.results_path, "new-00000.json")
    ws2.record_state(urls=urls, store=store.value, timestamp=datetime.datetime(2024, 1, 1), version=1, distribution_version=1)
    # be able to tell the contents apart
    # replace the results in one with the other
    # assert on the contents
    ws1.replace_results(ws2)
    # assert that metadata / state is replaced
    assert "http://localhost:8000/new_workspace.json" in ws1.state().urls
    assert "http://localhost:8000/old_workspace.json" not in ws1.state().urls

    # assert that results have been replaced
    assert os.path.exists(os.path.join(ws1.results_path, "new-00000.json"))
    assert not os.path.exists(os.path.join(ws1.results_path, "old-00000.json"))

    # assert that input path is not changed
    assert os.path.exists(os.path.join(ws1.input_path, "old-input-1.json"))
    assert not os.path.exists(os.path.join(ws1.input_path, "new-input-1.json"))


def test_validate_checksums_valid(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)
    urls = []
    dummy_file(ws.results_path, "dummy-result-1.json")
    ws.record_state(
        urls=urls,
        store=result.StoreStrategy.FLAT_FILE.value,
        timestamp=datetime.datetime(2021, 1, 1),
        version=1,
        distribution_version=1,
    )
    ws.validate_checksums()


def test_validate_checksums_invalid(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)
    urls = []
    result_file_path = dummy_file(ws.results_path, "dummy-result-1.json")
    ws.record_state(
        urls=urls,
        store=result.StoreStrategy.FLAT_FILE.value,
        timestamp=datetime.datetime(2021, 1, 1),
        version=1,
        distribution_version=1,
    )
    with open(result_file_path, "a") as f:
        f.write("invalid")
    with pytest.raises(RuntimeError) as e:
        ws.validate_checksums()
        assert "has been modified" in str(e)


def test_validate_checksums_missing(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)
    urls = []
    result_file_path = dummy_file(ws.results_path, "dummy-result-1.json")
    ws.record_state(
        urls=urls,
        store=result.StoreStrategy.FLAT_FILE.value,
        timestamp=datetime.datetime(2021, 1, 1),
        version=1,
        distribution_version=1,
    )
    os.remove(result_file_path)
    with pytest.raises(RuntimeError) as e:
        ws.validate_checksums()
        assert "does not exist" in str(e)


def test_validate_checksums_input_changed_ok(tmpdir, dummy_file):
    ws = workspace.Workspace(root=tmpdir, name="dummy", create=True)
    urls = []
    result_file_path = dummy_file(ws.results_path, "dummy-result-1.json")
    input_file_path = dummy_file(ws.input_path, "dummy-input-1.json")
    ws.record_state(
        urls=urls,
        store=result.StoreStrategy.FLAT_FILE.value,
        timestamp=datetime.datetime(2021, 1, 1),
        version=1,
        distribution_version=1,
    )
    with open(input_file_path, "a") as f:
        f.write("this won't change the checksums")

    ws.validate_checksums()


def test_result_count_with_multiple_db_files_regression(tmpdir):
    """
    Regression test for fix-dates feature bug where multiple .db files in results
    directory caused "no such table: results" error in workspace.result_count().

    This test simulates the scenario where observed-fix-dates.db (with fixdates table)
    exists alongside results.db (with results table). The result_count should only
    query results.db and ignore other .db files.

    Bug introduced in vunnel 0.39.0 when fix-dates feature was added.
    Fixed by changing workspace.result_count() to only query files ending with "results.db"
    instead of all ".db" files.
    """
    ws = workspace.Workspace(root=tmpdir, name="test_provider", create=True)
    store_strategy = result.StoreStrategy.SQLITE

    # Create some SQLite results using the normal flow
    with result.Writer(
        ws, result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE, store_strategy=store_strategy
    ) as writer:
        writer.write(
            identifier="test-result-1",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"id": "CVE-2023-1234"}},
        )
        writer.write(
            identifier="test-result-2",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"id": "CVE-2023-5678"}},
        )

    # Create a fake observed-fix-dates.db file with a different table schema
    # This simulates what the fix-dates feature creates
    fake_fixdates_db = os.path.join(ws.results_path, "test-observed-fix-dates.db")
    with sqlite3.connect(fake_fixdates_db) as db:
        db.execute("CREATE TABLE fixdates (id INTEGER PRIMARY KEY, vuln_id TEXT, fix_date TEXT)")
        db.execute("INSERT INTO fixdates (vuln_id, fix_date) VALUES ('CVE-2023-1111', '2023-01-01')")
        db.execute("INSERT INTO fixdates (vuln_id, fix_date) VALUES ('CVE-2023-2222', '2023-02-01')")

    # Record the state which will create checksums including both .db files
    ws.record_state(
        timestamp=datetime.datetime.now(),
        urls=["https://example.com"],
        store=store_strategy.value,
        version=1,
        distribution_version=1
    )

    state = ws.state()

    # Before the fix, this would fail with "no such table: results" when trying to
    # query the test-observed-fix-dates.db for a results table that doesn't exist
    result_count = state.result_count(ws.path)

    # Should count: 2 results from results.db + 1 for test-observed-fix-dates.db (as regular file)
    # Before the fix, this would crash with "no such table: results"
    # After the fix, test-observed-fix-dates.db is treated as a regular file (+1) instead of being queried
    assert result_count == 3

    # Verify both database files are tracked in the workspace
    result_files = list(state.result_files(ws.path))
    db_files = [f for f in result_files if f.path.endswith('.db')]
    assert len(db_files) == 2

    # Verify we can identify which is which
    assert any("results.db" in f.path for f in db_files)
    assert any("test-observed-fix-dates.db" in f.path for f in db_files)
