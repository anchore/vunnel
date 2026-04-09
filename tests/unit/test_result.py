from __future__ import annotations

import datetime
import os
import shutil

import pytest

from vunnel import result, schema, workspace


@pytest.fixture()
def ws(tmpdir) -> workspace.Workspace:
    return workspace.Workspace(root=tmpdir, name="nvd", create=True)


@pytest.fixture()
def flat_file_existing_workspace(ws: workspace.Workspace) -> workspace.Workspace:
    store_strategy = result.StoreStrategy.FLAT_FILE
    with result.Writer(ws, result_state_policy=result.ResultStatePolicy.DELETE, store_strategy=store_strategy) as writer:
        writer.write(
            identifier="dummy-result-1",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-1"}},
        )

        writer.write(
            identifier="dummy-result-2",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-2"}},
        )

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1, distribution_version=1)
    return ws


@pytest.fixture()
def sqlite_existing_workspace(ws: workspace.Workspace) -> workspace.Workspace:
    store_strategy = result.StoreStrategy.SQLITE
    with result.Writer(
        ws, result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE, store_strategy=store_strategy
    ) as writer:
        writer.write(
            identifier="dummy-result-1",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-1"}},
        )

        writer.write(
            identifier="dummy-result-2",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-2"}},
        )

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1, distribution_version=1)
    return ws


@pytest.fixture()
def sqlite_existing_workspace_with_partial_results(sqlite_existing_workspace: workspace.Workspace) -> workspace.Workspace:
    shutil.copy2(
        os.path.join(sqlite_existing_workspace.results_path, "results.db"),
        os.path.join(sqlite_existing_workspace.results_path, "results.db.tmp"),
    )
    sqlite_existing_workspace.record_state(
        timestamp=datetime.datetime.now(), urls=[], store=result.StoreStrategy.SQLITE, version=1, distribution_version=1
    )
    assert len(list(sqlite_existing_workspace.state().result_files(sqlite_existing_workspace.path))) == 2
    return sqlite_existing_workspace


@pytest.mark.parametrize(
    "result_state_policy,expected_files,expected_result_count",
    [
        (
            result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            [
                workspace.File(digest="ee3e94fdc6c24e87", path="results/dummy-result-3.json", algorithm="xxh64"),
                workspace.File(digest="99eaaf8393bba682", path="results/dummy-result-4.json", algorithm="xxh64"),
            ],
            2,
        ),
        (
            result.ResultStatePolicy.KEEP,
            [
                workspace.File(digest="6a2148315b319be0", path="results/dummy-result-1.json", algorithm="xxh64"),
                workspace.File(digest="cf21055f012abb22", path="results/dummy-result-2.json", algorithm="xxh64"),
                workspace.File(digest="ee3e94fdc6c24e87", path="results/dummy-result-3.json", algorithm="xxh64"),
                workspace.File(digest="99eaaf8393bba682", path="results/dummy-result-4.json", algorithm="xxh64"),
            ],
            4,
        ),
    ],
)
def test_result_writer_flat_file(
    flat_file_existing_workspace: workspace.Workspace,
    result_state_policy: result.ResultStatePolicy,
    expected_files: list[workspace.File],
    expected_result_count: int,
):
    ws = flat_file_existing_workspace
    store_strategy = result.StoreStrategy.FLAT_FILE
    with result.Writer(ws, result_state_policy=result_state_policy, store_strategy=store_strategy) as writer:
        writer.write(
            identifier="dummy-result-3",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-3"}},
        )

        writer.write(
            identifier="dummy-result-4",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-4"}},
        )

        writer.write(
            identifier="dummy-result-4",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-4"}},
        )

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1, distribution_version=1)

    state = ws.state()

    assert list(state.result_files(ws.path)) == expected_files
    assert state.result_count(ws.path) == expected_result_count


@pytest.mark.parametrize(
    "result_state_policy,expected_file_count,expected_result_count",
    [
        (
            result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            1,
            2,
        ),
        (
            result.ResultStatePolicy.KEEP,
            1,
            4,
        ),
    ],
)
def test_result_writer_sqlite(
    sqlite_existing_workspace: workspace.Workspace,
    result_state_policy: result.ResultStatePolicy,
    expected_file_count: int,
    expected_result_count: int,
):
    ws = sqlite_existing_workspace
    store_strategy = result.StoreStrategy.SQLITE
    with result.Writer(ws, result_state_policy=result_state_policy, store_strategy=store_strategy) as writer:
        writer.write(
            identifier="dummy-result-3",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-3"}},
        )

        writer.write(
            identifier="dummy-result-4",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-4"}},
        )

        writer.write(
            identifier="dummy-result-4",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-4"}},
        )

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1, distribution_version=1)
    state = ws.state()

    # note: since the hash changes on each test run, just confirm the result file count, not the extra metadata
    assert len(list(state.result_files(ws.path))) == expected_file_count
    assert state.result_count(ws.path) == expected_result_count


@pytest.mark.parametrize(
    "result_state_policy,expected_file_count,expected_result_count",
    [
        (
            result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            1,
            2,
        ),
        (
            result.ResultStatePolicy.KEEP,
            1,
            4,
        ),
    ],
)
def test_result_writer_sqlite_with_partial_result(
    sqlite_existing_workspace_with_partial_results: workspace.Workspace,
    result_state_policy: result.ResultStatePolicy,
    expected_file_count: int,
    expected_result_count: int,
):
    ws = sqlite_existing_workspace_with_partial_results
    store_strategy = result.StoreStrategy.SQLITE
    with result.Writer(ws, result_state_policy=result_state_policy, store_strategy=store_strategy) as writer:
        writer.write(
            identifier="dummy-result-3",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-3"}},
        )

        writer.write(
            identifier="dummy-result-4",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-4"}},
        )

        writer.write(
            identifier="dummy-result-4",
            schema=schema.OSSchema(),
            payload={"Vulnerability": {"dummy": "result-4"}},
        )

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1, distribution_version=1)
    state = ws.state()

    # note: since the hash changes on each test run, just confirm the result file count, not the extra metadata
    assert len(list(state.result_files(ws.path))) == expected_file_count
    assert state.result_count(ws.path) == expected_result_count


class TestSQLiteStoreBatchFlush:
    """tests for mid-batch auto-flush and duplicate handling across batch boundaries."""

    def test_auto_flush_triggers_at_batch_size(self, ws):
        """verify that records are flushed to the database when batch_size is reached."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            batch_size=3,
        )
        store.prepare()

        for i in range(5):
            envelope = result.Envelope(identifier=f"rec-{i}", schema="test", item={"n": i})
            store.store(f"rec-{i}", envelope)

        # after 5 stores with batch_size=3, one auto-flush should have occurred (3 records),
        # leaving 2 pending
        assert store._total_submitted == 3
        assert len(store._pending_records) == 2

        store.close(successful=True)

        # after close, all 5 records should be flushed and readable
        assert store._total_submitted == 5

        with result.SQLiteReader(os.path.join(ws.results_path, "results.db")) as reader:
            all_records = reader.read_all()
            assert len(all_records) == 5

    def test_skip_duplicates_ignores_within_batch(self, ws):
        """verify that OR IGNORE drops duplicates within the same batch."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            skip_duplicates=True,
            batch_size=100,
        )
        store.prepare()

        envelope_v1 = result.Envelope(identifier="dup-1", schema="test", item={"version": 1})
        envelope_v2 = result.Envelope(identifier="dup-1", schema="test", item={"version": 2})

        store.store("dup-1", envelope_v1)
        store.store("dup-1", envelope_v2)
        store.close(successful=True)

        with result.SQLiteReader(os.path.join(ws.results_path, "results.db")) as reader:
            record = reader.read("dup-1")
            # with OR IGNORE, the first insert wins
            assert record is not None
            assert record["item"]["version"] == 1

    def test_no_skip_duplicates_replaces_within_batch(self, ws):
        """verify that OR REPLACE overwrites duplicates within the same batch."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            skip_duplicates=False,
            batch_size=100,
        )
        store.prepare()

        envelope_v1 = result.Envelope(identifier="dup-1", schema="test", item={"version": 1})
        envelope_v2 = result.Envelope(identifier="dup-1", schema="test", item={"version": 2})

        store.store("dup-1", envelope_v1)
        store.store("dup-1", envelope_v2)
        store.close(successful=True)

        with result.SQLiteReader(os.path.join(ws.results_path, "results.db")) as reader:
            record = reader.read("dup-1")
            # with OR REPLACE, the last insert wins
            assert record is not None
            assert record["item"]["version"] == 2

    def test_skip_duplicates_across_batch_boundary(self, ws):
        """verify that duplicates spanning two batches are handled correctly."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            skip_duplicates=True,
            batch_size=2,
        )
        store.prepare()

        # batch 1: rec-0, rec-1 (auto-flushed)
        for i in range(2):
            envelope = result.Envelope(identifier=f"rec-{i}", schema="test", item={"batch": 1, "n": i})
            store.store(f"rec-{i}", envelope)

        # batch 2: rec-1 (duplicate), rec-2 (auto-flushed)
        store.store("rec-1", result.Envelope(identifier="rec-1", schema="test", item={"batch": 2, "n": 1}))
        store.store("rec-2", result.Envelope(identifier="rec-2", schema="test", item={"batch": 2, "n": 2}))

        store.close(successful=True)

        with result.SQLiteReader(os.path.join(ws.results_path, "results.db")) as reader:
            all_records = reader.read_all()
            assert len(all_records) == 3

            # the duplicate rec-1 should keep the original value from batch 1
            rec1 = reader.read("rec-1")
            assert rec1 is not None
            assert rec1["item"]["batch"] == 1

    def test_no_skip_duplicates_across_batch_boundary(self, ws):
        """verify that duplicates spanning two batches are replaced correctly."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            skip_duplicates=False,
            batch_size=2,
        )
        store.prepare()

        # batch 1: rec-0, rec-1 (auto-flushed)
        for i in range(2):
            envelope = result.Envelope(identifier=f"rec-{i}", schema="test", item={"batch": 1, "n": i})
            store.store(f"rec-{i}", envelope)

        # batch 2: rec-1 (updated), rec-2 (auto-flushed)
        store.store("rec-1", result.Envelope(identifier="rec-1", schema="test", item={"batch": 2, "n": 1}))
        store.store("rec-2", result.Envelope(identifier="rec-2", schema="test", item={"batch": 2, "n": 2}))

        store.close(successful=True)

        with result.SQLiteReader(os.path.join(ws.results_path, "results.db")) as reader:
            all_records = reader.read_all()
            assert len(all_records) == 3

            # the duplicate rec-1 should have the updated value from batch 2
            rec1 = reader.read("rec-1")
            assert rec1 is not None
            assert rec1["item"]["batch"] == 2

    def test_close_removes_wal_sidecar_files(self, ws):
        """verify that WAL sidecar files are cleaned up after close."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
        store.prepare()

        # capture the temp path before close (close may clear state)
        temp_path = store.temp_db_file_path

        envelope = result.Envelope(identifier="rec-0", schema="test", item={"n": 0})
        store.store("rec-0", envelope)

        store.close(successful=True)

        db_path = os.path.join(ws.results_path, "results.db")
        assert os.path.exists(db_path)
        assert not os.path.exists(temp_path + "-wal")
        assert not os.path.exists(temp_path + "-shm")

    def test_prepare_cleans_stale_sidecar_files(self, ws):
        """verify that prepare() removes stale WAL sidecar files from a previous run."""
        results_dir = ws.results_path
        temp_db = os.path.join(results_dir, "results.db.tmp")
        temp_wal = temp_db + "-wal"
        temp_shm = temp_db + "-shm"

        # simulate leftover files from an interrupted run
        for path in (temp_db, temp_wal, temp_shm):
            with open(path, "w") as f:
                f.write("stale")

        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
        store.prepare()

        assert not os.path.exists(temp_db)
        assert not os.path.exists(temp_wal)
        assert not os.path.exists(temp_shm)

    def test_store_after_close_raises(self, ws):
        """verify that store() raises RuntimeError after close() has been called."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
        store.prepare()

        envelope = result.Envelope(identifier="rec-0", schema="test", item={"n": 0})
        store.store("rec-0", envelope)
        store.close(successful=True)

        with pytest.raises(RuntimeError, match="store\\(\\) called after close\\(\\)"):
            store.store("rec-1", result.Envelope(identifier="rec-1", schema="test", item={"n": 1}))
