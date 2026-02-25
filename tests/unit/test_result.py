from __future__ import annotations

import datetime
import pytest
import os
import shutil

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


class TestFlatFileReader:
    def test_ids_yields_all_identifiers(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        ws = flat_file_existing_workspace
        reader = result.FlatFileReader(ws.results_path)

        ids = list(reader.ids())

        assert sorted(ids) == ["dummy-result-1", "dummy-result-2"]

    def test_ids_with_glob_pattern(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        ws = flat_file_existing_workspace
        reader = result.FlatFileReader(ws.results_path)

        # filter with pattern
        ids = list(reader.ids("dummy-result-1*"))
        assert ids == ["dummy-result-1"]

        # wildcard matches all
        ids = list(reader.ids("*"))
        assert sorted(ids) == ["dummy-result-1", "dummy-result-2"]

    def test_ids_handles_nested_directories(self, ws: workspace.Workspace) -> None:
        # create nested structure
        store_strategy = result.StoreStrategy.FLAT_FILE
        with result.Writer(ws, result_state_policy=result.ResultStatePolicy.DELETE, store_strategy=store_strategy) as writer:
            writer.write(
                identifier="nested/path/result-1",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"dummy": "nested-1"}},
            )
            writer.write(
                identifier="top-level-result",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"dummy": "top"}},
            )

        reader = result.FlatFileReader(ws.results_path)
        ids = list(reader.ids())

        assert sorted(ids) == ["nested/path/result-1", "top-level-result"]

    def test_ids_with_literal_filter(self, ws: workspace.Workspace) -> None:
        # create workspace with nested IDs similar to rhel provider
        store_strategy = result.StoreStrategy.FLAT_FILE
        with result.Writer(ws, result_state_policy=result.ResultStatePolicy.DELETE, store_strategy=store_strategy) as writer:
            writer.write(
                identifier="rhel:6/cve-2021-30473",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2021-30473"}},
            )
            writer.write(
                identifier="rhel:7/cve-2021-30473",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2021-30473"}},
            )
            writer.write(
                identifier="rhel:6/cve-2024-12345",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2024-12345"}},
            )

        reader = result.FlatFileReader(ws.results_path)

        # case-insensitive substring match
        ids = sorted(reader.ids(literal_filter="CVE-2021-30473"))
        assert ids == ["rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]

        # lowercase also works
        ids = sorted(reader.ids(literal_filter="cve-2021-30473"))
        assert ids == ["rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]

        # partial match
        ids = sorted(reader.ids(literal_filter="rhel:6"))
        assert ids == ["rhel:6/cve-2021-30473", "rhel:6/cve-2024-12345"]

    def test_read_returns_envelope(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        ws = flat_file_existing_workspace
        reader = result.FlatFileReader(ws.results_path)

        envelope = reader.read("dummy-result-1")

        assert isinstance(envelope, result.Envelope)
        assert envelope.identifier == "dummy-result-1"
        assert envelope.item == {"Vulnerability": {"dummy": "result-1"}}

    def test_read_returns_none_for_missing(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        ws = flat_file_existing_workspace
        reader = result.FlatFileReader(ws.results_path)

        envelope = reader.read("nonexistent")

        assert envelope is None

    def test_context_manager(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        ws = flat_file_existing_workspace

        with result.FlatFileReader(ws.results_path) as reader:
            ids = list(reader.ids())

        assert len(ids) == 2


class TestSQLiteReaderIds:
    def test_ids_yields_all_identifiers(self, sqlite_existing_workspace: workspace.Workspace) -> None:
        ws = sqlite_existing_workspace
        db_path = os.path.join(ws.results_path, "results.db")

        with result.SQLiteReader(db_path) as reader:
            ids = list(reader.ids())

        assert sorted(ids) == ["dummy-result-1", "dummy-result-2"]

    def test_ids_with_glob_pattern(self, sqlite_existing_workspace: workspace.Workspace) -> None:
        ws = sqlite_existing_workspace
        db_path = os.path.join(ws.results_path, "results.db")

        with result.SQLiteReader(db_path) as reader:
            # filter with pattern
            ids = list(reader.ids("dummy-result-1*"))
            assert ids == ["dummy-result-1"]

            # wildcard matches all
            ids = list(reader.ids("*"))
            assert sorted(ids) == ["dummy-result-1", "dummy-result-2"]

    def test_ids_with_literal_filter(self, ws: workspace.Workspace) -> None:
        # create workspace with nested IDs similar to rhel provider
        store_strategy = result.StoreStrategy.SQLITE
        with result.Writer(ws, result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE, store_strategy=store_strategy) as writer:
            writer.write(
                identifier="rhel:6/cve-2021-30473",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2021-30473"}},
            )
            writer.write(
                identifier="rhel:7/cve-2021-30473",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2021-30473"}},
            )
            writer.write(
                identifier="rhel:6/cve-2024-12345",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2024-12345"}},
            )

        db_path = os.path.join(ws.results_path, "results.db")

        with result.SQLiteReader(db_path) as reader:
            # case-insensitive substring match
            ids = sorted(reader.ids(literal_filter="CVE-2021-30473"))
            assert ids == ["rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]

            # lowercase also works
            ids = sorted(reader.ids(literal_filter="cve-2021-30473"))
            assert ids == ["rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]

            # partial match
            ids = sorted(reader.ids(literal_filter="rhel:6"))
            assert ids == ["rhel:6/cve-2021-30473", "rhel:6/cve-2024-12345"]

    def test_read(self, sqlite_existing_workspace: workspace.Workspace) -> None:
        ws = sqlite_existing_workspace
        db_path = os.path.join(ws.results_path, "results.db")

        with result.SQLiteReader(db_path) as reader:
            envelope = reader.read("dummy-result-1")

        assert envelope is not None
        assert isinstance(envelope, result.Envelope)
        assert envelope.identifier == "dummy-result-1"

    def test_read_returns_none_for_missing(self, sqlite_existing_workspace: workspace.Workspace) -> None:
        ws = sqlite_existing_workspace
        db_path = os.path.join(ws.results_path, "results.db")

        with result.SQLiteReader(db_path) as reader:
            envelope = reader.read("nonexistent")

        assert envelope is None


class TestReader:
    def test_auto_detects_flat_file(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        with result.Reader(flat_file_existing_workspace) as reader:
            assert isinstance(reader._store, result.FlatFileReader)
            ids = list(reader.ids())
            assert sorted(ids) == ["dummy-result-1", "dummy-result-2"]

    def test_auto_detects_sqlite(self, sqlite_existing_workspace: workspace.Workspace) -> None:
        with result.Reader(sqlite_existing_workspace) as reader:
            assert isinstance(reader._store, result.SQLiteReader)
            ids = list(reader.ids())
            assert sorted(ids) == ["dummy-result-1", "dummy-result-2"]

    def test_read_returns_envelope(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        with result.Reader(flat_file_existing_workspace) as reader:
            envelope = reader.read("dummy-result-1")
            assert envelope is not None
            assert envelope.identifier == "dummy-result-1"

    def test_read_returns_none_for_missing(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        with result.Reader(flat_file_existing_workspace) as reader:
            envelope = reader.read("nonexistent")
            assert envelope is None

    def test_store_property_raises_outside_context(self, flat_file_existing_workspace: workspace.Workspace) -> None:
        reader = result.Reader(flat_file_existing_workspace)
        with pytest.raises(RuntimeError, match="Reader not initialized"):
            _ = reader.store

    def test_ids_with_literal_filter(self, ws: workspace.Workspace) -> None:
        # create workspace with nested IDs
        store_strategy = result.StoreStrategy.FLAT_FILE
        with result.Writer(ws, result_state_policy=result.ResultStatePolicy.DELETE, store_strategy=store_strategy) as writer:
            writer.write(
                identifier="rhel:6/cve-2021-30473",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2021-30473"}},
            )
            writer.write(
                identifier="rhel:7/cve-2021-30473",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2021-30473"}},
            )
            writer.write(
                identifier="rhel:6/cve-2024-12345",
                schema=schema.OSSchema(),
                payload={"Vulnerability": {"id": "cve-2024-12345"}},
            )

        with result.Reader(ws) as reader:
            # case-insensitive substring match
            ids = sorted(reader.ids(literal_filter="CVE-2021-30473"))
            assert ids == ["rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]
