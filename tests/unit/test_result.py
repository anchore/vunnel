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
                workspace.File(digest="fc882c085f58a6b4", path="results/dummy-result-3.json", algorithm="xxh64"),
                workspace.File(digest="7811995c51f2fdd0", path="results/dummy-result-4.json", algorithm="xxh64"),
            ],
            2,
        ),
        (
            result.ResultStatePolicy.KEEP,
            [
                workspace.File(digest="903bd98818e2382e", path="results/dummy-result-1.json", algorithm="xxh64"),
                workspace.File(digest="19d53931485fa9d0", path="results/dummy-result-2.json", algorithm="xxh64"),
                workspace.File(digest="fc882c085f58a6b4", path="results/dummy-result-3.json", algorithm="xxh64"),
                workspace.File(digest="7811995c51f2fdd0", path="results/dummy-result-4.json", algorithm="xxh64"),
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
