from __future__ import annotations

import datetime

from vunnel import result, schema, workspace


def test_result_writer_flat_file(tmpdir):
    root = tmpdir
    ws = workspace.Workspace(root=root, name="nvd", create=True)
    store_strategy = result.StoreStrategy.FLAT_FILE
    with result.Writer(ws, store_strategy=store_strategy) as writer:
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

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1)

    state = ws.state()

    assert list(state.result_files(ws.path)) == [
        workspace.File(digest="15a391c356b028bd", path="results/dummy-result-1.json", algorithm="xxh64"),
        workspace.File(digest="773ff3e88c39e9db", path="results/dummy-result-2.json", algorithm="xxh64"),
    ]
    assert state.result_count(ws.path) == 2


def test_result_writer_sqlite(tmpdir):
    root = tmpdir
    ws = workspace.Workspace(root=root, name="nvd", create=True)
    store_strategy = result.StoreStrategy.SQLITE
    with result.Writer(ws, store_strategy=store_strategy) as writer:
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

    ws.record_state(timestamp=datetime.datetime.now(), urls=[], store=store_strategy, version=1)

    state = ws.state()

    # note: since the hash changes on each test run, just confirm the result file count, not the extra metadata
    assert len(list(state.result_files(ws.path))) == 1
    assert state.result_count(ws.path) == 2
