from __future__ import annotations

import ast
import dataclasses
import datetime
import importlib
import inspect
import os
import pkgutil
import shutil
import textwrap

import orjson
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

    def test_close_syncs_database_before_moving_it(self, ws, mocker):
        """verify that close() syncs the temporary database, which is written without syncing, before moving it."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
        store.prepare()
        temp_path = store.temp_db_file_path

        envelope = result.Envelope(identifier="rec-0", schema="test", item={"n": 0})
        store.store("rec-0", envelope)

        calls = []
        fsync = mocker.patch.object(result.os, "fsync", side_effect=lambda fd: calls.append(("fsync", os.path.exists(temp_path))))
        move = mocker.patch.object(result.shutil, "move", side_effect=lambda src, dst: calls.append(("move", src)))

        store.close(successful=True)

        assert fsync.call_count == 1
        assert move.call_count == 1
        assert calls == [("fsync", True), ("move", temp_path)]

    def test_close_unsuccessful_does_not_sync(self, ws, mocker):
        """verify that a failed run deletes the temporary database without syncing it."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
        store.prepare()
        temp_path = store.temp_db_file_path

        envelope = result.Envelope(identifier="rec-0", schema="test", item={"n": 0})
        store.store("rec-0", envelope)

        fsync = mocker.patch.object(result.os, "fsync")
        store.close(successful=False)

        assert fsync.call_count == 0
        assert not os.path.exists(temp_path)
        assert not os.path.exists(os.path.join(ws.results_path, "results.db"))

    def test_temporary_database_has_no_journal(self, ws):
        """verify that the temporary database is written without a journal or syncing."""
        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
        store.prepare()
        conn, _ = store.connection()
        raw = conn.connection.dbapi_connection
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "off"
        assert raw.execute("PRAGMA synchronous").fetchone()[0] == 0
        store.close(successful=True)

    def test_close_without_writes_deletes_leftover_temporary_database(self, ws):
        """verify that a run that writes nothing deletes a killed run's temporary database instead of moving it into place."""
        db_path = os.path.join(ws.results_path, "results.db")
        with open(db_path, "w") as f:
            f.write("previous results")
        temp_db = os.path.join(ws.results_path, "results.db.tmp")
        with open(temp_db, "w") as f:
            f.write("left by a killed run")

        store = result.SQLiteStore(
            workspace=ws,
            result_state_policy=result.ResultStatePolicy.KEEP,
        )
        store.close(successful=True)

        assert not os.path.exists(temp_db)
        with open(db_path) as f:
            assert f.read() == "previous results"

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


# modules that are scripts rather than importable library code
_NOT_IMPORTABLE = {"vunnel.__main__", "vunnel.providers.mariner.generate_models"}


def _vunnel_dataclasses() -> list[type]:
    """every dataclass defined in an importable vunnel module"""
    classes = []
    for module_info in pkgutil.walk_packages(importlib.import_module("vunnel").__path__, "vunnel."):
        if module_info.name in _NOT_IMPORTABLE:
            continue
        module = importlib.import_module(module_info.name)
        for _, cls in inspect.getmembers(module, lambda o: inspect.isclass(o) and dataclasses.is_dataclass(o)):
            if cls.__module__ == module.__name__:
                classes.append(cls)
    return classes


def test_no_vunnel_dataclass_has_an_underscore_field():
    """the result stores serialize envelopes with orjson, which silently drops dataclass fields
    whose names start with "_" (dataclasses.asdict() kept them), so no payload may have one."""
    classes = _vunnel_dataclasses()
    offenders = [
        f"{cls.__module__}.{cls.__qualname__}.{f.name}" for cls in classes for f in dataclasses.fields(cls) if f.name.startswith("_")
    ]

    assert classes
    assert not offenders, f"orjson would drop these fields from results: {offenders}"


def _self_attributes_assigned(cls: type) -> set[str]:
    """names a class's own methods assign on self, via self.x = ... or (object.)__setattr__/setattr(self, "x", ...)"""
    names = set()
    for node in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(cls)))):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                names.add(target.attr)

        if isinstance(node, ast.Call) and len(node.args) >= 2:
            func = node.func
            is_setattr = (isinstance(func, ast.Name) and func.id == "setattr") or (isinstance(func, ast.Attribute) and func.attr == "__setattr__")
            obj, name = node.args[0], node.args[1]
            if is_setattr and isinstance(obj, ast.Name) and obj.id == "self" and isinstance(name, ast.Constant):
                names.add(name.value)
    return names


def test_no_vunnel_dataclass_sets_a_non_field_attribute():
    """the result stores serialize envelopes with orjson, which also emits instance attributes
    that are not dataclass fields (dataclasses.asdict() dropped them), so no payload's own methods
    (e.g. __post_init__) may set one."""
    classes = _vunnel_dataclasses()
    offenders = []
    for cls in classes:
        field_names = {f.name for f in dataclasses.fields(cls)}
        offenders += [f"{cls.__module__}.{cls.__qualname__}.{name}" for name in sorted(_self_attributes_assigned(cls) - field_names)]

    assert classes
    assert not offenders, f"orjson would add these attributes to results: {offenders}"


def test_self_attributes_assigned_finds_non_field_attributes():
    """the scan behind test_no_vunnel_dataclass_sets_a_non_field_attribute catches each way of setting one"""

    @dataclasses.dataclass(frozen=True)
    class Payload:
        name: str

        def __post_init__(self):
            object.__setattr__(self, "frozen_extra", 1)
            setattr(self, "setattr_extra", 2)  # noqa: B010

        def other(self):
            self.assigned_extra = 3  # type: ignore[misc]
            self.annotated_extra: int = 4  # type: ignore[misc]
            self.augmented_extra += 5  # type: ignore[attr-defined]

    assert _self_attributes_assigned(Payload) == {"frozen_extra", "setattr_extra", "assigned_extra", "annotated_extra", "augmented_extra"}


def test_envelope_serializes_like_asdict():
    """orjson.dumps(envelope) must match the dataclasses.asdict() output it replaced."""

    @dataclasses.dataclass
    class Inner:
        name: str
        versions: list[str]

    @dataclasses.dataclass
    class Payload:
        id: str
        inner: Inner
        extra: dict[str, object]

    env = result.Envelope(
        schema="https://example.com/schema.json",
        identifier="ns/CVE-2024-0001",
        item=Payload(id="CVE-2024-0001", inner=Inner(name="pkg", versions=["1.0", "2.0"]), extra={"k": [1, None]}),
    )

    assert orjson.dumps(env) == orjson.dumps(dataclasses.asdict(env))


def test_envelope_with_vunnel_payload_serializes_like_asdict():
    """orjson also emits instance attributes that are not dataclass fields (asdict() dropped
    them), so a real payload dataclass gaining one, e.g. in __post_init__, must fail here."""
    from vunnel.utils import vulnerability

    vuln = vulnerability.Vulnerability(
        Name="CVE-2024-0001",
        NamespaceName="alpine:3.20",
        Description="a description",
        Severity="High",
        Link="https://example.com/CVE-2024-0001",
        CVSS=[
            vulnerability.CVSS(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_metrics=vulnerability.CVSSBaseMetrics(
                    base_score=9.8,
                    exploitability_score=3.9,
                    impact_score=5.9,
                    base_severity="Critical",
                ),
                status="N/A",
            ),
        ],
        FixedIn=[
            # Module and VendorAdvisory are filled in by __post_init__
            vulnerability.FixedIn(
                Name="openssl",
                NamespaceName="alpine:3.20",
                VersionFormat="apk",
                Version="3.0.1-r0",
                Module=None,
                VendorAdvisory=None,
                Available=vulnerability.FixAvailability(Date="2024-01-02", Kind="advisory"),
            ),
        ],
    )
    env = result.Envelope(schema="https://example.com/schema.json", identifier="alpine:3.20/CVE-2024-0001", item=vuln)

    assert orjson.loads(orjson.dumps(env)) == dataclasses.asdict(env)

    # the guard works: a non-field attribute makes the outputs differ
    vuln.extra = "not a field"  # type: ignore[attr-defined]
    assert orjson.loads(orjson.dumps(env)) != dataclasses.asdict(env)
