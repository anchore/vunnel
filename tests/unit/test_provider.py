from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from vunnel import provider, result, schema, workspace


def assert_path(path: str, exists: bool = True):
    assert os.path.exists(path) == exists


class DummyProvider(provider.Provider):
    def __init__(self, errors: int = 0, create_files=True, **kwargs):
        super().__init__(**kwargs)
        self.errors = errors
        self.count = 0
        self.config = {}
        self.create_files = create_files

    @classmethod
    def name(cls) -> str:
        return "dummy"

    @property
    def input_file(self):
        return f"{self.workspace.input_path}/dummy-input-1.json"

    def assert_state_file(self, exists: bool = True):
        assert_path(os.path.join(self.workspace.path, "state.json"), exists)

    def update(self, *args, **kwargs):
        self.count += 1
        if self.count <= self.errors:
            raise RuntimeError("dummy error")

        if self.create_files:
            # write some dummy data to the workspace input
            with open(self.input_file, "w", encoding="utf-8") as f:
                json.dump({"dummy": "input"}, f)

            # write some dummy data to the workspace results
            with self.results_writer() as writer:
                writer.write(
                    identifier="dummy-result-1",
                    schema=schema.OSSchema(),
                    payload={"Vulnerability": {"dummy": "result"}},
                )

        return ["http://localhost:8000/dummy-input-1.json"], 1


@pytest.fixture()
def dummy_provider(tmpdir):
    def apply(populate=True, use_dir=None, **kwargs):
        if not use_dir:
            use_dir = tmpdir
        # create a dummy provider
        subject = DummyProvider(root=use_dir, **kwargs)

        if populate:
            # update the provider
            subject.run()

            # check that the input and results are populated
            assert os.path.exists(subject.input_file)
            existing_results = os.listdir(subject.workspace.results_path)
            assert len(existing_results) > 0
        else:
            subject.workspace.create()

        return subject

    return apply


def test_clear_existing_state(dummy_provider):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.DELETE,
        existing_results=provider.ResultStatePolicy.DELETE,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy)
    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)

    subject.run()

    assert subject.workspace.clear_input.call_count == 1
    assert subject.workspace.clear_results.call_count == 1


def test_clear_existing_state_from_mismatched_versions(dummy_provider):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=True, runtime_cfg=policy)

    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace._clear_metadata = MagicMock(side_effect=subject.workspace._clear_metadata)
    subject.version = MagicMock(return_value=2)

    subject.run()

    assert subject.workspace.clear_input.call_count == 1
    assert subject.workspace.clear_results.call_count == 1
    assert subject.workspace._clear_metadata.call_count == 1


def test_keep_existing_state_from_matching_versions(dummy_provider):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=True, runtime_cfg=policy)

    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace._clear_metadata = MagicMock(side_effect=subject.workspace._clear_metadata)

    subject.run()

    assert subject.workspace.clear_input.call_count == 0
    assert subject.workspace.clear_results.call_count == 0
    assert subject.workspace._clear_metadata.call_count == 0


def test_keep_existing_state(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy)
    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)

    subject.run()

    assert subject.workspace.clear_input.call_count == 0
    assert subject.workspace.clear_results.call_count == 0


def test_keep_existing_state_until_write(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=1)
    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)

    with pytest.raises(RuntimeError):
        subject.run()

    assert subject.workspace.clear_results.call_count == 0

    # successful
    subject.run()

    assert subject.workspace.clear_results.call_count == 1


def test_fail_on_failure(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.FAIL,
            input=provider.InputStatePolicy.KEEP,
            results=provider.ResultStatePolicy.KEEP,
        ),
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=1)
    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)

    with pytest.raises(RuntimeError):
        subject.run()

    assert subject.workspace.clear_input.call_count == 0
    assert subject.workspace.clear_results.call_count == 0

    subject.assert_state_file(exists=False)


def test_clear_state_on_failure(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.FAIL,
            input=provider.InputStatePolicy.DELETE,
            results=provider.ResultStatePolicy.DELETE,
        ),
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=1)
    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)

    with pytest.raises(RuntimeError):
        subject.run()

    assert subject.workspace.clear_input.call_count == 1
    assert subject.workspace.clear_results.call_count == 1

    subject.assert_state_file(exists=False)


def test_keep_state_on_multiple_failures(dummy_provider, dummy_file, tmpdir):
    policy = provider.RuntimeConfig(
        result_store=result.StoreStrategy.FLAT_FILE,
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.FAIL,
            input=provider.InputStatePolicy.KEEP,
            results=provider.ResultStatePolicy.KEEP,
        ),
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(use_dir=tmpdir)  # create state file and workspace with input and results
    assert_dummy_workspace_state(subject.workspace)

    subject = dummy_provider(use_dir=tmpdir, populate=False, runtime_cfg=policy, errors=1)

    with pytest.raises(RuntimeError):
        subject.run()

    assert_dummy_workspace_state(subject.workspace)


def test_skip_on_failure(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.SKIP,
            input=provider.InputStatePolicy.DELETE,
            results=provider.ResultStatePolicy.DELETE,
        ),
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=1)
    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)

    subject.run()

    assert subject.workspace.clear_input.call_count == 1
    assert subject.workspace.clear_results.call_count == 1

    subject.assert_state_file(exists=False)


def test_retry_on_failure(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.RETRY,
            retry_delay=0,
            retry_count=1,
        ),
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=1)

    subject.run()

    assert subject.count == 2
    assert_dummy_workspace_state(subject.workspace)


def test_retry_on_failure_max_attempts(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.RETRY,
            retry_delay=0,
            retry_count=1,
        ),
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=2, create_files=False)

    with pytest.raises(RuntimeError):
        subject.run()

    assert subject.count == 2

    subject.assert_state_file(exists=False)


def assert_dummy_workspace_state(ws):
    current_state = workspace.State.read(root=ws.path)

    # ignore timestamp (make certain it exists)
    assert current_state.timestamp is not None
    current_state.timestamp = None

    expected_state = workspace.State(
        store=result.StoreStrategy.FLAT_FILE.value,
        provider="dummy",
        urls=["http://localhost:8000/dummy-input-1.json"],
        listing=workspace.File(digest="1e119ae45b38b28f", algorithm="xxh64", path="checksums"),
        timestamp=None,
        schema=schema.ProviderStateSchema(),
    )

    assert current_state == expected_state
