import json
import os
import uuid
from datetime import datetime

import pytest

from vunnel import provider, schema, workspace


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
        return f"{self.input}/dummy-input-1.json"

    def assert_input_file(self, exists: bool = True):
        assert_path(self.input_file, exists)

    def assert_result_file(self, exists: bool = True):
        assert_path(os.path.join(self.results, "dummy-00000.json"), exists)

    def assert_state_file(self, exists: bool = True):
        assert_path(os.path.join(self.root, "state.json"), exists)

    def update(self):
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

        return ["http://localhost:8000/dummy-input-1.json"]


@pytest.fixture
def dummy_file():
    def apply(d: str):
        prefix = str(uuid.uuid4())[:8]
        path = f"{d}/random-{prefix}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"prefix": prefix}, f)
        return path

    return apply


@pytest.fixture
def dummy_provider(tmpdir):
    def apply(populate=True, use_dir=None, **kwargs):
        if not use_dir:
            use_dir = tmpdir
        # create a dummy provider
        subject = DummyProvider(root=use_dir, **kwargs)

        if populate:
            # update the provider
            subject.populate()

            # check that the input and results are populated
            assert os.path.exists(subject.input_file)
            existing_results = os.listdir(subject.results)
            assert len(existing_results) > 0
        else:
            subject._create_workspace()

        return subject

    return apply


def test_provider_clear_input(dummy_provider):
    subject = dummy_provider()
    original_state = workspace.WorkspaceState.read(root=subject.root)

    # clear the input
    subject.clear_input()

    subject.assert_input_file(exists=False)
    subject.assert_result_file(exists=True)

    # ensure the URLs are still populated
    new_state = workspace.WorkspaceState.read(root=subject.root)
    assert original_state.urls == new_state.urls
    assert len(original_state.urls) > 0

    # ensure the results file listing is cleared
    assert len(new_state.input.files) == 0


def test_provider_clear_results(dummy_provider):
    subject = dummy_provider()
    original_state = workspace.WorkspaceState.read(root=subject.root)

    # clear the results
    subject.clear_results()

    subject.assert_input_file(exists=True)
    subject.assert_result_file(exists=False)

    # ensure the URLs are still populated
    new_state = workspace.WorkspaceState.read(root=subject.root)
    assert original_state.urls == new_state.urls
    assert len(original_state.urls) > 0

    # ensure the results file listing is cleared
    assert len(new_state.results.files) == 0


def test_provider_clear(dummy_provider):
    subject = dummy_provider()

    # clear the provider
    subject.clear()

    subject.assert_input_file(exists=False)
    subject.assert_result_file(exists=False)


def test_clear_existing_state(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.DELETE,
        existing_results=provider.ResultStatePolicy.DELETE,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy)

    dummy_input_path = dummy_file(subject.input)
    dummy_results_path = dummy_file(subject.results)

    # check that the input and results are populated
    assert os.path.exists(dummy_input_path)
    assert os.path.exists(dummy_results_path)

    subject.populate()

    # check that existing results no longer exist
    assert not os.path.exists(dummy_input_path)
    assert not os.path.exists(dummy_results_path)


def test_keep_existing_state(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy)

    dummy_input_path = dummy_file(subject.input)
    dummy_results_path = dummy_file(subject.results)

    # check that the input and results are populated
    assert os.path.exists(dummy_input_path)
    assert os.path.exists(dummy_results_path)

    subject.populate()

    # check that existing results still exist
    assert os.path.exists(dummy_input_path)
    assert os.path.exists(dummy_results_path)


def test_keep_existing_state_until_write(dummy_provider, dummy_file):
    policy = provider.RuntimeConfig(
        existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy, errors=1)

    dummy_input_path = dummy_file(subject.input)
    dummy_results_path = dummy_file(subject.results)

    # check that the input and results are populated
    assert os.path.exists(dummy_input_path)
    assert os.path.exists(dummy_results_path)

    with pytest.raises(RuntimeError):
        subject.populate()

    assert not os.path.exists(dummy_input_path)  # should be deleted
    assert os.path.exists(dummy_results_path)  # should still exist

    # successful
    subject.populate()

    assert not os.path.exists(dummy_results_path)  # should now be deleted


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

    dummy_input_path = dummy_file(subject.input)
    dummy_results_path = dummy_file(subject.results)

    # check that the input and results are populated
    assert_path(dummy_input_path, exists=True)
    assert_path(dummy_results_path, exists=True)

    with pytest.raises(RuntimeError):
        subject.populate()

    assert_path(dummy_input_path, exists=True)
    assert_path(dummy_results_path, exists=True)

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

    dummy_input_path = dummy_file(subject.input)
    dummy_results_path = dummy_file(subject.results)

    # check that the input and results are populated
    assert_path(dummy_input_path, exists=True)
    assert_path(dummy_results_path, exists=True)

    with pytest.raises(RuntimeError):
        subject.populate()

    assert_path(dummy_input_path, exists=False)
    assert_path(dummy_results_path, exists=False)

    subject.assert_state_file(exists=False)


def test_keep_state_on_multiple_failures(dummy_provider, dummy_file, tmpdir):
    policy = provider.RuntimeConfig(
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.FAIL,
            input=provider.InputStatePolicy.KEEP,
            results=provider.ResultStatePolicy.KEEP,
        ),
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider(use_dir=tmpdir)  # create state file and workspace with input and results
    assert_dummy_workspace_state(subject)

    subject = dummy_provider(use_dir=tmpdir, populate=False, runtime_cfg=policy, errors=1)

    with pytest.raises(RuntimeError):
        subject.populate()

    assert_dummy_workspace_state(subject)


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

    dummy_input_path = dummy_file(subject.input)
    dummy_results_path = dummy_file(subject.results)

    # check that the input and results are populated
    assert_path(dummy_input_path, exists=True)
    assert_path(dummy_results_path, exists=True)

    subject.populate()

    assert_path(dummy_input_path, exists=False)
    assert_path(dummy_results_path, exists=False)

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

    subject.populate()

    assert subject.count == 2
    assert_dummy_workspace_state(subject)


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
        subject.populate()

    assert subject.count == 2

    subject.assert_state_file(exists=False)


def test_catalog_workspace(dummy_provider):
    subject = dummy_provider()
    assert_dummy_workspace_state(subject)


def assert_dummy_workspace_state(subject, has_input=True, has_results=True):
    current_state, dummy_ts = read_workspace_state(subject)

    expected_state = workspace.WorkspaceState(
        provider="dummy",
        urls=["http://localhost:8000/dummy-input-1.json"],
        input=workspace.FileListing(
            files=[
                workspace.FileState(
                    path="dummy-input-1.json",
                    digests=[
                        "xxh64:f907da5a37987674",
                        "sha256:2fa8fd006977f562942a7e0582bcdde36ebca8e284230d601bd14e78234a1bfa",
                    ],
                    modified=dummy_ts,
                ),
            ],
            timestamp=dummy_ts,
        ),
        results=workspace.FileListing(
            files=[
                workspace.FileState(
                    path="dummy-00000.json",
                    digests=[
                        "xxh64:dc7f0c9c83aab9b0",
                        "sha256:7a556fcc7a307cc5a896ef7ef1827a82298546c62e8c76706adf6561bb5e1dc1",
                    ],
                    modified=dummy_ts,
                )
            ],
            timestamp=dummy_ts,
        ),
        schema=schema.Schema(
            version="1.0.0",
            url="https://raw.githubusercontent.com/anchore/vunnel/main/schema/provider-workspace-state/schema-1.0.0.json",
        ),
    )

    if not has_input:
        expected_state.input.files = []
        expected_state.input.timestamp = None

    if not has_results:
        expected_state.results.files = []
        expected_state.results.timestamp = None

    assert current_state == expected_state


def read_workspace_state(subject: provider.Provider) -> workspace.WorkspaceState:

    current_state = workspace.WorkspaceState.read(root=subject.root)

    dummy_ts = datetime.strptime("2022-12-16T20:51:59+00:00", "%Y-%m-%dT%H:%M:%S%z")

    # check that current input and result timestamps that conform to RFC3339
    def validate_ts(ts: datetime):
        assert ts
        assert ts.tzinfo is not None

    if current_state.input.timestamp:
        validate_ts(current_state.input.timestamp)
        current_state.input.timestamp = dummy_ts

    if current_state.results.timestamp:
        validate_ts(current_state.results.timestamp)
        current_state.results.timestamp = dummy_ts

    # validate all file listing timestamps
    for file in current_state.input.files:
        validate_ts(file.modified)
        file.modified = dummy_ts

    for file in current_state.results.files:
        validate_ts(file.modified)
        file.modified = dummy_ts

    return current_state, dummy_ts
