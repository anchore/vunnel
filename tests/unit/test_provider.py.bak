from __future__ import annotations

import os
import datetime
import tarfile
import json
import logging
import random
import string
import hashlib
import shutil
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
import zstandard

from vunnel import provider, result, schema, workspace, distribution
from vunnel.utils import hasher, archive


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

    def _fetch_or_use_results_archive(self):
        urls, count = self.update()
        return urls, count, datetime.datetime(2021, 1, 1, 0, 0, 0)

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


class DummyProviderWithZeroCountOnUpdate(DummyProvider):
    def _fetch_or_use_results_archive(self):
        urls, _ = self.update()
        return urls, 0, datetime.datetime(2021, 1, 1, 0, 0, 0)


def get_random_string(length=10):
    characters = string.ascii_letters + string.digits
    return "".join(random.choice(characters) for _ in range(length))


@pytest.fixture()
def dummy_provider(tmpdir):
    def apply(populate=True, use_dir=None, **kwargs) -> provider.Provider:
        if not use_dir:
            use_dir = tmpdir + get_random_string()
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


@pytest.fixture()
def dummy_provider_with_zero_count_on_update(tmpdir):
    def apply(populate=True, use_dir=None, **kwargs) -> provider.Provider:
        if not use_dir:
            use_dir = tmpdir + get_random_string()
        # create a dummy provider
        subject = DummyProviderWithZeroCountOnUpdate(root=use_dir, **kwargs)

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


def test_clear_existing_state_from_mismatched_distribution_versions(dummy_provider):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        import_results_enabled=True,
        import_results_path="{provider_name}/listing.json",
        import_results_host="http://localhost",
    )

    subject = dummy_provider(populate=True, runtime_cfg=policy)

    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace._clear_metadata = MagicMock(side_effect=subject.workspace._clear_metadata)
    subject.distribution_version = MagicMock(return_value=2)

    subject.run()

    assert subject.workspace.clear_input.call_count == 1
    assert subject.workspace.clear_results.call_count == 1
    assert subject.workspace._clear_metadata.call_count == 1


def test_mismatched_distribution_versions_has_no_effect_when_import_disabled(dummy_provider):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        import_results_enabled=False,
    )

    subject = dummy_provider(populate=True, runtime_cfg=policy)

    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace._clear_metadata = MagicMock(side_effect=subject.workspace._clear_metadata)
    subject.distribution_version = MagicMock(return_value=2)

    subject.run()

    assert subject.workspace.clear_input.call_count == 0
    assert subject.workspace.clear_results.call_count == 0
    assert subject.workspace._clear_metadata.call_count == 0


def test_mismatched_versions_has_no_effect_when_import_enabled(dummy_provider):
    policy = provider.RuntimeConfig(
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        import_results_enabled=True,
        import_results_path="{provider_name}/listing.json",
        import_results_host="http://localhost",
    )

    subject = dummy_provider(populate=True, runtime_cfg=policy)

    # track calls without affecting behavior (get mock tracking abilities without mocking)
    subject.workspace.clear_input = MagicMock(side_effect=subject.workspace.clear_input)
    subject.workspace.clear_results = MagicMock(side_effect=subject.workspace.clear_results)
    subject.workspace._clear_metadata = MagicMock(side_effect=subject.workspace._clear_metadata)
    subject.version = MagicMock(return_value=2)

    subject.run()

    assert subject.workspace.clear_input.call_count == 0
    assert subject.workspace.clear_results.call_count == 0
    assert subject.workspace._clear_metadata.call_count == 0


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


def listing_tar_entry(
    tmpdir: str,
    port: int,
    dummy_provider_factory,
    archive_name: str | None = None,
    archive_checksum: str | None = None,
    results_checksum: str | None = None,
) -> tuple[str, str, distribution.ListingEntry, str]:
    if not archive_name:
        archive_name = "results.tar.gz"

    policy = provider.RuntimeConfig(
        result_store=result.StoreStrategy.SQLITE,
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
    )

    subject = dummy_provider_factory(populate=True, runtime_cfg=policy)
    subject.run()

    dest = os.path.join(tmpdir, subject.name())
    os.makedirs(dest, exist_ok=True)

    # tar up the subject.workspace.path into a tarfile
    shutil.rmtree(subject.workspace.input_path, ignore_errors=True)
    tarfile_path = os.path.join(dest, archive_name)
    with _get_tar_writer_obj(tarfile_path) as tar:
        tar.add(subject.workspace.path, arcname=subject.name())

    if not archive_checksum:
        archive_checksum = hasher.Method.XXH64.digest(tarfile_path, label=True)

    if not results_checksum:
        workspace_state: workspace.State = subject.workspace.state()
        results_checksum = workspace_state.listing.digest

    listing_entry = distribution.ListingEntry(
        built="2021-01-01T00:00:00Z",
        distribution_version=1,
        url=f"http://localhost:{port}/{subject.name()}/{archive_name}",
        distribution_checksum=archive_checksum,
        enclosed_checksum=results_checksum,
    )

    listing_doc = distribution.ListingDocument(available={"1": [listing_entry]}, provider=subject.name())
    listing_url = f"http://localhost:{port}/{subject.name()}/listing.json"

    # write out the listing document
    listing_path = os.path.join(dest, "listing.json")
    with open(listing_path, "w") as f:
        json.dump(listing_doc.to_dict(), f)

    return tarfile_path, listing_url, listing_entry, listing_path


def _get_tar_writer_obj(tarfile_path):
    if tarfile_path.endswith(".tar.zst"):
        return _get_tar_zst_writer_obj(tarfile_path)

    elif tarfile_path.endswith(".tar"):
        return tarfile.open(tarfile_path, "w:")

    if tarfile_path.endswith(".tar.gz"):
        return tarfile.open(tarfile_path, "w:gz")

    raise ValueError("unsupported tarfile extension")


@contextmanager
def _get_tar_zst_writer_obj(tarfile_path):
    fileobj = zstandard.ZstdCompressor().stream_writer(open(tarfile_path, "wb"))
    tf = None
    try:
        tf = tarfile.open(tarfile_path, "w|", fileobj=fileobj)
        yield tf
    finally:
        if tf:
            tf.close()
        fileobj.close()


@pytest.mark.parametrize(
    "archive_name,archive_checksum,raises_type",
    (
        ("results.tar.gz", None, None),
        ("results.tar.zst", None, None),
        ("results.tar", None, None),
        ("results.tar.gz", "sha256:1234567890abcdef", ValueError),
    ),
)
@patch("requests.get")
def test_fetch_listing_entry_archive(mock_requests, tmpdir, dummy_provider, archive_name, archive_checksum, raises_type):
    port = 8080

    tarfile_path, listing_url, listing_entry, listing_path = listing_tar_entry(
        tmpdir, port, dummy_provider_factory=dummy_provider, archive_name=archive_name, archive_checksum=archive_checksum
    )

    with open(tarfile_path, "rb") as f:
        content = f.read()

    mock_requests.return_value.status_code = 200
    mock_requests.return_value.iter_content.return_value = [content]

    logger = logging.getLogger("test")

    if not raises_type:
        unarchived_dir = provider._fetch_listing_entry_archive(entry=listing_entry, dest=tmpdir, logger=logger)

        # assert the unarchived_dir path contents is the same as the tarfile contents
        compare_dir_tar(tmpdir, unarchived_dir, tarfile_path)

        args, _ = mock_requests.call_args
        assert args == (listing_entry.url,)
    else:
        with pytest.raises(raises_type):
            provider._fetch_listing_entry_archive(entry=listing_entry, dest=tmpdir, logger=logger)


def checksum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def compare_dir_tar(tmpdir, dir_path, tar_path):
    temp_dir = os.path.join(tmpdir, "extracted")

    archive.extract(tar_path, temp_dir)

    dir_checksums = {}
    tar_checksums = {}

    # walk through directory and calculate checksums
    for root, dirs, files in os.walk(dir_path):
        for name in files:
            rel_dir = os.path.relpath(root, dir_path)
            rel_file = os.path.join(rel_dir, name)
            file_path = os.path.join(root, name)
            dir_checksums[rel_file] = checksum(file_path)

    # walk through extracted tar contents and calculate checksums
    for root, dirs, files in os.walk(temp_dir):
        for name in files:
            rel_dir = os.path.relpath(root, temp_dir)
            rel_file = os.path.join(rel_dir, name)
            file_path = os.path.join(root, name)
            tar_checksums[rel_file] = checksum(file_path)

    # cleanup temporary directory
    for root, dirs, files in os.walk(temp_dir, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(temp_dir)

    assert dir_checksums == tar_checksums, "Directory and TAR file contents differ"


@patch("requests.get")
def test_fetch_listing_document(mock_requests, tmpdir, dummy_provider):
    port = 8080

    policy = provider.RuntimeConfig(
        result_store=result.StoreStrategy.SQLITE,
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        import_results_enabled=True,
        import_results_path="{provider_name}/listing.json",
        import_results_host="http://localhost",
    )

    tarfile_path, listing_url, entry, listing_path = listing_tar_entry(tmpdir, port, dummy_provider_factory=dummy_provider)

    subject = dummy_provider(populate=False, runtime_cfg=policy)
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.json.return_value = json.loads(open(listing_path, "r").read())

    doc = subject._fetch_listing_document()

    args, _ = mock_requests.call_args
    assert args == ("http://localhost/dummy/listing.json",)


@patch("requests.get")
def test_prep_workspace_from_listing_entry(mock_requests, tmpdir, dummy_provider):
    provider = dummy_provider(populate=False)
    tarfile_path, listing_url, entry, listing_path = listing_tar_entry(
        tmpdir=tmpdir, port=8080, dummy_provider_factory=dummy_provider
    )

    with open(tarfile_path, "rb") as f:
        content = f.read()
        mock_requests.return_value.status_code = 200
        mock_requests.return_value.iter_content.return_value = [content]

    with tarfile.open(tarfile_path, "r:gz") as tar:
        list_of_files = tar.getnames()

    provider._prep_workspace_from_listing_entry(entry=entry)

    state = provider.workspace.state()

    assert state.stale

    provider.workspace.validate_checksums()

    for file in list_of_files:
        assert os.path.exists(os.path.join(provider.workspace.path, "..", file))

    # what this does is:
    # 1. it receives a listing entry and makes a call to fetch and unarchive it
    # 2. it creates a temp workspace around the unarchive path
    # 3. it validates the checksums on the temp workspace
    # 4. it overlays it's current workspace with the temp workspace


@patch("requests.get")
def test_fetch_or_use_results_archive(mock_requests, tmpdir, dummy_provider):
    port = 8080

    tarfile_path, listing_url, entry, listing_path = listing_tar_entry(
        tmpdir=tmpdir, port=port, dummy_provider_factory=dummy_provider
    )
    # fetch the tar file
    tarfile_bytes = None
    with open(tarfile_path, "rb") as f:
        tarfile_bytes = f.read()

    policy = provider.RuntimeConfig(
        result_store=result.StoreStrategy.SQLITE,
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        import_results_enabled=True,
        import_results_path="{provider_name}/listing.json",
        import_results_host=f"http://localhost:{port}",
    )

    subject = dummy_provider(populate=False, runtime_cfg=policy)

    def handle_get_requests(url, *args, **kwargs):
        listing_response = MagicMock()
        listing_response.status_code = 200
        listing_response.raise_for_status.side_effect = None
        listing_response.json.return_value = json.loads(open(listing_path, "r").read())

        entry_response = MagicMock()
        entry_response.status_code = 200
        entry_response.raise_for_status.side_effect = None
        entry_response.iter_content.return_value = [tarfile_bytes]

        not_found_response = MagicMock()
        not_found_response.status_code = 404
        not_found_response.raise_for_status.side_effect = Exception("404")

        if url == f"http://localhost:{port}/{subject.name()}/listing.json":
            return listing_response
        elif url == entry.url:
            return entry_response
        else:
            return not_found_response

    mock_requests.side_effect = handle_get_requests

    urls, count, start = subject._fetch_or_use_results_archive()
    assert urls == ["http://localhost:8000/dummy-input-1.json"]
    assert count == 1
    assert start == datetime.datetime(2021, 1, 1, 0, 0, 0)


@patch("requests.get")
def test_fetch_results_keeps_original_metadata(mock_requests, tmpdir, dummy_provider):
    port = 8080

    tarfile_path, listing_url, entry, listing_path = listing_tar_entry(
        tmpdir=tmpdir, port=port, dummy_provider_factory=dummy_provider
    )
    # fetch the tar file
    tarfile_bytes = None
    with open(tarfile_path, "rb") as f:
        tarfile_bytes = f.read()

    policy = provider.RuntimeConfig(
        result_store=result.StoreStrategy.SQLITE,
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        import_results_enabled=True,
        import_results_path="{provider_name}/listing.json",
        import_results_host=f"http://localhost:{port}",
    )

    subject = dummy_provider(populate=True, runtime_cfg=policy)

    current = subject.workspace.state()

    og_timestamp = datetime.datetime(2021, 1, 1, 0, 0, 0)
    current.timestamp = og_timestamp

    subject.workspace.record_state(
        version=subject.version(),
        distribution_version=subject.distribution_version(),
        timestamp=og_timestamp,
        urls=[subject.input_file],
        store=result.StoreStrategy.FLAT_FILE.value,
    )

    def handle_get_requests(url, *args, **kwargs):
        listing_response = MagicMock()
        listing_response.status_code = 200
        listing_response.raise_for_status.side_effect = None
        listing_response.json.return_value = json.loads(open(listing_path, "r").read())

        entry_response = MagicMock()
        entry_response.status_code = 200
        entry_response.raise_for_status.side_effect = None
        entry_response.iter_content.return_value = [tarfile_bytes]

        not_found_response = MagicMock()
        not_found_response.status_code = 404
        not_found_response.raise_for_status.side_effect = Exception("404")

        if url == f"http://localhost:{port}/{subject.name()}/listing.json":
            return listing_response
        elif url == entry.url:
            return entry_response
        else:
            return not_found_response

    mock_requests.side_effect = handle_get_requests

    subject.run()

    updated_state = subject.workspace.state()

    assert updated_state.timestamp == og_timestamp
    assert updated_state.stale


@pytest.mark.parametrize(
    "enabled,host,path,error_message",
    [
        (True, "", "", "enabling import results requires host"),
        (True, "http://example.com", "", "enabling import results requires path"),
        (False, "", "", None),
    ],
)
def test_validate_import_results_config(enabled: bool, host: str, path: str, error_message: str | None, dummy_provider):
    runtime_config = provider.RuntimeConfig()
    runtime_config.import_results_enabled = enabled
    runtime_config.import_results_host = host
    runtime_config.import_results_path = path
    if error_message:
        with pytest.raises(RuntimeError) as e:
            dummy_provider(runtime_cfg=runtime_config)
            assert error_message == str(e)
    else:
        dummy_provider(runtime_cfg=runtime_config)


def test_has_newer_archive_distribution_version_mismatch_true(dummy_provider):
    subject = dummy_provider()
    distribution_version = subject.distribution_version()
    mismatched_distribution_version = distribution_version + 1
    existing_state = subject.workspace.state()
    subject.workspace.record_state(
        version=subject.version(),
        distribution_version=mismatched_distribution_version,
        timestamp=existing_state.timestamp,
        store=result.StoreStrategy.FLAT_FILE.value,
        urls=existing_state.urls,
    )
    entry = distribution.ListingEntry(
        enclosed_checksum=f"{existing_state.listing.algorithm}:{existing_state.listing.digest}",
        distribution_checksum="xxh64:12341234aedf",
        distribution_version=subject.distribution_version(),
        built="2024-03-25T13:36:36Z",
        url="http://example.com/some-example",
    )
    assert subject._has_newer_archive(latest_entry=entry)


def test_has_newer_archive_version_mismatch_has_no_effect(dummy_provider):
    subject = dummy_provider()
    version = subject.version()
    mismatched_version = version + 1
    existing_state = subject.workspace.state()
    subject.workspace.record_state(
        version=mismatched_version,
        distribution_version=subject.distribution_version(),
        timestamp=existing_state.timestamp,
        store=result.StoreStrategy.FLAT_FILE.value,
        urls=existing_state.urls,
    )
    entry = distribution.ListingEntry(
        enclosed_checksum=f"{existing_state.listing.algorithm}:{existing_state.listing.digest}",
        distribution_checksum="xxh64:12341234aedf",
        distribution_version=subject.distribution_version(),
        built="2024-03-25T13:36:36Z",
        url="http://example.com/some-example",
    )
    assert not subject._has_newer_archive(latest_entry=entry)


def test_has_newer_archive_false(dummy_provider):
    subject = dummy_provider(populate=True)
    state = subject.workspace.state()
    entry = distribution.ListingEntry(
        enclosed_checksum=f"{state.listing.algorithm}:{state.listing.digest}",
        distribution_checksum="xxh64:12341234aedf",
        distribution_version=subject.distribution_version(),
        built="2024-03-25T13:36:36Z",
        url="http://example.com/some-example",
    )
    assert not subject._has_newer_archive(entry)


def test_timestamp_updated_on_fetch_or_use_results_archive(tmpdir, dummy_provider):
    subject = dummy_provider(populate=True)
    subject.runtime_cfg.import_results_enabled = True
    subject.runtime_cfg.import_results_host = "http://localhost"
    subject.runtime_cfg.import_results_path = "{provider_name}/listing.json"
    current_state = subject.workspace.state()
    # fetch the results archive
    urls, count, timestamp = subject._fetch_or_use_results_archive()
    assert current_state.timestamp != timestamp
    assert timestamp == datetime.datetime(2021, 1, 1, 0, 0, 0)


def test_state_update_on_stale(tmpdir, dummy_provider_with_zero_count_on_update):
    subject = dummy_provider_with_zero_count_on_update(populate=True)
    current_state = subject.workspace.state()
    subject.runtime_cfg.import_results_enabled = True
    subject.runtime_cfg.import_results_host = "http://localhost"
    subject.runtime_cfg.import_results_path = "{provider_name}/listing.json"
    subject._update()
    new_state = subject.workspace.state()
    assert new_state.timestamp is not None
    assert new_state.timestamp == datetime.datetime(2021, 1, 1, 0, 0, 0)


@pytest.mark.parametrize(
    "host,path,want",
    [
        ("http://example.com/", "{provider_name}/listing.json", "http://example.com/test-provider/listing.json"),
        # extra leading and trailing slashes are handled correctly:
        ("http://example.com////", "///{provider_name}/listing.json", "http://example.com/test-provider/listing.json"),
        ("http://example.com/", "specific-path/listing.json", "http://example.com/specific-path/listing.json"),
        ("http://sub.example.com/", "v1/{provider_name}/listing.json", "http://sub.example.com/v1/test-provider/listing.json"),
        ("http://sub.example.com/v1", "/{provider_name}/listing.json", "http://sub.example.com/v1/test-provider/listing.json"),
    ],
)
def test_import_url(host, path, want, dummy_provider):
    subject = provider.RuntimeConfig(
        import_results_path=path,
        import_results_enabled=True,
        import_results_host=host,
    )
    got = subject.import_url(provider_name="test-provider")
    assert got == want


def assert_dummy_workspace_state(ws):
    current_state = workspace.State.read(root=ws.path)

    # ignore timestamp (make certain it exists)
    assert current_state.timestamp is not None
    current_state.timestamp = None

    expected_state = workspace.State(
        store=result.StoreStrategy.FLAT_FILE.value,
        provider="dummy",
        urls=["http://localhost:8000/dummy-input-1.json"],
        listing=workspace.File(digest="b23db1a0e34dad13", algorithm="xxh64", path="checksums"),
        timestamp=None,
        schema=schema.ProviderStateSchema(),
    )

    assert current_state == expected_state


@patch("vunnel.provider.schema_def.ProviderStateSchema")
def test_version(mock_schema):
    mock_schema.return_value = MagicMock(major_version=3)

    class Impl(provider.Provider):
        __distribution_version__ = 4
        __version__ = 2

        def __init__(self):
            # intentionally do not call super().__init__()
            pass

        def name(self):
            return "dummy"

        def update(self):
            return None

    # distribution version = 4 + (3-1) = 6
    # provider version = __version__ + (distribution version - 1) = 2 + (6-1) = 7
    assert Impl().version() == 7


@patch("vunnel.provider.schema_def.ProviderStateSchema")
def test_distribution_version(mock_schema):
    mock_schema.return_value = MagicMock(major_version=1)

    class Impl(provider.Provider):
        __distribution_version__ = 4

        def __init__(self):
            # intentionally do not call super().__init__()
            pass

        def name(self):
            return "dummy"

        def update(self):
            return None

    assert Impl().distribution_version() == 4

    # a breaking change to the workspace schema should reflect a change in distribution version
    mock_schema.return_value = MagicMock(major_version=2)
    assert Impl().distribution_version() == 5

    # a change in the provider's distribution version should reflect a change in distribution version
    Impl.__distribution_version__ = 6
    assert Impl().distribution_version() == 7


def test_provider_versions(tmpdir):
    from vunnel import providers

    # WARNING: changing the values of these versions has operational impact! Do not change them without
    # understanding the implications!
    expected = {
        "alma": 1,
        "alpine": 1,
        "amazon": 1,
        "bitnami": 1,
        "chainguard": 1,
        "debian": 1,
        "echo": 1,
        "epss": 1,
        "github": 1,
        "kev": 1,
        "mariner": 1,
        "minimos": 1,
        "nvd": 2,
        "oracle": 1,
        "rhel": 1,
        "rocky": 1,
        "sles": 1,
        "ubuntu": 3,
        "wolfi": 1,
    }

    got = {}
    for name in providers.names():
        p = providers.create(name, tmpdir)
        got[p.name()] = p.version()

    assert expected == got, "WARNING! CHANGES TO VERSIONS HAVE OPERATIONAL IMPACT!"


def test_provider_distribution_versions(tmpdir):
    from vunnel import providers

    # WARNING: changing the values of these distributions has operational impact! Do not change them without
    # understanding the implications!
    expected = {
        "alma": 1,
        "alpine": 1,
        "amazon": 1,
        "bitnami": 1,
        "chainguard": 1,
        "debian": 1,
        "echo": 1,
        "epss": 1,
        "github": 1,
        "kev": 1,
        "mariner": 1,
        "minimos": 1,
        "nvd": 1,
        "oracle": 1,
        "rhel": 1,
        "rocky": 1,
        "sles": 1,
        "ubuntu": 1,
        "wolfi": 1,
    }

    got = {}
    for name in providers.names():
        p = providers.create(name, tmpdir)
        got[p.name()] = p.distribution_version()

    assert expected == got, "WARNING! CHANGES TO DISTRIBUTION VERSIONS HAVE OPERATIONAL IMPACT!"
