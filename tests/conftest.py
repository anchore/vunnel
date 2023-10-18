from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import uuid
import os.path
import shutil

import jsonschema
import pytest


class WorkspaceHelper:
    def __init__(self, root: str, name: str, snapshot):
        self.root = root
        self.name = name
        self.snapshot = snapshot

    @property
    def metadata_path(self):
        return self.root / self.name / "metadata.json"

    @property
    def input_dir(self):
        return self.root / self.name / "input"

    @property
    def results_dir(self):
        return self.root / self.name / "results"

    def result_files(self):
        results = []
        for root, _dirs, files in os.walk(self.results_dir):
            for filename in files:
                results.append(os.path.join(root, filename))
        return results

    def _snapshot_files(self):
        snapshot_files = []

        for root, _dirs, files in os.walk(self.snapshot.snapshot_dir):
            for filename in files:
                snapshot_files.append(os.path.join(root, filename))
        return snapshot_files

    def num_result_entries(self):
        return len(self.result_files())

    def result_schemas_valid(self, require_entries: bool = True) -> bool:
        entries_validated = 0
        for result_file in self.result_files():
            with open(result_file) as f:
                envelope = json.load(f)
                schema_url = envelope["schema"]

                schema_dict = load_json_schema(get_schema_repo_path(schema_url))
                jsonschema.validate(instance=envelope["item"], schema=schema_dict)
                entries_validated += 1

        if require_entries and entries_validated == 0:
            raise ValueError("no entries were validated")

        return True

    def metadata_schema_valid(self) -> bool:
        with open(self.metadata_path) as f:
            item = json.load(f)
            schema_url = item["schema"]["url"]

            schema_dict = load_json_schema(get_schema_repo_path(schema_url))
            jsonschema.validate(instance=item, schema=schema_dict)

        return True

    def copy_input_fixtures(self, mock_data_path: str):
        shutil.copytree(mock_data_path, self.input_dir, dirs_exist_ok=True)

    def assert_result_snapshots(self):
        expected_files_to_test = set(self._snapshot_files())
        missing_snapshot_files = []

        for result_file in self.result_files():
            # protection against test configuration not swapping to the flat file store strategy
            assert result_file.endswith(".json")

            with open(result_file) as f:
                snapshot_path = result_file.split("results/")[-1]

                snapshot_abs_path = os.path.join(self.snapshot.snapshot_dir, snapshot_path)

                if not self.snapshot._snapshot_update and not os.path.exists(snapshot_abs_path):
                    missing_snapshot_files.append(snapshot_abs_path)
                else:
                    self.snapshot.assert_match(f.read() + "\n", snapshot_path)

                    if snapshot_abs_path in expected_files_to_test:
                        expected_files_to_test.remove(snapshot_abs_path)

        message_lines = []
        if expected_files_to_test:
            message_lines.append("existing snapshot files that were not asserted:")
            for expected_snapshot_path in expected_files_to_test:
                message_lines.append(f"  - {expected_snapshot_path}")

        if missing_snapshot_files:
            if message_lines:
                message_lines.append("")
            message_lines.append("missing snapshot files:")
            for missing_snapshot_file in missing_snapshot_files:
                message_lines.append(f"  - {missing_snapshot_file}")

        if message_lines:
            pytest.fail("\n".join(message_lines), pytrace=False)


def load_json_schema(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def get_schema_repo_path(url: str):
    # e.g. https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/nvd/schema-{version}.json
    relative_path = url.removeprefix("https://raw.githubusercontent.com/anchore/vunnel/main/")
    if relative_path == url:
        raise ValueError(f"URL {url!r} is not a valid schema URL")
    return os.path.join(git_root(), relative_path)


class Helpers:
    def __init__(self, request, tmpdir, snapshot):
        # current information about the running test
        # docs: https://docs.pytest.org/en/6.2.x/reference.html#std-fixture-request
        self.request = request
        self.tmpdir = tmpdir
        self.snapshot = snapshot

    def local_dir(self, path: str):
        """
        Returns the path of a file relative to the current test file.

        Given the following setup:

            test/unit/providers/centos/
            ├── test-fixtures
            │   ├── mock_data_1
            │   └── mock_data_2
            └── test_centos.py

        The call `local_dir("test-fixtures/mock_data_1")` will return the absolute path to
        the mock data file relative to test_centos.py
        """
        current_test_filepath = os.path.realpath(self.request.module.__file__)
        parent = os.path.realpath(os.path.dirname(current_test_filepath))
        return os.path.join(parent, path)

    def provider_workspace_helper(
        self, name: str, create: bool = True, input_fixture: str | None = None, snapshot_prefix: str = ""
    ) -> WorkspaceHelper:
        root = self.tmpdir
        if create:
            os.makedirs(root / name / "input")
            os.makedirs(root / name / "results")

        # any snapshot tests should be stored in the same place
        snapshot_path = "test-fixtures/snapshots"
        if snapshot_prefix:
            snapshot_path = os.path.join(snapshot_path, snapshot_prefix)
        self.snapshot.snapshot_dir = self.local_dir(snapshot_path)

        h = WorkspaceHelper(root, name, self.snapshot)

        if input_fixture:
            h.copy_input_fixtures(self.local_dir(input_fixture))

        return h


@pytest.fixture()
def helpers(request, tmpdir, snapshot):
    """
    Returns a common set of helper functions for tests.
    """
    return Helpers(request, tmpdir, snapshot)


def git_root() -> str:
    return (
        subprocess.Popen(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE)
        .communicate()[0]
        .rstrip()
        .decode("utf-8")
    )


@pytest.fixture()
def dummy_file():
    def apply(d: str, name: str = ""):
        if name == "":
            suffix = str(uuid.uuid4())[:8]
            name = f"random-{suffix}.json"

        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"name": name}, f)
        return path

    return apply
