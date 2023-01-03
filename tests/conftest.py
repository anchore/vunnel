import json
import os
import subprocess
import uuid
from datetime import datetime

import jsonschema
import pytest

from vunnel import provider, workspace


class WorkspaceHelper:
    def __init__(self, root: str, name: str):
        self.root = root
        self.name = name

    @property
    def input_dir(self):
        return self.root / self.name / "input"

    @property
    def results_dir(self):
        return self.root / self.name / "results"

    def result_files(self):
        results = []
        for root, dirs, files in os.walk(self.results_dir):
            for filename in files:
                results.append(os.path.join(root, filename))
        return results

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
    def __init__(self, request, tmpdir):
        # current information about the running test
        # docs: https://docs.pytest.org/en/6.2.x/reference.html#std-fixture-request
        self.request = request
        self.tmpdir = tmpdir

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

    def provider_workspace_helper(self, name: str) -> WorkspaceHelper:
        root = self.tmpdir / "provider"
        os.makedirs(root / name / "input")
        os.makedirs(root / name / "results")
        return WorkspaceHelper(root, name)


@pytest.fixture
def helpers(request, tmpdir):
    """
    Returns a common set of helper functions for tests.
    """
    return Helpers(request, tmpdir)


def git_root() -> str:
    return (
        subprocess.Popen(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE)
        .communicate()[0]
        .rstrip()
        .decode("utf-8")
    )


@pytest.fixture
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
