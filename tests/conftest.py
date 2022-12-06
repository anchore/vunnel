import os

import pytest


class Helpers:
    def __init__(self, request):
        # current information about the running test
        # docs: https://docs.pytest.org/en/6.2.x/reference.html#std-fixture-request
        self.request = request

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


@pytest.fixture
def helpers(request):
    """
    Returns a common set of helper functions for tests.
    """
    return Helpers(request)
