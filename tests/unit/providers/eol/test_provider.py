from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import pytest

from vunnel.providers.eol import Provider


def test_provider_name():
    assert Provider.name() == "eol"


def test_provider_update():
    provider = Provider(root="/tmp/vunnel")
    # Patch the manager attribute directly
    mock_manager = MagicMock()
    mock_manager.get.return_value = [
        ("python", "3.12", {"product": "python", "cycle": "3.12", "eol": datetime(2025, 10, 1), "latest": "3.12.0"}),
        ("python", "3.11", {"product": "python", "cycle": "3.11", "eol": datetime(2027, 10, 24), "latest": "3.11.7"}),
    ]
    mock_manager.urls = ["https://endoflife.date/api/v1/products.json"]
    provider.manager = mock_manager
    writer = MagicMock()
    writer.__len__.return_value = 2
    provider.results_writer = MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=writer), __exit__=MagicMock()))
    urls, count = provider.update(None)

    assert urls == ["https://endoflife.date/api/v1/products.json"]
    assert count == 2

    # Verify the writer was called with the correct data
    assert writer.write.call_count == 2

    # Check first write call
    args, kwargs = writer.write.call_args_list[0]
    assert kwargs["identifier"] == "python:3.12"
    assert kwargs["payload"] == {"product": "python", "cycle": "3.12", "eol": datetime(2025, 10, 1), "latest": "3.12.0"}

    # Check second write call
    args, kwargs = writer.write.call_args_list[1]
    assert kwargs["identifier"] == "python:3.11"
    assert kwargs["payload"] == {"product": "python", "cycle": "3.11", "eol": datetime(2027, 10, 24), "latest": "3.11.7"} 