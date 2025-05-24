import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest
import requests

from vunnel.providers.eol.manager import Manager


@pytest.fixture
def mock_products_response():
    return [
        {"product": "python"},
        {"product": "nodejs"},
    ]


@pytest.fixture
def mock_cycles_response():
    return [
        {
            "cycle": "3.12",
            "eol": "2025-10-01",
            "latest": "3.12.0",
            "latest_release_date": "2023-10-02",
            "release_date": "2023-10-02",
            "lts": False,
        },
        {
            "cycle": "3.11",
            "eol": "2027-10-24",
            "latest": "3.11.7",
            "latest_release_date": "2023-10-02",
            "release_date": "2022-10-24",
            "lts": True,
        },
    ]


def test_manager_get(mock_products_response, mock_cycles_response):
    workspace = Mock()
    logger = Mock()

    with patch("requests.get") as mock_get:
        # Provide a response for each requests.get call
        mock_get.side_effect = [
            Mock(json=Mock(return_value=mock_products_response), raise_for_status=Mock()),  # products
            Mock(json=Mock(return_value=mock_cycles_response), raise_for_status=Mock()),    # python cycles
            Mock(json=Mock(return_value=[]), raise_for_status=Mock()),                      # nodejs cycles (empty)
        ]

        manager = Manager(
            url="https://endoflife.date/api/v1/products.json",
            workspace=workspace,
            download_timeout=125,
            logger=logger,
        )

        # Get all records
        records = list(manager.get())

        # Verify the results
        assert len(records) == 2
        product, cycle, data = records[0]
        assert product == "python"
        assert cycle == "3.12"
        assert isinstance(data["eol"], datetime)
        assert data["eol"].isoformat() == "2025-10-01T00:00:00"
        assert data["latest"] == "3.12.0"
        assert data["lts"] is False


def test_manager_get_request_error():
    workspace = Mock()
    logger = Mock()

    with patch("requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Failed to connect")

        manager = Manager(
            url="https://endoflife.date/api/v1/products.json",
            workspace=workspace,
            download_timeout=125,
            logger=logger,
        )

        # Get all records
        records = list(manager.get())

        # Verify no records were returned
        assert len(records) == 0
        logger.error.assert_called_once()


def test_manager_get_invalid_date():
    workspace = Mock()
    logger = Mock()

    with patch("requests.get") as mock_get:
        # Mock the products response
        mock_get.return_value.json.return_value = [{"product": "python"}]
        mock_get.return_value.raise_for_status = Mock()

        # Mock the cycles response with invalid date
        mock_get.side_effect = [
            Mock(json=Mock(return_value=[{"product": "python"}]), raise_for_status=Mock()),
            Mock(
                json=Mock(
                    return_value=[
                        {
                            "cycle": "3.12",
                            "eol": "invalid-date",
                            "latest": "3.12.0",
                        }
                    ]
                ),
                raise_for_status=Mock(),
            ),
        ]

        manager = Manager(
            url="https://endoflife.date/api/v1/products.json",
            workspace=workspace,
            download_timeout=125,
            logger=logger,
        )

        # Get all records
        records = list(manager.get())

        # Verify the results
        assert len(records) == 1
        product, cycle, data = records[0]
        assert product == "python"
        assert cycle == "3.12"
        assert data["eol"] is None
        assert data["latest"] == "3.12.0"
        logger.warning.assert_called_once() 