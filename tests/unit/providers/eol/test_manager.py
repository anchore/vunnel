import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest
import requests

from vunnel.providers.eol.manager import Manager


@pytest.fixture
def mock_products_response():
    return [
        {
            "name": "python",
            "identifiers": [
                {
                    "type": "cpe",
                    "id": "cpe:/:a:python:python"
                },
                {
                    "type": "cpe",
                    "id": "cpe:2.3:a:python:python"
                }
            ],
            "releases": [
                {
                    "name": "3.12",
                    "codename": "Some Codename",
                    "label": "3.12 (Some Codename)",
                    "releaseDate": "2023-10-02",
                    "isLts": False,
                    "eolFrom": "2025-10-01",
                    "isMaintained": True,
                },
                {
                    "name": "3.11",
                    "codename": "Other Codename",
                    "label": "3.11 (Other Codename)",
                    "releaseDate": "2022-10-24",
                    "isLts": True,
                    "eolFrom": "2027-10-24",
                    "isMaintained": False,
                },
            ],
        },
        {
            "name": "nodejs",
            "identifiers": [
                {
                    "type": "cpe",
                    "id": "cpe:/:a:nodejs:nodejs"
                },
                {
                    "type": "cpe",
                    "id": "cpe:2.3:a:nodejs:nodejs"
                }
            ],
            "releases": [
                {
                    "name": "20",
                    "codename": "Node LTS",
                    "label": "20 (Node LTS)",
                    "releaseDate": "2023-04-18",
                    "isLts": True,
                    "eolFrom": "2026-04-30",
                    "isMaintained": True,
                }
            ],
        },
    ]


def test_manager_get(mock_products_response):
    workspace = Mock()
    logger = Mock()

    with patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"result": mock_products_response}
        mock_get.return_value.raise_for_status = Mock()

        manager = Manager(
            url="https://endoflife.date/api/v1/products/full",
            workspace=workspace,
            download_timeout=125,
            logger=logger,
        )

        records = list(manager.get())

        # There should be 3 records: 2 for python, 1 for nodejs
        assert len(records) == 3
        # Check first record (python 3.12)
        product, cycle, data = records[0]
        assert product == "python"
        assert cycle == "3.12"
        assert data["codename"] == "Some Codename"
        assert data["is_lts"] is False
        assert data["is_maintained"] is True
        assert data["identifiers"] == [
            {"type": "cpe", "id": "cpe:/:a:python:python"},
            {"type": "cpe", "id": "cpe:2.3:a:python:python"}
        ]
        # Check second record (python 3.11)
        product, cycle, data = records[1]
        assert product == "python"
        assert cycle == "3.11"
        assert data["codename"] == "Other Codename"
        assert data["is_lts"] is True
        assert data["is_maintained"] is False
        assert data["identifiers"] == [
            {"type": "cpe", "id": "cpe:/:a:python:python"},
            {"type": "cpe", "id": "cpe:2.3:a:python:python"}
        ]
        # Check third record (nodejs 20)
        product, cycle, data = records[2]
        assert product == "nodejs"
        assert cycle == "20"
        assert data["codename"] == "Node LTS"
        assert data["is_lts"] is True
        assert data["is_maintained"] is True
        assert data["identifiers"] == [
            {"type": "cpe", "id": "cpe:/:a:nodejs:nodejs"},
            {"type": "cpe", "id": "cpe:2.3:a:nodejs:nodejs"}
        ]


def test_manager_get_request_error():
    workspace = Mock()
    logger = Mock()

    with patch("requests.get") as mock_get:
        mock_get.side_effect = requests.RequestException("Failed to connect")

        manager = Manager(
            url="https://endoflife.date/api/v1/products/full",
            workspace=workspace,
            download_timeout=125,
            logger=logger,
        )

        records = list(manager.get())
        assert len(records) == 0
        logger.error.assert_called_once()


def test_manager_get_invalid_date():
    workspace = Mock()
    logger = Mock()

    mock_products_response = [
        {
            "name": "python",
            "releases": [
                {
                    "name": "3.12",
                    "codename": "Some Codename",
                    "label": "3.12 (Some Codename)",
                    "releaseDate": "invalid-date",
                    "isLts": False,
                    "eolFrom": "invalid-date",
                    "isMaintained": True,
                }
            ],
        }
    ]

    with patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"result": mock_products_response}
        mock_get.return_value.raise_for_status = Mock()

        manager = Manager(
            url="https://endoflife.date/api/v1/products/full",
            workspace=workspace,
            download_timeout=125,
            logger=logger,
        )

        records = list(manager.get())
        assert len(records) == 1
        product, cycle, data = records[0]
        assert product == "python"
        assert cycle == "3.12"
        assert data["release_date"] is None
        assert data["eol_from"] is None
        logger.warning.assert_any_call(
            f"failed to parse date for python 3.12 release_date: invalid-date",
        )
        logger.warning.assert_any_call(
            f"failed to parse date for python 3.12 eol_from: invalid-date",
        ) 