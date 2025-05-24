from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .provider import Schema


@dataclass
class EOLRecord:
    """EOL record schema for end-of-life data."""

    product: str
    cycle: str
    eol: datetime | None
    latest: str | None
    latest_release_date: datetime | None
    release_date: datetime | None
    lts: bool | None
    support: datetime | None
    discontinued: datetime | None
    extended_support: datetime | None


class EOLSchema(Schema):
    """Schema for EOL data."""

    def __init__(self, version: str = "1.0.0"):
        url = f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/eol/schema-{version}.json"
        super().__init__(version, url)

    def validate(self, data: dict[str, Any]) -> None:
        """Validate the data against the schema."""
        if not isinstance(data, dict):
            raise ValueError("data must be a dictionary")

        required_fields = ["product", "cycle"]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"missing required field: {field}")

        if not isinstance(data["product"], str):
            raise ValueError("product must be a string")

        if not isinstance(data["cycle"], str):
            raise ValueError("cycle must be a string")

        # Optional fields validation
        optional_fields = {
            "eol": datetime,
            "latest": str,
            "latest_release_date": datetime,
            "release_date": datetime,
            "lts": bool,
            "support": datetime,
            "discontinued": datetime,
            "extended_support": datetime,
        }

        for field, field_type in optional_fields.items():
            if field in data and not isinstance(data[field], field_type):
                raise ValueError(f"{field} must be of type {field_type.__name__}")

    def normalize(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize the data to ensure consistent format."""
        normalized = data.copy()

        # Convert datetime objects to ISO format strings
        datetime_fields = [
            "eol",
            "latest_release_date",
            "release_date",
            "support",
            "discontinued",
            "extended_support",
        ]

        for field in datetime_fields:
            if field in normalized and normalized[field] is not None and isinstance(normalized[field], datetime):
                normalized[field] = normalized[field].isoformat()

        return normalized
