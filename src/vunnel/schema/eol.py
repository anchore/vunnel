from __future__ import annotations

from .provider import Schema

# EOL schema version constant
EOL_SCHEMA_VERSION = "1.0.0"


def EOLSchema(version: str = EOL_SCHEMA_VERSION) -> Schema:
    """Schema for EOL data from endoflife.date API.

    This provider uses a passthrough format - data is passed through from
    the API in camelCase format with minimal transformation. The JSON schema
    at schema/eol/schema-{version}.json defines the expected structure.

    Required fields: product, name
    """
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/eol/schema-{version}.json",
    )
