#!/usr/bin/env python3
"""
Generate JSON Schema for EOL provider from the endoflife.date OpenAPI specification.

Usage:
    python generate_schema.py

This script fetches the OpenAPI spec from endoflife.date and converts the
ProductRelease schema to JSON Schema format, adding the 'product' and
'identifiers' fields that vunnel adds during processing.

The output is written to: schema/eol/schema-1.0.0.json
"""

from __future__ import annotations

import json
from pathlib import Path

import requests
import yaml

from vunnel.schema.eol import EOL_SCHEMA_VERSION

OPENAPI_URL = "https://endoflife.date/docs/api/v1/openapi.yml"


def fetch_openapi_spec() -> dict:
    """Fetch the OpenAPI specification from endoflife.date."""
    print(f"Fetching OpenAPI spec from {OPENAPI_URL}")
    response = requests.get(OPENAPI_URL, timeout=30)
    response.raise_for_status()
    return yaml.safe_load(response.text)


def openapi_type_to_jsonschema(openapi_type: dict) -> dict:
    """Convert an OpenAPI type definition to JSON Schema format."""
    result = {}

    # Handle anyOf (nullable types in OpenAPI 3.1)
    if "anyOf" in openapi_type:
        types = []
        for option in openapi_type["anyOf"]:
            if option.get("type") == "null":
                types.append("null")
            elif "type" in option:
                types.append(option["type"])
                if "format" in option:
                    result["format"] = option["format"]
        result["type"] = types if len(types) > 1 else types[0]
        if "description" in openapi_type:
            result["description"] = openapi_type["description"]
        return result

    # Handle simple types
    if "type" in openapi_type:
        result["type"] = openapi_type["type"]

    if "format" in openapi_type:
        result["format"] = openapi_type["format"]

    if "description" in openapi_type:
        result["description"] = openapi_type["description"]

    # Handle objects
    if openapi_type.get("type") == "object":
        if "properties" in openapi_type:
            result["properties"] = {k: openapi_type_to_jsonschema(v) for k, v in openapi_type["properties"].items()}
        if "additionalProperties" in openapi_type:
            result["additionalProperties"] = openapi_type["additionalProperties"]

    # Handle arrays
    if openapi_type.get("type") == "array" and "items" in openapi_type:
        result["items"] = openapi_type_to_jsonschema(openapi_type["items"])

    return result


def extract_release_schema(openapi_spec: dict) -> dict:
    """Extract and convert the ProductRelease schema from OpenAPI spec."""
    schemas = openapi_spec.get("components", {}).get("schemas", {})
    product_release = schemas.get("ProductRelease", {})

    if not product_release:
        raise ValueError("ProductRelease schema not found in OpenAPI spec")

    # Convert to JSON Schema
    json_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/eol/schema-{EOL_SCHEMA_VERSION}.json",
        "type": "object",
        "title": "EOL Record",
        "description": "End-of-life data from endoflife.date API (ProductRelease schema)",
    }

    # Add required fields - product is required (we add it), name is from API
    json_schema["required"] = ["product", "name"]

    # Convert properties
    properties = {}

    # Add our custom 'product' field (not in upstream API, we add it)
    properties["product"] = {
        "type": "string",
        "description": "Product name (added by vunnel)",
    }

    # Add our custom 'identifiers' field (from parent Product, we flatten it)
    properties["identifiers"] = {
        "type": "array",
        "description": "Product identifiers such as CPE, purl, repology (added by vunnel from parent Product)",
        "items": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "description": "Identifier type (e.g., cpe, purl, repology)"},
                "id": {"type": "string", "description": "Identifier value"},
            },
            "required": ["type", "id"],
        },
    }

    # Convert upstream properties
    for prop_name, prop_def in product_release.get("properties", {}).items():
        properties[prop_name] = openapi_type_to_jsonschema(prop_def)

    json_schema["properties"] = properties

    # Allow additional properties (API may add new fields)
    json_schema["additionalProperties"] = True

    return json_schema


def write_schema(schema: dict, output_path: Path) -> None:
    """Write the JSON schema to file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(schema, f, indent=2)
        f.write("\n")
    print(f"Schema written to {output_path}")


def main() -> None:
    # Determine output path relative to repo root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent.parent.parent.parent  # src/vunnel/providers/eol -> repo root
    output_path = repo_root / "schema" / "eol" / f"schema-{EOL_SCHEMA_VERSION}.json"

    # Fetch and convert
    openapi_spec = fetch_openapi_spec()
    json_schema = extract_release_schema(openapi_spec)

    # Write output
    write_schema(json_schema, output_path)

    print("Done!")


if __name__ == "__main__":
    main()
