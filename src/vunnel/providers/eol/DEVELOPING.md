# Developing for the EOL Provider

This provider fetches end-of-life data from the [endoflife.date](https://endoflife.date) API.

## How this provider works

1. End-of-life data is published at https://endoflife.date/api/v1/products/full
2. The API returns product release cycles with EOL dates, LTS status, and other lifecycle information
3. Vunnel downloads this JSON data and passes it through with minimal transformation
4. Each release cycle is written as a separate record with the product name added

The provider uses a "passthrough" approach:
- API response data is preserved in camelCase format (e.g., `isLts`, `eolFrom`, `isMaintained`)
- The only additions are `product` (the product name) and `identifiers` (from the parent product object)
- This simplifies maintenance since schema changes upstream are automatically reflected

## Schema Generation

The JSON Schema at `schema/eol/schema-1.0.0.json` is generated from the endoflife.date OpenAPI specification.

### Regenerating the schema

If the upstream API schema changes, regenerate the JSON schema:

```bash
cd src/vunnel/providers/eol
uv run python generate_schema.py
```

Note: The script requires the `requests` and `pyyaml` packages (included in vunnel's dependencies).

This will:
1. Fetch the OpenAPI spec from https://endoflife.date/docs/api/v1/openapi.yml
2. Extract the `ProductRelease` schema
3. Convert it to JSON Schema format
4. Add the `product` and `identifiers` fields that vunnel adds
5. Write the result to `schema/eol/schema-{version}.json`

### What to do if the schema changes?

1. Re-run `./generate_schema.py`
2. Review the diff to understand what changed
3. Update the schema version in `src/vunnel/schema/eol.py` if it's a breaking change

## Data Format

Each record contains:

| Field | Type | Description |
|-------|------|-------------|
| `product` | string | Product name (added by vunnel) |
| `name` | string | Release cycle name |
| `releaseDate` | string/null | Release date (ISO 8601) |
| `isLts` | boolean/null | Whether this is an LTS release |
| `ltsFrom` | string/null | When LTS support started |
| `isEoas` | boolean/null | Whether active support has ended |
| `eoasFrom` | string/null | End of active support date |
| `isEol` | boolean/null | Whether end-of-life has been reached |
| `eolFrom` | string/null | End-of-life date |
| `isMaintained` | boolean/null | Whether the release is maintained |
| `identifiers` | array | Product identifiers like CPE, purl (added by vunnel) |

Additional fields from the API are preserved via `additionalProperties: true`.

## Testing

Run the provider tests:

```bash
cd vunnel
uv run pytest tests/unit/providers/eol/ -v
```

## API Documentation

- API Docs: https://endoflife.date/docs/api
- OpenAPI Spec: https://endoflife.date/docs/api/v1/openapi.yml
- GitHub: https://github.com/endoflife-date/endoflife.date
