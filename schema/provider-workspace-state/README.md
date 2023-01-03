# `ProviderState` JSON Schema

This schema governs the `state.json` file produced by each vulnerability data provider run, describing what input as needed for the run and what files were produced.

See `src/vunnel.provider.State` for the root object that represents this schema.

## Updating the schema

Versioning the JSON schema must be done manually by copying the existing JSON schema into a new `schema-x.y.z.json` file and manually making the necessary updates (or by using an online tool such as https://www.liquid-technologies.com/online-json-to-schema-converter).

This schema is being versioned based off of the "SchemaVer" guidelines, which slightly diverges from Semantic Versioning to tailor for the purposes of data models.

Given a version number format `MODEL.REVISION.ADDITION`:

- `MODEL`: increment when you make a breaking schema change which will prevent interaction with any historical data
- `REVISION`: increment when you make a schema change which may prevent interaction with some historical data
- `ADDITION`: increment when you make a schema change that is compatible with all historical data
