# Example "awesome" provider

This is an example of a provider for the "awesome" vulnerability data source. When writing a new provider it is
encouraged to copy this example (within the `awesome` directory) and modify it to fit the needs of the new provider.

Take note of the `NOTE: CHANGE ME!` comments in the code. These are places where you will require tailoring.

If you wanted to run the provider locally to try it out independent of the vunnel CLI:

```bash
# run from the example/ directory

uv run python run.py
```

Then checkout the `./data` directory to see what was created.


## Code organization

There tend to be two files in a directory that make up a provider:
```bash
src/vunnel/providers/<your-provider-name>/
  ├── __init__.py
  └── parser.py
```

Where:
- `__init__.py` defines:
  - defining the `Provider` class, which subclasses `vunnel.provider.Provider`. Try to keep this class as small as possible, importing functions and helpers from the surrounding `*.py` files.
  - defining the provider `Config` class. This is used in the vunnel application configuration to define the configuration for the provider.
- `parser.py` is where any downloading and parsing logic lives. Feel free to change this name based off of the specific needs and implementation that you need.


## Considerations for writing a provider

1. If possible, logically split up the downloading and parsing logic into separate functions. This will make it easier to test and debug.
2. Each provider may have different runtime configuration needs, tailor the specific defaults of the provider configuration you create accordingly
3. Pay careful attention to the runtime option for `existing_input`, if your provider requires previous data to accumulate over time, forbid customizing this value via configuration.
4. Make certain in the provider constructor to validate if the configuration is valid. If any fields are missing or have improper values raise a `ValueError` to prevent creation of the provider object.


## Testing your provider

Unit tests for providers can be found under `tests/unit/providers/<your-provider-name>/`. Tests should at least cover:
- parsing logic from static test fixture data representing downloaded data
- a `test_provider_schema` test that validates the provider is always outputting data in the correct schema
