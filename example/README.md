# Example "awsome" provider

This is an example of a provider for the "awesome" vulnerability data source. When writing a new provider it is
encouraged to copy this example (within the `awesome` directory) and modify it to fit the needs of the new provider.

Take note of the `NOTE: CHANGE ME!` comments in the code. These are places where you will require tailoring.

If you wanted to run the provider locally to try it out independent of the vunnel CLI:

```bash
poetry run python run.py
```

Then checkout the `./data` directory to see what was created.
