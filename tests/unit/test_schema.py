from vunnel import schema as schema_def


def test_provider_workspace_schema_v1():
    # it is vital that we do not make any breaking changes to the provider workspace state schema
    # until there is a mechanism to deal with the state version detection, migration, and possibly supporting
    # multiple version implementations in the codebase
    assert schema_def.PROVIDER_WORKSPACE_STATE_SCHEMA_VERSION.startswith("1.")
    assert schema_def.ProviderStateSchema().version.startswith("1.")
