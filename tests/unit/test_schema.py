from __future__ import annotations

from vunnel import schemas as schema_mod
from vunnel.schemas import ProviderStateSchema, ProviderListingSchema, Schema


def test_provider_workspace_schema_v1():
    # it is vital that we do not make any breaking changes to the provider workspace state schema
    # until there is a mechanism to deal with the state version detection, migration, and possibly supporting
    # multiple version implementations in the codebase
    assert schema_mod.PROVIDER_WORKSPACE_STATE_SCHEMA_VERSION.startswith("1.")
    assert ProviderStateSchema().version.startswith("1.")
