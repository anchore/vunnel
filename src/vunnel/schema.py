from __future__ import annotations

from dataclasses import dataclass

PROVIDER_WORKSPACE_STATE_SCHEMA_VERSION = "1.0.1"
MATCH_EXCLUSION_SCHEMA_VERSION = "1.0.0"
GITHUB_SECURITY_ADVISORY_SCHEMA_VERSION = "1.0.1"
MSRC_SCHEMA_VERSION = "1.0.0"
OS_SCHEMA_VERSION = "1.0.0"
NVD_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class Schema:
    version: str
    url: str


def ProviderStateSchema(version: str = PROVIDER_WORKSPACE_STATE_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/provider-workspace-state/schema-{version}.json",
    )


def MatchExclusionSchema(version: str = MATCH_EXCLUSION_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/match-exclusion/schema-{version}.json",
    )


def GithubSecurityAdvisorySchema(version: str = GITHUB_SECURITY_ADVISORY_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/github-security-advisory/schema-{version}.json",  # noqa: E501
    )


def MSRCSchema(version: str = MSRC_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/msrc/schema-{version}.json",
    )


def OSSchema(version: str = OS_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-{version}.json",
    )


def NVDSchema(version: str = NVD_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/nvd/schema-{version}.json",
    )
