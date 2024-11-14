from __future__ import annotations

import os.path
from dataclasses import dataclass

# Note: this metadata.json file currently is not allowed to have a breaking change
PROVIDER_WORKSPACE_STATE_SCHEMA_VERSION = "1.0.3"

PROVIDER_ARCHIVE_LISTING_SCHEMA_VERSION = "1.0.0"
MATCH_EXCLUSION_SCHEMA_VERSION = "1.0.0"
GITHUB_SECURITY_ADVISORY_SCHEMA_VERSION = "1.0.1"
MSRC_SCHEMA_VERSION = "1.0.0"
OS_SCHEMA_VERSION = "1.0.0"
NVD_SCHEMA_VERSION = "1.0.0"
OSV_SCHEMA_VERSION = "1.6.1"


@dataclass(frozen=True)
class Schema:
    version: str
    url: str

    @property
    def major_version(self) -> str:
        return self.version.split(".")[0]

    @property
    def name(self) -> str:
        name = self.url.removeprefix("https://raw.githubusercontent.com/anchore/vunnel/main/schema/")
        return os.path.dirname(name)


def ProviderListingSchema(version: str = PROVIDER_ARCHIVE_LISTING_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/provider-archive-listing/schema-{version}.json",
    )


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
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/github-security-advisory/schema-{version}.json",
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


def OSVSchema(version: str = OSV_SCHEMA_VERSION) -> Schema:
    return Schema(
        version=version,
        url=f"https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/osv/schema-{version}.json",
    )
