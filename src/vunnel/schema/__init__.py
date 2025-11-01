"""
Schema package for vunnel.
"""

from .eol import EOLSchema
from .provider import (
    AnnotatedOpenVEXSchema,
    EPSSSchema,
    GithubSecurityAdvisorySchema,
    KnownExploitedVulnerabilitySchema,
    MatchExclusionSchema,
    MSRCSchema,
    NVDSchema,
    OSSchema,
    OSVSchema,
    ProviderListingSchema,
    ProviderStateSchema,
    Schema,
)

__all__ = [
    "AnnotatedOpenVEXSchema",
    "EOLSchema",
    "EPSSSchema",
    "GithubSecurityAdvisorySchema",
    "KnownExploitedVulnerabilitySchema",
    "MSRCSchema",
    "MatchExclusionSchema",
    "NVDSchema",
    "OSSchema",
    "OSVSchema",
    "ProviderListingSchema",
    "ProviderStateSchema",
    "Schema",
]
