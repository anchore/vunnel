"""What one published OpenVEX statement means, and how it joins to the OSV feed.

Canonical's OSV publication collapses six tracker statuses
(`needs-triage`, `needed`, `ignored`, `pending`, `deferred`, `in-progress`)
into a single shape — `affected[]` with `events: [{"introduced": "0"}]`
and no `fixed:` event — losing the won't-fix signal that downstream
matchers and humans use to triage findings. See
documentation.ubuntu.com/security/security-updates/osv/ for the
explicit mapping table.

VEX preserves more granularity. For `status: "affected"`, the
`action_statement` field uses four canonical opening phrases
(measured against the full live feed):

  * "...decided to not fix it..."        →  ignored (won't fix)
  * "...is no longer supported..."       →  ignored (EOL flavor — won't fix)
  * "...needs fixing"                    →  needed (will be fixed eventually)
  * "...needs fixing, and...actively..." →  active/in-progress

Only the first two indicate won't-fix intent, and this module is where that
prefix match and the four dispositions a statement can carry are defined. It is
kept apart from the pass that reads the feed so that revising what a statement
means is a change in one file.

Why distro label and not OSV ecosystem string: both OSV and VEX records
embed the same `distro=X` qualifier in their package PURLs (e.g.
`distro=noble`, `distro=esm-infra/jammy`). Joining on the PURL distro
avoids the ecosystem-string-to-channel-codename inverse lookup that
would otherwise be necessary.
"""

from __future__ import annotations

import re

# action_statement openings (from the live vex-all.tar.xz feed) that mean
# "Canonical decided not to fix". Measured against ~156k statements — these
# two prefixes cover all wont-fix dispositions.
_WONT_FIX_PREFIXES: tuple[str, ...] = (
    "This package (for the given release) is vulnerable to the CVE, the problem is understood, but the Ubuntu Security Team decided to not fix it",
    "This package (for the given release) is no longer supported",
)

# The OpenVEX statuses. `fixed` is stored in the cache and read nowhere: a fix
# version comes from OSV, never from a statement, so a `fixed` statement with no
# OSV entry behind it has nothing to state and produces nothing.
_STATUS_AFFECTED = "affected"
_STATUS_NOT_AFFECTED = "not_affected"
_STATUS_UNDER_INVESTIGATION = "under_investigation"

# The two justifications Canonical publishes on a `not_affected` statement, and
# they do not mean the same thing. `vulnerable_code_not_present` is the
# researched conclusion that the package in this release does not carry the
# vulnerability, which is the tracker's `not-affected` and worth stating.
# `component_not_present` says the release does not ship the package at all,
# which is the tracker's `DNE` — there is no package for a statement to be about,
# and the pre-OSV provider emitted nothing for it. A statement carrying neither
# is read as the first: it is a conclusion about the package, just an unjustified
# one.
_JUSTIFICATION_COMPONENT_NOT_PRESENT = "component_not_present"

# What a statement means to the emit path. Three outcomes, because the fourth
# (a fix version) is OSV's to supply.
#
# `under_investigation` collapses onto NO_FIX rather than onto a fourth
# disposition of its own. It means "not yet determined", which this provider
# emitted as vulnerable-with-no-fix for years before it read this feed at all;
# treating it as a clearance would drop tens of thousands of real findings.
NOT_AFFECTED = "not-affected"
NOT_PRESENT = "not-present"
WONT_FIX = "wont-fix"
NO_FIX = "no-fix"

_LEGACY_ESM_POCKET = "esm-infra-legacy"
_ESM_SUFFIX = "esm"

# Extracts (distro, source-pkg) from a deb PURL.
_PURL_DISTRO_RE = re.compile(r"distro=([^&]+)")
_PURL_NAME_RE = re.compile(r"^pkg:deb/ubuntu/([^@?]+)")


def _is_wont_fix_action(action_statement: str | None) -> bool:
    """Prefix-match an OpenVEX action_statement against the won't-fix openings.

    Canonical writes one of four canonical openings; the two that indicate
    won't-fix are matched here. Returns False for unset, empty, or
    "needs fixing"-style action statements.
    """
    if not action_statement:
        return False
    return action_statement.startswith(_WONT_FIX_PREFIXES)


def disposition_of(status: str, justification: str | None, action_statement: str | None) -> str | None:
    """What one published statement says about a package, or None if it says nothing usable.

    `fixed` returns None. The version on a `fixed` statement's product URL is
    the package's current version in that pocket rather than the version that
    fixed the vulnerability, so a `fixed` statement on its own has no fix
    version to state and nothing to say that isn't better said by the OSV
    record beside it.
    """
    if status == _STATUS_NOT_AFFECTED:
        return NOT_PRESENT if justification == _JUSTIFICATION_COMPONENT_NOT_PRESENT else NOT_AFFECTED
    if status == _STATUS_AFFECTED:
        return WONT_FIX if _is_wont_fix_action(action_statement) else NO_FIX
    if status == _STATUS_UNDER_INVESTIGATION:
        return NO_FIX
    return None


def canonical_token(token: str) -> str:
    """Fold the two spellings of the oldest ESM pocket onto one join key.

    Canonical writes that slice both ways round — `trusty/esm` and
    `esm-infra-legacy/trusty` — and both spellings appear on both sides of the
    join, which is why joining on the raw label leaves about 23,000 OSV entries
    looking as though VEX says nothing about them.

    This is about pockets, not releases, and is deliberately separate from the
    OSV ecosystem identity: a token names a pocket of a release.
    """
    head, sep, tail = token.partition("/")
    if sep and tail == _ESM_SUFFIX:
        return f"{_LEGACY_ESM_POCKET}/{head}"
    return token


# The release's own archive, as `pocket_of_token` spells it.
BASE_POCKET = ""


def codename_of_token(token: str) -> str:
    """The release codename a token names.

    Tokens come in two shapes and the pocket is on a different side in each:

      focal                    -> focal
      esm-infra/focal          -> focal      (<pocket>/<codename>)
      trusty/esm               -> trusty     (<codename>/esm)

    Taking the tail resolves `trusty/esm` to `esm`, which
    `parser_legacy.ubuntu_version_names` does not know, which reads as "this
    token names no release" — right for trusty by accident and wrong in general.
    """
    head, sep, tail = token.partition("/")
    if not sep:
        return head
    return head if tail == _ESM_SUFFIX else tail


def pocket_of_token(token: str) -> str:
    """The pocket a token names, or the empty string for a release's own archive.

    The mirror of `codename_of_token`, and it has to read the same two shapes:

      focal                    -> ""            (the release archive itself)
      esm-infra/focal          -> esm-infra
      trusty/esm               -> esm
      fips-updates/focal       -> fips-updates
      bluefield/noble          -> bluefield
    """
    head, sep, tail = token.partition("/")
    if not sep:
        return BASE_POCKET
    return tail if tail == _ESM_SUFFIX else head


# Which pockets may speak for a release's base namespace at all, and which of
# them may put a finding there. The two are deliberately different sets.
#
# A clearance travels. `not_affected` / `vulnerable_code_not_present` is the
# security team's researched conclusion that the vulnerable code is not in this
# release's package, and the team that maintains the extended-support build of a
# package is the same team maintaining the base one. Canonical publishes that
# conclusion against whichever pocket it was doing the work for, and a base
# release left saying nothing — or saying `needs-triage` — is an absence of
# research rather than a contradiction of it. The pre-OSV provider made the same
# call: it downgraded a base `needs-triage` to not-affected when an ESM pocket
# had confirmed it.
#
# A finding does not travel. An extended-support pocket rebuilds a package and
# then states what is true of the rebuild, so `affected` there is not a claim
# about the base build and would invent findings the vendor never made about it.
# Only the release's own archive can put a finding in its namespace.
#
# `fips`, `fips-updates`, `fips-preview`, `realtime`, `bluefield` and `ros-esm`
# are in neither set. They are separate builds that map to no output namespace,
# so nothing they say can be asserted anywhere.
_POCKETS_THAT_ASSERT: frozenset[str] = frozenset(
    {
        BASE_POCKET,
        "esm-infra",
        "esm-apps",
        "esm-infra-legacy",
        "esm-apps-legacy",
        # the other way round the tokens are written: `trusty/esm`
        _ESM_SUFFIX,
    },
)

_POCKETS_THAT_ASSERT_FINDINGS: frozenset[str] = frozenset({BASE_POCKET})


def token_asserts(token: str) -> bool:
    """May this token's clearances be asserted into its release's base namespace?"""
    return pocket_of_token(token) in _POCKETS_THAT_ASSERT


def token_asserts_findings(token: str) -> bool:
    """May this token put a finding in its release's base namespace?"""
    return pocket_of_token(token) in _POCKETS_THAT_ASSERT_FINDINGS


def distro_label_from_purl(purl: str) -> str | None:
    """Pull the `distro=` qualifier value out of a deb PURL.

    Returns values like "noble", "esm-infra/jammy", "fips-updates/focal",
    or None if the PURL doesn't carry one. Both OSV and VEX records use
    the same distro qualifier, so we use it as the join key.
    """
    m = _PURL_DISTRO_RE.search(purl or "")
    return m.group(1) if m else None


def source_package_from_purl(purl: str) -> str | None:
    """Pull the source package name from a deb PURL (`pkg:deb/ubuntu/<name>@...`)."""
    m = _PURL_NAME_RE.match(purl or "")
    return m.group(1) if m else None
