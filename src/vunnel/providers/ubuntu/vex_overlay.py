"""Read the cached VEX statements and answer the two questions they settle.

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

Only the first two indicate won't-fix intent. This module prefix-matches
`action_statement` and exposes a lookup keyed by
(cve_id, distro_label_from_purl, source_package), built from the cached
statements in `vex_cache` rather than from the tarball — see that module
for why the statements have to be cached at all.

One token's statements are read at a time, when something first asks about
that token, and the caller drops them again when it moves on to another
release. Held all at once they are several million tuples for no gain: every
question asked of them is asked while one release is being assembled, and the
tokens of one release are a small slice of the cache.

Why distro label and not OSV ecosystem string: both OSV and VEX records
embed the same `distro=X` qualifier in their package PURLs (e.g.
`distro=noble`, `distro=esm-infra/jammy`). Joining on the PURL distro
avoids the ecosystem-string-to-channel-codename inverse lookup that
would otherwise be necessary.
"""

from __future__ import annotations

import logging
import re
import sys
from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping


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
STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# The two justifications Canonical publishes on a `not_affected` statement, and
# they do not mean the same thing. `vulnerable_code_not_present` is the
# researched conclusion that the package in this release does not carry the
# vulnerability, which is the tracker's `not-affected` and worth stating.
# `component_not_present` says the release does not ship the package at all,
# which is the tracker's `DNE` — there is no package for a statement to be about,
# and the pre-OSV provider emitted nothing for it. A statement carrying neither
# is read as the first: it is a conclusion about the package, just an unjustified
# one.
JUSTIFICATION_COMPONENT_NOT_PRESENT = "component_not_present"

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

# The two dispositions that say a finding is not warranted. They differ in what
# is emitted in its place: the first is stated, the second is silence.
CLEARANCES = (NOT_AFFECTED, NOT_PRESENT)

_LEGACY_ESM_POCKET = "esm-infra-legacy"
_ESM_SUFFIX = "esm"

# Extracts (distro, source-pkg) from a deb PURL.
_PURL_DISTRO_RE = re.compile(r"distro=([^&]+)")
_PURL_NAME_RE = re.compile(r"^pkg:deb/ubuntu/([^@?]+)")


def is_wont_fix_action(action_statement: str | None) -> bool:
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
    if status == STATUS_NOT_AFFECTED:
        return NOT_PRESENT if justification == JUSTIFICATION_COMPONENT_NOT_PRESENT else NOT_AFFECTED
    if status == STATUS_AFFECTED:
        return WONT_FIX if is_wont_fix_action(action_statement) else NO_FIX
    if status == STATUS_UNDER_INVESTIGATION:
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


class VEXOverlay:
    """Read-side view of the cached VEX statements, one token at a time.

    A token's fragment is read the first time something asks about that token
    and held as a map of (upstream CVE, source package) to disposition. The
    caller drops the loaded tokens when it finishes a release, so what is held
    at once is the tokens of one release rather than the whole cache.

    Read from the fragments rather than from the tarball, so a frozen release is
    still answered for after Canonical drops it from the feed. The prose match
    that decides won't-fix is applied here, at read time, so it can be revised
    without rewriting a fragment that can never be rewritten.
    """

    def __init__(
        self,
        fragments: dict[str, str] | None = None,
        read: Callable[[str], Iterable[Any]] | None = None,
        logger: logging.Logger | None = None,
    ):
        # Two spellings of the oldest ESM pocket are one join key and two files,
        # so a canonical token can name more than one fragment.
        self._fragments: dict[str, list[str]] = defaultdict(list)
        for token, path in (fragments or {}).items():
            self._fragments[canonical_token(token)].append(path)
        self._read = read
        self._loaded: dict[str, dict[tuple[str, str], str]] = {}
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)

    def dispositions(self, distro_label: str) -> Mapping[tuple[str, str], str]:
        """Every statement cached for a token, as (upstream CVE, source package) -> disposition.

        This is the enumeration the emit path needs as well as the lookup: for a
        base token it is the vendor's complete word on the release, which the
        OSV feed's affected[] is a subset of.
        """
        token = canonical_token(distro_label)
        loaded = self._loaded.get(token)
        if loaded is None:
            loaded = self._load(token)
            self._loaded[token] = loaded
        return loaded

    def _load(self, token: str) -> dict[tuple[str, str], str]:
        out: dict[tuple[str, str], str] = {}
        for path in self._fragments.get(token, []):
            if self._read is None:
                continue
            for statement in self._read(path):
                disposition = disposition_of(statement.status, statement.justification, statement.action_statement)
                if disposition is None:
                    continue
                # The CVE repeats across every package of a document and the
                # package name across every CVE, so interning both keeps one
                # copy of each string rather than one per row.
                out[(sys.intern(statement.cve), sys.intern(statement.package))] = disposition
        if out:
            self.logger.debug(f"VEX statements loaded for {token}: {len(out)}")
        return out

    def release(self) -> None:
        """Forget every loaded token. Nothing is lost; a fragment is re-read if asked again."""
        self._loaded.clear()

    def disposition(self, cve_id: str, distro_label: str, source_pkg: str) -> str | None:
        """What the cached statements say about one triple, or None if they say nothing.

        cve_id is the upstream CVE identifier (e.g. "CVE-2016-20013"), NOT the
        UBUNTU-CVE-* OSV record id. distro_label is the PURL `distro=` qualifier
        value (e.g. "noble", "esm-infra/jammy"). source_pkg is the source
        package name.
        """
        return self.dispositions(distro_label).get((cve_id, source_pkg))

    def is_wont_fix(self, cve_id: str, distro_label: str, source_pkg: str) -> bool:
        """Return True iff Canonical's VEX feed marks this triple as won't-fix.

        cve_id is the upstream CVE identifier (e.g. "CVE-2016-20013"), NOT
        the UBUNTU-CVE-* OSV record id. distro_label is the PURL `distro=`
        qualifier value (e.g. "noble", "esm-infra/jammy"). source_pkg is
        the source package name.
        """
        return self.disposition(cve_id, distro_label, source_pkg) == WONT_FIX

    def is_not_affected(self, cve_id: str, distro_label: str, source_pkg: str) -> bool:
        """Return True iff Canonical states this triple is not vulnerable, for either reason.

        This is a positive assertion of absence, which the OSV feed has no field
        able to carry. `under_investigation` is its opposite, not its neighbour,
        and is deliberately not included: it means "not yet determined", which
        the provider has always emitted as vulnerable-with-no-fix.

        Callers that emit something in place of the finding have to ask
        `disposition` instead, since only one of the two reasons is worth
        stating.
        """
        return self.disposition(cve_id, distro_label, source_pkg) in CLEARANCES

    def tokens(self) -> Iterator[str]:
        """Every canonical token the cache holds a fragment for."""
        yield from sorted(self._fragments)

    def __len__(self) -> int:
        """How many tokens are cached, which is zero for a workspace with no VEX fragments."""
        return len(self._fragments)
