"""Parse the target RHEL minor version (and extended-support channel) out of a CSAF/Hydra product_id.

Red Hat's CSAF advisories identify a fixed build with a "full product id" (FPI) string. The FPI
encodes which RHEL *minor* stream the build targets, but that minor is NOT present in the
human-readable ``product_name`` ("Red Hat Enterprise Linux 9") nor in the platform CPE
("cpe:/a:redhat:enterprise_linux:9") -- both of which collapse every minor of a major into one
bucket. The minor is only recoverable from the FPI's platform prefix.

Two FPI prefix formats exist and Red Hat is migrating from the first to the second, so both must be
handled (detected per-record):

OLD format -- the platform prefix is ``{Repo}-{MAJOR}.{MINOR}[.{Z}][.{markers}]``::

    AppStream-9.5.0.GA:webkit2gtk3-0:2.44.3-2.el9.x86_64          -> minor 5,  channel "ga"
    AppStream-8.2.0.Z.EUS:bind-32:9.11.13-6.el8_2.3.x86_64        -> minor 2,  channel "eus"
    BaseOS-9.4.0.Z.MAIN.EUS:glibc-0:2.34-100.el9_4.x86_64         -> minor 4,  channel "eus"
    AppStream-9.5.Z:foo-0:1-1.el9_5.x86_64                        -> minor 5,  channel "ga"
    AppStream-8.4.0.Z.AUS:bar-0:1-1.el8_4.x86_64                  -> minor 4,  channel "aus"
    AppStream-8.8.0.Z.ENS:foo-0:1-1.el8_8.x86_64                  -> minor 8,  channel None (unknown marker)
    7Server-ELS:webkitgtk4-0:2.48.3-2.el7_9.x86_64               -> minor None, channel "els"
    6Server-ELS.EXTENSION:bind-32:9.8.2-0.68.rc1.el6_10.17.x86_64 -> minor None, channel "els"

NEW format -- the platform prefix is ``rhel-{MAJOR}.{MINOR}[-marker]``::

    rhel-9.5::appstream:webkit2gtk3-0:2.44.3-2.el9                -> minor 5,  channel "ga"
    rhel-8.6-eus::appstream:foo-0:1-1.el8_6                       -> minor 6,  channel "eus"

The channel is TRI-STATE:

* a recognized GENERAL marker yields ``"ga"`` (generally available): the GA compose (``.GA``), a
  z-stream MAIN with no extended token (``.Z.MAIN``), and new-format ids with no extended marker
  (``rhel-9.4::appstream:...``);
* a recognized EXTENDED token yields that canonical lowercase token: ``eus``, ``e4s``, ``aus``,
  ``tus`` (pinned-minor maintenance streams) or ``els`` (extended *lifecycle* support, major-only);
* ANYTHING unrecognized -- an unexpected marker such as ``.Z.ENS``, garbage input, or a non-RHEL
  product (e.g. OpenShift) -- yields ``None`` (unknown). ``None`` does NOT mean "generally available";
  unknown is never assumed to be GA.

The minor and the channel are independent: ELS yields ``minor=None`` (major-only stream) but a real
``els`` channel, while GA/EUS/E4S/AUS/TUS yield both a minor and their channel token. If the minor
cannot be determined the parser returns ``minor=None`` rather than guessing.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# Dot-separated tokens (old format) or hyphen suffix (new format) that mark a pinned-MINOR extended
# maintenance stream. Matched case-insensitively as whole tokens and normalized to lowercase tokens.
# NOTE: ELS is intentionally NOT here. Extended Lifecycle Support is a MAJOR-only stream (e.g.
# "7Server-ELS", no minor in the prefix), so it never appears as a versioned dot-token alongside a
# minor the way these do. It is recognized by its own branch in parse_product_id (the trailing
# "-ELS" marker) and yields minor=None, channel="els". Adding it here would be wrong -- these markers
# are scanned only against a versioned prefix's tokens, where ELS does not occur.
_EXTENDED_MARKERS = ("EUS", "E4S", "AUS", "TUS")

# Recognized GENERAL (non-extended) markers. Their presence -- or, in the new format, the absence of
# ANY marker -- means the build ships generally available and resolves to the explicit ``"ga"`` token.
# ``GA`` is the GA compose; ``Z`` and ``MAIN`` appear in z-stream main-channel ids (e.g. ``.Z.MAIN``).
# Any token NOT in this set and NOT an extended marker (e.g. ``ENS``) is unrecognized -> channel None.
_GENERAL_MARKERS = ("GA", "Z", "MAIN")

# OLD format platform prefix, e.g. "AppStream-9.5.0.GA", "BaseOS-9.4.0.Z.MAIN.EUS", "AppStream-9.5.Z".
# Capture the repo label, then MAJOR.MINOR (minor optional in case only a major is present), then the
# trailing marker tokens. The version-like part is "{MAJOR}.{MINOR}" optionally followed by ".{Z}"
# and any number of ".{TOKEN}" markers.
_OLD_PREFIX = re.compile(
    r"^(?P<repo>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*?)-(?P<major>\d+)\.(?P<minor>\d+)(?P<rest>(?:\.[A-Za-z0-9]+)*)$",
)

# NEW format platform prefix, e.g. "rhel-9.5", "rhel-8.6-eus".
_NEW_PREFIX = re.compile(
    r"^rhel-(?P<major>\d+)\.(?P<minor>\d+)(?:-(?P<marker>[A-Za-z0-9]+))?$",
)

# RPM dist tag carried in a build's release, used as a fallback when the FPI is unavailable. The
# minor is encoded in exactly two tag shapes:
#   * the Z-stream/EUS form ".elN_M" -- the underscore is the minor separator (".el9_2" -> 2);
#   * the modular form "+elN.M"     -- preceded by "+", a dot then carries the minor ("+el8.1.0" -> 1).
# A bare GA tag ".elN" carries NO minor, and a GA respin suffix ".elN.M" (a DOT after a plain ".el",
# e.g. "7.2-3.el7.1") is a rebuild counter, NOT a minor -- so neither yields one (only the FPI can
# supply a GA build's minor). Two alternatives keep "_" (any tag) distinct from "." (modular "+el" only).
_DIST_TAG_MINOR = re.compile(r"(?:(?:^|[.+])el\d+_(?P<zminor>\d+))|(?:\+el\d+\.(?P<modminor>\d+))")


class ProductIdInfo(NamedTuple):
    """Parsed view of a product_id: the target minor (or None) and the TRI-STATE channel.

    ``channel`` is one of:

    * ``"ga"`` -- a recognized GENERAL marker (the GA compose ``.GA``, a z-stream ``.Z.MAIN`` with no
      extended token, or a new-format id with no extended marker); the build is generally available;
    * a canonical lowercase extended token (``"eus"``, ``"e4s"``, ``"aus"``, ``"tus"``, ``"els"``)
      when the FPI targets that extended-support channel;
    * ``None`` (UNKNOWN) when no recognized marker was found -- an unexpected marker (e.g. ``.Z.ENS``),
      garbage input, or a non-RHEL product. ``None`` does NOT mean "generally available".
    """

    minor: int | None
    channel: str | None


def _platform_prefix(product_id: str) -> str:
    """Return the platform/stream prefix of an FPI.

    NEW format uses ``::`` to separate the platform from the repo (``rhel-9.5::appstream:...``), so
    for new-format ids the prefix is everything before the first ``::``.

    OLD format uses a single ``:`` between platform and package (``AppStream-9.5.0.GA:webkit...``);
    the prefix is everything before the first ``:``. Note ``::`` ALSO appears in old-format *modular*
    ids, but only as a trailing module-name suffix (``...x86_64::squid:4``), so we must NOT split old
    ids on ``::``. Distinguish purely by the ``rhel-`` marker that opens the new format.
    """
    if product_id.startswith("rhel-"):
        return product_id.split("::", 1)[0]
    return product_id.split(":", 1)[0]


def _channel_from_tokens(tokens: list[str]) -> str | None:
    """Resolve the TRI-STATE channel from a build's marker tokens.

    * If any token is a recognized EXTENDED marker, return its canonical lowercase token (extended
      wins over general -- e.g. ``.Z.MAIN.EUS`` is ``"eus"``).
    * Otherwise, if every (non-numeric) token is a recognized GENERAL marker (``GA``/``Z``/``MAIN``),
      the build is generally available -> ``"ga"``. Purely-numeric tokens (the z-stream position digit
      in ``.0.GA``) are ignored for classification.
    * Otherwise (an unrecognized token such as ``ENS`` is present), the channel is unknown -> ``None``.
    """
    # Drop purely-numeric tokens (e.g. the "0" in ".0.GA"); they carry no channel meaning.
    upper = [t.upper() for t in tokens if not t.isdigit()]
    for marker in _EXTENDED_MARKERS:
        if marker in upper:
            return marker.lower()
    if upper and all(t in _GENERAL_MARKERS for t in upper):
        return "ga"
    return None


def parse_product_id(product_id: str | None) -> ProductIdInfo:
    """Parse the target RHEL minor and extended-support channel out of a CSAF/Hydra product_id (full product id).

    Detects the OLD (``AppStream-9.5.0.GA:...``) and NEW (``rhel-9.5::...``) formats automatically and
    returns a :class:`ProductIdInfo`. ``channel`` is TRI-STATE: ``"ga"`` for a recognized generally-
    available build, a lowercase token (``eus``/``e4s``/``aus``/``tus``/``els``) for an extended-support
    stream, or ``None`` (unknown) when no recognized marker was found. ``None`` is NOT assumed to be GA.
    When the minor cannot be determined (empty/garbage input, or a major-only stream such as
    ``7Server-ELS``), ``minor`` is ``None`` and we do not guess.
    """
    if not product_id:
        return ProductIdInfo(minor=None, channel=None)

    prefix = _platform_prefix(product_id)

    # NEW format: rhel-{major}.{minor}[-marker]
    new_match = _NEW_PREFIX.match(prefix)
    if new_match:
        minor = int(new_match.group("minor"))
        marker = new_match.group("marker")
        # No marker in the new format means generally available -> "ga"; a marker is resolved
        # tri-state (extended token, or None when unrecognized).
        channel = _channel_from_tokens([marker]) if marker else "ga"
        return ProductIdInfo(minor=minor, channel=channel)

    # OLD format: {Repo}-{major}.{minor}[.{Z}][.{markers}]
    old_match = _OLD_PREFIX.match(prefix)
    if old_match:
        minor = int(old_match.group("minor"))
        rest = old_match.group("rest") or ""
        # rest looks like ".0.GA" or ".Z.MAIN.EUS"; split into dot tokens and resolve tri-state.
        tokens = [t for t in rest.split(".") if t]
        channel = _channel_from_tokens(tokens)
        return ProductIdInfo(minor=minor, channel=channel)

    # ELS: extended *lifecycle* support is a major-only stream (no minor in the prefix), but it IS an
    # extended-support channel. Recognize the "-ELS" marker even when no minor parses; it may end the
    # prefix ("7Server-ELS") or be followed by a dotted repo segment ("6Server-ELS.EXTENSION" on RHEL 6).
    if re.search(r"(?:^|-)ELS(?:[.:]|$)", prefix, flags=re.IGNORECASE):
        return ProductIdInfo(minor=None, channel="els")

    # No recognizable minor or channel (garbage, or a non-RHEL product). Do not guess.
    return ProductIdInfo(minor=None, channel=None)


def minor_from_dist_tag(version: str | None) -> int | None:
    """Recover the target RHEL minor from an RPM version's own ``.elN_M`` dist tag.

    Used as a fallback when no FPI/product_id is available (e.g. fix builds resolved off the
    CVE/Hydra path, which carry no FPI) so the minor can still be recovered from the facts already
    present in the version string. The minor is only encoded in the Z-stream/EUS form ``.elN_M``
    (``0:2.34-60.el9_2.7`` -> ``2``) or in a modular ``+elN.M`` tag (``...module+el8.1.0+...`` -> 1).

    A bare GA build whose tag is just ``.elN`` (e.g. ``0:2.34-100.el9``) encodes NO minor -- only the
    FPI can supply one for a GA build -- so this returns ``None`` for it rather than guessing. Returns
    ``None`` for empty input or a version with no recognizable dist tag.
    """
    if not version:
        return None
    match = _DIST_TAG_MINOR.search(version)
    if match:
        minor = match.group("zminor") or match.group("modminor")
        return int(minor)
    return None
