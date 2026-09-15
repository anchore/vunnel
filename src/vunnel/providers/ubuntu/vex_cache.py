"""Persist Canonical's OpenVEX feed per distro token, under the same freeze rule as OSV.

Why this has to be a cache
--------------------------
VEX is the only place Canonical publishes a confirmed-not-vulnerable assertion,
and the only place "we will not fix this" is distinguishable from "no fix yet":
OSV renders both as an `affected[]` entry with no `fixed` event. It is also
erased harder than OSV when a release dies — OSV leaves a husk of withdrawn
records behind, VEX regenerates every surviving document without the release,
so the slice collapses to a handful of stragglers or to nothing at all. Rebuilt
from each day's download, a dead release's assertions vanish the day Canonical
sweeps it.

So the statements are cached exactly as the OSV records are: one fragment per
token, replaced wholesale each run while the token's release is live, never
written again once it is frozen.

Why statements and not verdicts
-------------------------------
Rows hold `status`, `justification` and `action_statement` as published. A
frozen fragment can never be rewritten and the feed it came from no longer
carries the release, so a verdict baked in at write time is a one-way door.
Storing the statement means a change to how statements are read is a code
change rather than a cache rebuild against a feed that cannot supply one.

Why per distro token and not per release
----------------------------------------
`focal` and `esm-infra/focal` have separate lifecycles — ESM keeps publishing
for years after base support ends — and the token is what the join already keys
on. Since an LTS release never freezes, per-token and per-release give the same
freeze answer today; per-token costs nothing and is the key that exists.

What is never read
------------------
The `@version` on a product PURL. On a `fixed` statement it is the package's
current version in that pocket, not the version that fixed the CVE, and it is
later than the OSV fix in almost every measured pair. Fix versions come from
OSV and from the tracker cache, never from a statement.

What the statements are for
---------------------------
They are the vendor's most complete word on which packages a CVE affects in a
release: a total function over the release's source packages where the OSV
feed's affected[] lists only what is affected, so a package the vendor has
cleared is simply absent there and indistinguishable from one nobody has
looked at. So the emit path enumerates from both, and these rows decide
affectedness while OSV decides the fix version.
"""

from __future__ import annotations

import os
import tarfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import result, schema

from .vex_overlay import distro_label_from_purl, source_package_from_purl

if TYPE_CHECKING:
    import datetime
    import logging
    from collections.abc import Iterator

    from vunnel.workspace import Workspace

    from .eol_calendar import ReleaseCalendar

FRAGMENTS_SUBDIR = "vex-fragments"

# Written once, after the first VEX write pass that completes without error. Its
# absence is what makes a run a bootstrap run; see `VEXFragmentStore.write`.
BOOTSTRAP_MARKER = ".bootstrap-complete"

STATUS_NOT_AFFECTED = "not_affected"

_ESM_SUFFIX = "esm"

# The release's own archive, as `pocket_of_token` spells it.
BASE_POCKET = ""


def token_to_slug(token: str) -> str:
    """Map a `distro=` token to a filesystem-safe fragment name.

    `esm-infra/focal` -> `esm-infra-focal`, `focal` -> `focal`. A collision would
    need a token holding a literal `-` where another holds `/`, which Canonical's
    token vocabulary does not contain. The reverse mapping is never needed: the
    token is read back out of the rows.
    """
    return token.replace("/", "-").replace(":", "-").lower()


def codename_of_token(token: str) -> str:
    """The release codename a token names.

    Tokens come in two shapes and the pocket is on a different side in each:

      focal                    -> focal
      esm-infra/focal          -> focal      (<pocket>/<codename>)
      trusty/esm               -> trusty     (<codename>/esm)

    Taking the tail resolves `trusty/esm` to `esm`, which the calendar does not
    know, which reads as live — right for trusty by accident and wrong in
    general.
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


@dataclass(frozen=True)
class VexStatement:
    """One published statement about one source package on one distro token."""

    cve: str
    token: str
    package: str
    status: str
    justification: str | None = None
    action_statement: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "token": self.token,
            "package": self.package,
            "status": self.status,
            "justification": self.justification,
            "action_statement": self.action_statement,
        }

    @classmethod
    def from_payload(cls, payload: Any) -> VexStatement | None:
        if not isinstance(payload, dict):
            return None
        cve, token, package, status = (payload.get(k) for k in ("cve", "token", "package", "status"))
        if not (cve and token and package and status):
            return None
        return cls(
            cve=str(cve),
            token=str(token),
            package=str(package),
            status=str(status),
            justification=payload.get("justification"),
            action_statement=payload.get("action_statement"),
        )

    @property
    def identifier(self) -> str:
        return f"{token_to_slug(self.token)}/{self.cve.lower()}/{self.package}"


def _document_cve(document: dict[str, Any], statements: list[Any]) -> str | None:
    """The CVE a document is about, from the preamble or from a statement."""
    for container in (document, *statements):
        if not isinstance(container, dict):
            continue
        vuln = container.get("vulnerability")
        if isinstance(vuln, dict) and vuln.get("name"):
            return str(vuln["name"])
    return None


def distill(document: dict[str, Any]) -> Iterator[VexStatement]:
    """Reduce one VEX document to the rows worth caching.

    Only `arch=source` products are read. Canonical repeats each statement
    across every binary architecture and the source entry carries the same
    disposition; the OSV side keys on source packages too, so this is the shape
    the join needs and it cuts the row count by about an order of magnitude.

    Every status is kept. Filtering here is what made the previous overlay
    unable to answer anything but "won't fix".
    """
    statements = document.get("statements") or []
    cve = _document_cve(document, statements)
    if not cve:
        return

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        status = statement.get("status")
        if not status:
            continue
        justification = statement.get("justification")
        action_statement = statement.get("action_statement")
        for product in statement.get("products") or []:
            purl = product.get("@id") if isinstance(product, dict) else product
            if not isinstance(purl, str) or "arch=source" not in purl:
                continue
            token = distro_label_from_purl(purl)
            package = source_package_from_purl(purl)
            if not token or not package:
                continue
            yield VexStatement(
                cve=cve,
                token=token,
                package=package,
                status=str(status),
                justification=justification,
                action_statement=action_statement,
            )


def _iter_vex_documents(tar: tarfile.TarFile, logger: logging.Logger) -> Iterator[dict[str, Any]]:
    """Yield parsed VEX documents from a streaming tar (vex/cve/**/*.json only).

    USN records are skipped: they carry no per-release disposition this uses.
    """
    for member in tar:
        if not member.isfile():
            continue
        if not (member.name.startswith("vex/cve/") and member.name.endswith(".json")):
            continue
        fh = tar.extractfile(member)
        if fh is None:
            continue
        try:
            yield orjson.loads(fh.read())
        except orjson.JSONDecodeError:
            logger.warning(f"failed to parse VEX record {member.name}")


class VEXFragmentStore:
    """The per-token VEX fragments under `input/vex-fragments/`.

    One `results.db` per token, holding one envelope per
    (CVE, token, source package), written by the same writer and read by the
    same reader as the OSV fragments so both caches freeze by the same rules.
    """

    def __init__(self, workspace: Workspace, logger: logging.Logger):
        self.workspace = workspace
        self.logger = logger
        self.directory = os.path.join(workspace.input_path, FRAGMENTS_SUBDIR)

    def path_for(self, token: str) -> str:
        return os.path.join(self.directory, f"{token_to_slug(token)}.db")

    @property
    def marker_path(self) -> str:
        return os.path.join(self.directory, BOOTSTRAP_MARKER)

    @property
    def bootstrapped(self) -> bool:
        return os.path.exists(self.marker_path)

    def has_fragment(self, token: str) -> bool:
        return os.path.isfile(self.path_for(token))

    def _open_writer(self, token: str) -> result.Writer:
        os.makedirs(self.directory, exist_ok=True)
        writer = result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=self.path_for(token),
            logger=self.logger,
        )
        return writer.__enter__()

    def write(
        self,
        archive_path: str,
        calendar: ReleaseCalendar | None,
        now: datetime.datetime,
        husk_releases: frozenset[str] | set[str] = frozenset(),
    ) -> None:
        """Rewrite every live token's fragment from the archive.

        A frozen token is skipped and its fragment left exactly as the last live
        run wrote it — except on the run that introduces this cache to a
        workspace. On that one run a frozen token with no fragment is written
        from the feed, because the freeze rule protects a cache but cannot
        create one, and a cache introduced after a release's end of life would
        otherwise never hold that release at all.

        The exception is scoped to the cache rather than to the release. What is
        new on that run is this cache, not the release, so a completion marker
        records that the bootstrap happened and from then on no frozen token is
        ever written. A release in the known-husk set is excluded even during the
        bootstrap: its feed slice is residue, and recording residue is what the
        freeze rule exists to prevent.
        """
        if not os.path.isfile(archive_path):
            self.logger.warning(f"VEX archive missing at {archive_path}; cached statements are unchanged")
            return

        bootstrap = not self.bootstrapped
        if bootstrap:
            self.logger.info("no VEX cache on disk; this run bootstraps it, frozen tokens included")

        writers: dict[str, result.Writer] = {}
        skipped: set[str] = set()
        exc: BaseException | None = None
        try:
            with tarfile.open(archive_path, mode="r:xz") as tar:
                for document in _iter_vex_documents(tar, self.logger):
                    for statement in distill(document):
                        writer = self._writer_for(statement.token, writers, skipped, calendar, now, husk_releases, bootstrap)
                        if writer is None:
                            continue
                        writer.write(
                            identifier=statement.identifier,
                            schema=schema.AnnotatedOpenVEXSchema(),
                            payload=statement.to_payload(),
                        )
        except BaseException as e:
            exc = e
            raise
        finally:
            for writer in writers.values():
                writer.__exit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)

        if skipped:
            self.logger.info(f"VEX statements not written for {len(skipped)} frozen token(s): {', '.join(sorted(skipped))}")
        if bootstrap:
            self._record_bootstrap()

    def _writer_for(  # noqa: PLR0913
        self,
        token: str,
        writers: dict[str, result.Writer],
        skipped: set[str],
        calendar: ReleaseCalendar | None,
        now: datetime.datetime,
        husk_releases: frozenset[str] | set[str],
        bootstrap: bool,
    ) -> result.Writer | None:
        """The open writer for a token, opening one on first sight, or None if frozen."""
        writer = writers.get(token)
        if writer is not None:
            return writer
        if token in skipped:
            return None
        if not self._may_write(token, calendar, now, husk_releases, bootstrap):
            skipped.add(token)
            return None
        writers[token] = self._open_writer(token)
        return writers[token]

    def _may_write(
        self,
        token: str,
        calendar: ReleaseCalendar | None,
        now: datetime.datetime,
        husk_releases: frozenset[str] | set[str],
        bootstrap: bool,
    ) -> bool:
        if calendar is None:
            return True
        codename = codename_of_token(token)
        release = calendar.get(codename)
        # a token whose codename the calendar does not know is live
        if release is None or not calendar.frozen(codename, now):
            return True
        if not bootstrap or self.has_fragment(token):
            return False
        return release.version not in husk_releases

    def _record_bootstrap(self) -> None:
        """Mark the bootstrap complete. Only reached when the write pass raised nothing.

        An interrupted bootstrap leaves no marker, so the next run resumes it for
        whatever frozen tokens still have no fragment rather than leaving the
        cache half-frozen.
        """
        os.makedirs(self.directory, exist_ok=True)
        with open(self.marker_path, "wb"):
            pass
        self.logger.info("VEX cache bootstrap complete; frozen tokens will not be written again")

    def tokens_on_disk(self) -> list[str]:
        if not os.path.isdir(self.directory):
            return []
        return sorted(f[: -len(".db")] for f in os.listdir(self.directory) if f.endswith(".db"))

    def fragment_paths(self) -> dict[str, str]:
        """Every cached token and the fragment holding it.

        The token is read out of a row rather than recovered from the file name:
        the slug replaces `/` with `-` and `esm-infra/focal` and a hypothetical
        `esm-infra-focal` would spell the same file. Every row in a fragment
        carries the same token, so one row answers it.
        """
        out: dict[str, str] = {}
        for slug in self.tokens_on_disk():
            path = os.path.join(self.directory, f"{slug}.db")
            token = self._token_of_fragment(path)
            if token is None:
                self.logger.warning(f"could not read the token from VEX fragment {path}; skipping it")
                continue
            out[token] = path
        return out

    def _token_of_fragment(self, path: str) -> str | None:
        try:
            with result.SQLiteReader(path) as reader:
                for envelope in reader.each():
                    statement = VexStatement.from_payload(envelope.item)
                    return statement.token if statement is not None else None
        except Exception as e:  # a corrupt fragment must not take down the run
            self.logger.warning(f"could not read VEX fragment {path}: {e}")
        return None

    def statements_at(self, path: str) -> Iterator[VexStatement]:
        """Every statement in one token's fragment."""
        try:
            with result.SQLiteReader(path) as reader:
                for envelope in reader.each():
                    statement = VexStatement.from_payload(envelope.item)
                    if statement is not None:
                        yield statement
        except Exception as e:  # a corrupt fragment must not take down the run
            self.logger.warning(f"could not read VEX fragment {path}: {e}")

    def statements(self) -> Iterator[VexStatement]:
        """Every cached statement, across every token's fragment."""
        if not os.path.isdir(self.directory):
            return
        for slug in self.tokens_on_disk():
            yield from self.statements_at(os.path.join(self.directory, f"{slug}.db"))
