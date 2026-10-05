"""Reduce Canonical's OpenVEX feed to one row per CVE.

Which pocket speaks for what is `vex_overlay`'s answer, not this module's: the
pocket vocabulary (`pocket_of_token`, `codename_of_token`, `token_asserts`,
`token_asserts_findings`) lives there next to `canonical_token`, since all four
parse the same `<pocket>/<codename>` token grammar.

Why the feed is read at all
---------------------------
VEX is the only place Canonical publishes a confirmed-not-vulnerable assertion,
and the only place "we will not fix this" is distinguishable from "no fix yet":
OSV renders both as an `affected[]` entry with no `fixed` event.

The statements are also the vendor's most complete word on which packages a CVE
affects in a release — a total function over the release's source packages,
where the OSV feed's `affected[]` lists only what is affected, so a package the
vendor has cleared is simply absent there and indistinguishable from one nobody
has looked at. So the emit path enumerates from both, and these rows decide
affectedness while OSV decides the fix version.

What a row holds
----------------
One `(token, source package, disposition)` triple per statement that says
anything. Only `arch=source` products are read: Canonical repeats each statement
across every binary architecture and the source entry carries the same
disposition, the OSV side keys on source packages too, and this cuts the row
count by about an order of magnitude.

The prose match that separates "decided not to fix" from "needs fixing" is
applied here, once, rather than being carried as an `action_statement` and
matched per release — every statement is read exactly once in this shape, so
there is nothing to be gained by deferring it.

What is never read
------------------
The `@version` on a product PURL. On a `fixed` statement it is the package's
current version in that pocket, not the version that fixed the CVE, and it is
later than the OSV fix in almost every measured pair. Fix versions come from
OSV and from the tracker snapshot, never from a statement, so a `fixed`
statement has nothing left to say and is dropped on the way in.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .vex_overlay import canonical_token, disposition_of, distro_label_from_purl, source_package_from_purl

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(frozen=True)
class _VexStatement:
    """One published statement about one source package on one distro token."""

    cve: str
    token: str
    package: str
    status: str
    justification: str | None = None
    action_statement: str | None = None


def _document_cve(document: dict[str, Any], statements: list[Any]) -> str | None:
    """The CVE a document is about, from the preamble or from a statement."""
    for container in (document, *statements):
        if not isinstance(container, dict):
            continue
        vuln = container.get("vulnerability")
        if isinstance(vuln, dict) and vuln.get("name"):
            return str(vuln["name"])
    return None


def _distill(document: dict[str, Any]) -> Iterator[_VexStatement]:
    """Reduce one VEX document to the statements worth reading.

    Only `arch=source` products are read; see the module docstring for why.
    Every status is kept here and filtered where the disposition is decided, so
    that what a status means stays in one place.
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
            yield _VexStatement(
                cve=cve,
                token=token,
                package=package,
                status=str(status),
                justification=justification,
                action_statement=action_statement,
            )


def distil_row(document: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Reduce one VEX document to `(CVE, row)`, or None when it says nothing.

    The row is a list of `[token, source package, disposition]`. A statement
    whose status has no disposition — which is `fixed`, and anything Canonical
    publishes that this does not recognize — is dropped rather than carried,
    because the emit path would drop it again and the rows are a gigabyte either
    way.
    """
    triples: list[list[str]] = []
    cve: str | None = None
    for statement in _distill(document):
        cve = statement.cve
        disposition = disposition_of(statement.status, statement.justification, statement.action_statement)
        if disposition is None:
            continue
        triples.append([statement.token, statement.package, disposition])
    if cve is None or not triples:
        return None
    return cve, {"s": triples}


def dispositions_by_token(row: dict[str, Any]) -> dict[str, dict[str, str]]:
    """One CVE's statements as `canonical token -> {source package: disposition}`.

    The two spellings of the oldest ESM pocket — `trusty/esm` and
    `esm-infra-legacy/trusty` — are one pocket written two ways, and both appear
    on both sides of the join, so they are folded onto one key here. The fold and
    what it is worth live on `canonical_token`.
    """
    out: dict[str, dict[str, str]] = defaultdict(dict)
    for token, package, disposition in row.get("s", []):
        out[canonical_token(token)][package] = disposition
    return out
