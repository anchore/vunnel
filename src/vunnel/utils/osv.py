from collections.abc import Callable
from typing import Any

from vunnel.tool import fixdate

ExtraCandidatesCallable = Callable[[str, str, str, str | None], list["fixdate.Result"]]


def patch_fix_date(
    advisory: dict[str, Any],
    fixdater: fixdate.Finder,
    ecosystem_processor: Callable[[str], str] | None = None,
    vuln_id_override: str | None = None,
    extra_candidates: ExtraCandidatesCallable | None = None,
) -> None:
    """Patch database_specific.anchore.fixes on each affected range with first-observed dates.

    `vuln_id_override` lets a caller pass a different vuln_id than `advisory["id"]`
    for the fixdater lookup. Needed when the OSV record's id is provider-internal
    (e.g. Canonical's `UBUNTU-CVE-*`) but the fix-date cache keys by the upstream
    CVE (e.g. `CVE-*`). Without it, the lookup silently misses and every range
    falls back to the (often wrong) published-date candidate.

    `extra_candidates` lets a caller inject provider-specific candidate fix dates
    that are typically more authoritative than the advisory's `published` field
    (e.g. the ubuntu provider passes the corresponding USN's `published` date,
    which is the real fix-ship date). Signature: callable taking
    (vuln_id, package_name, fix_version, ecosystem) and returning a list of
    fixdate.Result candidates. Candidates with accurate=True are preferred by
    fixdater.best().
    """
    if not fixdater:
        return

    vuln_id: str = vuln_id_override or advisory.get("id")  # type: ignore[assignment]
    published = advisory.get("published")

    for affected in advisory.get("affected", []):
        package_name = affected.get("package", {}).get("name")
        if not package_name:
            continue

        ecosystem = affected.get("package", {}).get("ecosystem")
        if not ecosystem:
            continue

        if ecosystem_processor:
            ecosystem = ecosystem_processor(ecosystem)

        for r in affected.get("ranges", []):
            _process_fix_dates_for_range(r, vuln_id, package_name, ecosystem, published, fixdater, extra_candidates)


def _process_fix_dates_for_range(  # noqa: PLR0913
    range_data: dict[str, Any],
    vuln_id: str,
    package_name: str,
    ecosystem: str,
    published: str | None,
    fixdater: fixdate.Finder,
    extra_candidates: ExtraCandidatesCallable | None = None,
) -> None:
    """Process fix dates for events in a range and update database_specific field."""
    new_available = []
    for event in range_data.get("events", []):
        fix_version = event.get("fixed")

        # Skip events without a valid fix version
        if not fix_version:
            continue

        candidates = []
        # Provider-supplied authoritative candidates first; fixdater.best() picks the most accurate.
        if extra_candidates is not None:
            candidates.extend(extra_candidates(vuln_id, package_name, fix_version, ecosystem))
        if published:
            candidates.append(
                fixdate.Result(
                    date=published,  # type: ignore[arg-type]
                    kind="advisory",
                    # it isn't clear that for any arbitrary osv record the published date
                    # is actually the fix date, so we mark it as not accurate
                    accurate=False,
                ),
            )

        result = fixdater.best(
            vuln_id=vuln_id,
            cpe_or_package=package_name,
            fix_version=fix_version,
            ecosystem=ecosystem,
            candidates=candidates,
        )
        if not result or not result.date:
            continue

        available = {
            "version": fix_version,
            "date": result.date.isoformat(),
            "kind": result.kind,
        }
        new_available.append(available)

    # we want to preserve any existing database specific data, and add a new anchore-specific field
    if new_available:
        db_spec = range_data.get("database_specific", {})
        db_spec["anchore"] = {"fixes": new_available}
        range_data["database_specific"] = db_spec
