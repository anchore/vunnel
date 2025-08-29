from collections.abc import Callable
from typing import Any

from vunnel.tool import fixdate


def patch_fix_date(
    advisory: dict[str, Any],
    fixdater: fixdate.Finder | None,
    ecosystem_processor: Callable[[str], str] | None = None,
) -> None:
    if not fixdater:
        return

    vuln_id: str = advisory.get("id")  # type: ignore[assignment]

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
            _process_fix_dates_for_range(r, vuln_id, package_name, ecosystem, fixdater)


def _process_fix_dates_for_range(
    range_data: dict[str, Any],
    vuln_id: str,
    package_name: str,
    ecosystem: str,
    fixdater: fixdate.Finder,
) -> None:
    """Process fix dates for events in a range and update database_specific field."""
    new_available = []
    for event in range_data.get("events", []):
        fix_version = event.get("fixed")

        # Skip events without a valid fix version
        if not fix_version:
            continue

        dates = fixdater.find(
            vuln_id=vuln_id,
            cpe_or_package=package_name,
            fix_version=fix_version,
            ecosystem=ecosystem,
        )
        if not dates:
            continue

        result = dates[0]
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
