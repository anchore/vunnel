from __future__ import annotations

import copy
import os
from typing import TYPE_CHECKING

from vunnel.utils.csaf_types import (
    Branch,
    CSAFDoc,
    ProductStatus,
    ProductTree,
    Relationship,
    Remediation,
    Score,
    Threat,
    Vulnerability,
    from_path,
)

from .csaf_client import CSAFVEXClient

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

    from vunnel.utils.csaf_types import Flag
    from vunnel.workspace import Workspace

HUMMINGBIRD_CPE_PREFIX = "cpe:/a:redhat:hummingbird"


def _is_hummingbird_cpe(cpe: str | None) -> bool:
    if not cpe:
        return False
    return cpe.startswith(HUMMINGBIRD_CPE_PREFIX)


class Parser:
    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger,
        max_workers: int = 16,
        skip_download: bool = False,
    ):
        self.workspace = workspace
        self.logger = logger
        self.max_workers = max_workers
        self.skip_download = skip_download

    def get(self) -> Generator[tuple[str, CSAFDoc]]:
        """Yield (cve_id, subsetted_csaf_doc) for each CVE that affects hummingbird."""
        client = CSAFVEXClient(
            workspace=self.workspace,
            logger=self.logger,
            max_workers=self.max_workers,
            skip_download=self.skip_download,
        )

        cve_paths = client.cve_paths()
        self.logger.info(f"processing {len(cve_paths)} CVE files")

        for path in cve_paths:
            try:
                result = self._process_cve_file(path)
            except Exception:
                self.logger.exception(f"error processing {path}")
                continue

            if result is not None:
                yield result

    def _process_cve_file(self, path: str) -> tuple[str, CSAFDoc] | None:
        doc = from_path(path)

        subsetted = self._subset_document(doc)
        if subsetted is None:
            return None

        cve_id = os.path.splitext(os.path.basename(path))[0]
        return cve_id, subsetted

    # ── subsetting ────────────────────────────────────────────────────

    def _subset_document(self, doc: CSAFDoc) -> CSAFDoc | None:
        """Create a valid CSAF VEX document containing only hummingbird data.

        The approach works in layers, each derived from the previous:

        1. Find hummingbird platform product IDs by CPE-matching branches.
        2. Keep only relationships where relates_to_product_reference is a
           hummingbird platform. Collect the composite IDs and bare package
           references from those kept relationships.
        3. Prune branches to keep platform branches + package branches that
           are referenced by kept relationships.
        4. Filter vulnerability fields (product_status, remediations, scores,
           etc.) using only the composite relationship IDs + platform IDs.
        """
        tree = doc.product_tree

        # step 1: find hummingbird platform IDs from branch CPEs
        platform_ids: set[str] = set()
        for branch in tree.product_branches():
            cpe = branch.cpe()
            if _is_hummingbird_cpe(cpe) and branch.product_id():
                platform_ids.add(branch.product_id())  # type: ignore[arg-type]

        if not platform_ids:
            return None

        # step 2: keep relationships where the platform is hummingbird
        kept_relationships, composite_ids, package_refs = _collect_hummingbird_relationships(
            tree.relationships,
            platform_ids,
        )

        # the set of IDs that can appear in product_status, remediations, etc.
        filter_ids = platform_ids | composite_ids

        # step 3: prune branches
        branch_ids = platform_ids | package_refs
        pruned_branches = _prune_branches(tree.branches, branch_ids)

        # step 4: subset vulnerabilities
        subsetted_vulns = [sv for v in doc.vulnerabilities if (sv := _subset_vulnerability(v, filter_ids)) is not None]

        if not subsetted_vulns:
            return None

        out = copy.deepcopy(doc)
        out.product_tree = ProductTree(
            relationships=kept_relationships,
            branches=pruned_branches,
        )
        out.vulnerabilities = subsetted_vulns

        return out


# ── helpers (module-level for static analysis) ────────────────────────


def _collect_hummingbird_relationships(
    relationships: list[Relationship],
    platform_ids: set[str],
) -> tuple[list[Relationship], set[str], set[str]]:
    """Return (kept_relationships, composite_ids, package_refs) for hummingbird platforms."""
    kept: list[Relationship] = []
    composite_ids: set[str] = set()
    package_refs: set[str] = set()

    for rel in relationships:
        if rel.relates_to_product_reference not in platform_ids:
            continue
        kept.append(rel)
        composite_ids.add(rel.full_product_name.product_id)
        package_refs.add(rel.product_reference)

    return kept, composite_ids, package_refs


def _prune_branches(branches: list[Branch], keep_ids: set[str]) -> list[Branch]:
    """Recursively prune branches, keeping only paths that lead to a product in keep_ids."""
    kept = []
    for branch in branches:
        is_kept = branch.product is not None and branch.product.product_id in keep_ids
        pruned_children = _prune_branches(branch.branches, keep_ids)

        if is_kept or pruned_children:
            new_branch = copy.copy(branch)
            new_branch.branches = pruned_children if pruned_children else []
            kept.append(new_branch)

    return kept


def _subset_vulnerability(vuln: Vulnerability, filter_ids: set[str]) -> Vulnerability | None:
    filtered_ps = _filter_product_status(vuln.product_status, filter_ids)
    if filtered_ps is None:
        return None

    out = copy.deepcopy(vuln)
    out.product_status = filtered_ps
    out.remediations = _filter_by_product_ids(vuln.remediations, filter_ids)
    out.threats = _filter_threats(vuln.threats, filter_ids)
    out.flags = _filter_flags(vuln.flags, filter_ids)
    out.scores = _filter_scores(vuln.scores, filter_ids)
    return out


def _filter_product_status(ps: ProductStatus | None, filter_ids: set[str]) -> ProductStatus | None:
    if ps is None:
        return None

    fixed = [pid for pid in ps.fixed if pid in filter_ids]
    known_affected = [pid for pid in ps.known_affected if pid in filter_ids]
    known_not_affected = [pid for pid in ps.known_not_affected if pid in filter_ids]
    under_investigation = [pid for pid in ps.under_investigation if pid in filter_ids]

    if not any([fixed, known_affected, known_not_affected, under_investigation]):
        return None

    return ProductStatus(
        fixed=fixed,
        known_affected=known_affected,
        known_not_affected=known_not_affected,
        under_investigation=under_investigation,
    )


def _filter_scores(scores: list[Score], filter_ids: set[str]) -> list[Score]:
    result = []
    for score in scores:
        products = [p for p in score.products if p in filter_ids]
        if products:
            s = copy.deepcopy(score)
            s.products = products
            result.append(s)
    return result


def _filter_by_product_ids(remediations: list[Remediation], filter_ids: set[str]) -> list[Remediation]:
    result = []
    for rem in remediations:
        filtered = [pid for pid in rem.product_ids if pid in filter_ids]
        if filtered:
            r = copy.deepcopy(rem)
            r.product_ids = filtered
            result.append(r)
    return result


def _filter_threats(threats: list[Threat], filter_ids: set[str]) -> list[Threat]:
    result = []
    for threat in threats:
        filtered = [pid for pid in threat.product_ids if pid in filter_ids]
        if filtered:
            t = copy.deepcopy(threat)
            t.product_ids = filtered
            result.append(t)
    return result


def _filter_flags(flags: list[Flag], filter_ids: set[str]) -> list[Flag]:
    result = []
    for flag in flags:
        filtered = [pid for pid in flag.product_ids if pid in filter_ids]
        if filtered:
            f = copy.deepcopy(flag)
            f.product_ids = filtered
            result.append(f)
    return result
