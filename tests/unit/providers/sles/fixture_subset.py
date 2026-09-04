"""Trim a real SUSE CSAF VEX document down to only its plain + LTSS SLES data.

This is fixture-generation tooling, not provider code: the committed fixtures under
test-fixtures/csaf/ are real corpus documents passed through subset_for_sles() rather
than hand-authored, so their product trees, product_status categories and remediations
stay exactly as SUSE spells them. Keeping the trimmer here is what makes adding a new
fixture from the real corpus reproducible.

To add a fixture:

    from vunnel.utils.csaf_types import from_path
    from tests.unit.providers.sles.fixture_subset import subset_for_sles

    doc = from_path("<corpus>/cve-YYYY-NNNNN.json")
    subsetted = subset_for_sles(doc, allow_versions=["15"])
    # write subsetted.to_dict() to test-fixtures/csaf/
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from vunnel.providers.sles.csaf_parser import _in_scope_platform_namespaces
from vunnel.utils.csaf_types import ProductStatus, ProductTree

if TYPE_CHECKING:
    from vunnel.utils.csaf_types import Branch, CSAFDoc, Flag, Remediation, Score, Threat, Vulnerability

_PRODUCT_STATUS_FIELDS = (
    "first_affected",
    "first_fixed",
    "fixed",
    "known_affected",
    "known_not_affected",
    "last_affected",
    "recommended",
    "under_investigation",
)


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


def _filter_ids(ids: list[str], filter_ids: set[str]) -> list[str]:
    return [i for i in ids if i in filter_ids]


def _subset_product_status(ps: ProductStatus | None, filter_ids: set[str]) -> ProductStatus | None:
    if ps is None:
        return None
    kwargs = {f: _filter_ids(getattr(ps, f), filter_ids) for f in _PRODUCT_STATUS_FIELDS}
    if not any(kwargs.values()):
        return None
    return ProductStatus(**kwargs)


def _subset_remediations(remediations: list[Remediation], filter_ids: set[str]) -> list[Remediation]:
    result = []
    for r in remediations:
        product_ids = _filter_ids(r.product_ids, filter_ids)
        if product_ids:
            new_r = copy.deepcopy(r)
            new_r.product_ids = product_ids
            result.append(new_r)
    return result


def _subset_threats(threats: list[Threat], filter_ids: set[str]) -> list[Threat]:
    result = []
    for t in threats:
        if not t.product_ids:
            # threats aren't required to name specific products; keep as-is
            result.append(t)
            continue
        product_ids = _filter_ids(t.product_ids, filter_ids)
        if product_ids:
            new_t = copy.deepcopy(t)
            new_t.product_ids = product_ids
            result.append(new_t)
    return result


def _subset_flags(flags: list[Flag], filter_ids: set[str]) -> list[Flag]:
    result = []
    for f in flags:
        product_ids = _filter_ids(f.product_ids, filter_ids)
        if product_ids:
            new_f = copy.deepcopy(f)
            new_f.product_ids = product_ids
            result.append(new_f)
    return result


def _subset_scores(scores: list[Score], filter_ids: set[str]) -> list[Score]:
    result = []
    for s in scores:
        products = _filter_ids(s.products, filter_ids)
        if products:
            new_s = copy.deepcopy(s)
            new_s.products = products
            result.append(new_s)
    return result


def _subset_vulnerability(vuln: Vulnerability, filter_ids: set[str]) -> Vulnerability | None:
    product_status = _subset_product_status(vuln.product_status, filter_ids)
    remediations = _subset_remediations(vuln.remediations, filter_ids)
    if product_status is None and not remediations:
        return None
    out = copy.deepcopy(vuln)
    out.product_status = product_status
    out.remediations = remediations
    out.threats = _subset_threats(vuln.threats, filter_ids)
    out.flags = _subset_flags(vuln.flags, filter_ids)
    out.scores = _subset_scores(vuln.scores, filter_ids)
    return out


def subset_for_sles(doc: CSAFDoc, allow_versions: list[str] | None = None) -> CSAFDoc | None:
    """Trim a CSAF VEX document down to its plain + LTSS SLES data, for the
    downconvert_to_os_schema=False path."""
    if doc.product_tree is None:
        return None

    allow_set = {str(v) for v in allow_versions} if allow_versions is not None else None
    tree = doc.product_tree

    platform_ids = _in_scope_platform_namespaces(tree, allow_set).keys()

    if not platform_ids:
        return None

    kept_relationships = []
    composite_ids: set[str] = set()
    package_refs: set[str] = set()
    for rel in tree.relationships:
        if rel.relates_to_product_reference not in platform_ids:
            continue
        kept_relationships.append(rel)
        composite_ids.add(rel.full_product_name.product_id)
        package_refs.add(rel.product_reference)

    filter_ids = platform_ids | composite_ids
    branch_ids = platform_ids | package_refs
    pruned_branches = _prune_branches(tree.branches, branch_ids)

    subsetted_vulns = [sv for v in doc.vulnerabilities if (sv := _subset_vulnerability(v, filter_ids)) is not None]
    if not subsetted_vulns:
        return None

    out = copy.deepcopy(doc)
    out.product_tree = ProductTree(relationships=kept_relationships, branches=pruned_branches)
    out.vulnerabilities = subsetted_vulns
    return out
