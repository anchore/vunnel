from __future__ import annotations

import copy
import os
from typing import TYPE_CHECKING, Any

import orjson

from .csaf_client import CSAFVEXClient

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

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

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """Yield (cve_id, subsetted_csaf_dict) for each CVE that affects hummingbird."""
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

    def _process_cve_file(self, path: str) -> tuple[str, dict[str, Any]] | None:
        with open(path, "rb") as fh:
            doc = orjson.loads(fh.read())

        subsetted = self._subset_document(doc)
        if subsetted is None:
            return None

        cve_id = os.path.splitext(os.path.basename(path))[0]
        return cve_id, subsetted

    # ── subsetting ────────────────────────────────────────────────────

    def _subset_document(self, doc: dict[str, Any]) -> dict[str, Any] | None:
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
        product_tree = doc.get("product_tree", {})

        # step 1: find hummingbird platform IDs from branch CPEs
        platform_ids: set[str] = set()
        self._collect_platform_ids(product_tree.get("branches", []), platform_ids)
        if not platform_ids:
            return None

        # step 2: keep relationships where the platform is hummingbird
        kept_relationships, composite_ids, package_refs = self._collect_hummingbird_relationships(
            product_tree.get("relationships", []),
            platform_ids,
        )

        # the set of IDs that can appear in product_status, remediations, etc.
        filter_ids = platform_ids | composite_ids

        # step 3: prune branches - keep platforms and referenced packages
        branch_ids = platform_ids | package_refs
        pruned_branches = self._prune_branches(product_tree.get("branches", []), branch_ids)

        # step 4: subset vulnerabilities using filter_ids
        subsetted_vulns = [sv for vuln in doc.get("vulnerabilities", []) if (sv := self._subset_vulnerability(vuln, filter_ids)) is not None]

        if not subsetted_vulns:
            return None

        out = copy.deepcopy(doc)
        out["product_tree"] = {}
        if pruned_branches:
            out["product_tree"]["branches"] = pruned_branches
        if kept_relationships:
            out["product_tree"]["relationships"] = kept_relationships
        out["vulnerabilities"] = subsetted_vulns

        return out

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _collect_hummingbird_relationships(
        relationships: list[dict[str, Any]],
        platform_ids: set[str],
    ) -> tuple[list[dict[str, Any]], set[str], set[str]]:
        """Return (kept_relationships, composite_ids, package_refs) for hummingbird platforms."""
        kept: list[dict[str, Any]] = []
        composite_ids: set[str] = set()
        package_refs: set[str] = set()

        for rel in relationships:
            if rel.get("relates_to_product_reference") not in platform_ids:
                continue
            kept.append(rel)
            fpn_id = rel.get("full_product_name", {}).get("product_id")
            if fpn_id:
                composite_ids.add(fpn_id)
            prod_ref = rel.get("product_reference")
            if prod_ref:
                package_refs.add(prod_ref)

        return kept, composite_ids, package_refs

    def _collect_platform_ids(self, branches: list[dict[str, Any]], platform_ids: set[str]) -> None:
        """Recursively find branch product IDs that have a hummingbird CPE."""
        for branch in branches:
            product = branch.get("product")
            if product:
                helper = product.get("product_identification_helper", {})
                if _is_hummingbird_cpe(helper.get("cpe")):
                    pid = product.get("product_id")
                    if pid:
                        platform_ids.add(pid)
            self._collect_platform_ids(branch.get("branches", []), platform_ids)

    def _prune_branches(self, branches: list[dict[str, Any]], keep_ids: set[str]) -> list[dict[str, Any]]:
        """Recursively prune branches, keeping only paths that lead to a product in keep_ids."""
        kept = []
        for branch in branches:
            product = branch.get("product")
            is_kept = product is not None and product.get("product_id") in keep_ids

            pruned_children = self._prune_branches(branch.get("branches", []), keep_ids)

            if is_kept or pruned_children:
                new_branch = {k: v for k, v in branch.items() if k != "branches"}
                if pruned_children:
                    new_branch["branches"] = pruned_children
                kept.append(new_branch)

        return kept

    def _subset_vulnerability(self, vuln: dict[str, Any], filter_ids: set[str]) -> dict[str, Any] | None:
        out = {}

        # copy scalar / metadata fields as-is
        for key in ("cve", "title", "cwe", "discovery_date", "release_date", "notes", "references", "ids"):
            if key in vuln:
                out[key] = vuln[key]

        # filter product_status lists
        filtered_ps = self._filter_product_status(vuln.get("product_status", {}), filter_ids)
        if not filtered_ps:
            return None
        out["product_status"] = filtered_ps

        # filter list-of-dicts fields that have product_ids
        for key in ("remediations", "threats", "flags"):
            if key in vuln:
                filtered = self._filter_by_product_ids(vuln[key], filter_ids)
                if filtered:
                    out[key] = filtered

        # filter scores
        if "scores" in vuln:
            filtered_scores = self._filter_scores(vuln["scores"], filter_ids)
            if filtered_scores:
                out["scores"] = filtered_scores

        return out

    @staticmethod
    def _filter_product_status(ps: dict[str, Any], filter_ids: set[str]) -> dict[str, Any]:
        filtered_ps = {}
        for status_key in ("fixed", "known_affected", "known_not_affected", "under_investigation"):
            if status_key in ps:
                filtered = [pid for pid in ps[status_key] if pid in filter_ids]
                if filtered:
                    filtered_ps[status_key] = filtered
        return filtered_ps

    @staticmethod
    def _filter_scores(scores: list[dict[str, Any]], filter_ids: set[str]) -> list[dict[str, Any]]:
        result = []
        for score in scores:
            products = [p for p in score.get("products", []) if p in filter_ids]
            if products:
                s = copy.deepcopy(score)
                s["products"] = products
                result.append(s)
        return result

    @staticmethod
    def _filter_by_product_ids(items: list[dict[str, Any]], filter_ids: set[str]) -> list[dict[str, Any]]:
        """Filter a list of objects that have a product_ids field."""
        result = []
        for item in items:
            pids = item.get("product_ids", [])
            filtered = [pid for pid in pids if pid in filter_ids]
            if filtered:
                new_item = copy.deepcopy(item)
                new_item["product_ids"] = filtered
                result.append(new_item)
        return result
