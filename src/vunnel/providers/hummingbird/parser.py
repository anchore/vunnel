from __future__ import annotations

import copy
import json
import logging
import os
from collections.abc import Generator

from vunnel.workspace import Workspace

from .csaf_client import CSAFVEXClient

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

    def get(self) -> Generator[tuple[str, dict], None, None]:
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

    def _process_cve_file(self, path: str) -> tuple[str, dict] | None:
        with open(path) as fh:
            doc = json.load(fh)

        subsetted = self._subset_document(doc)
        if subsetted is None:
            return None

        cve_id = os.path.splitext(os.path.basename(path))[0]
        return cve_id, subsetted

    # ── subsetting ────────────────────────────────────────────────────

    def _subset_document(self, doc: dict) -> dict | None:
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
        kept_relationships = []
        composite_ids: set[str] = set()  # e.g. "hummingbird-1:python3.11"
        package_refs: set[str] = set()  # e.g. "python3.11" (bare branch product_ids)

        for rel in product_tree.get("relationships", []):
            if rel.get("relates_to_product_reference") not in platform_ids:
                continue
            kept_relationships.append(rel)
            fpn_id = rel.get("full_product_name", {}).get("product_id")
            if fpn_id:
                composite_ids.add(fpn_id)
            prod_ref = rel.get("product_reference")
            if prod_ref:
                package_refs.add(prod_ref)

        # the set of IDs that can appear in product_status, remediations, etc.
        filter_ids = platform_ids | composite_ids

        # step 3: prune branches — keep platforms and referenced packages
        branch_ids = platform_ids | package_refs
        pruned_branches = self._prune_branches(product_tree.get("branches", []), branch_ids)

        # step 4: subset vulnerabilities using filter_ids
        subsetted_vulns = []
        for vuln in doc.get("vulnerabilities", []):
            sv = self._subset_vulnerability(vuln, filter_ids)
            if sv is not None:
                subsetted_vulns.append(sv)

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

    def _collect_platform_ids(self, branches: list[dict], platform_ids: set[str]) -> None:
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

    def _prune_branches(self, branches: list[dict], keep_ids: set[str]) -> list[dict]:
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

    def _subset_vulnerability(self, vuln: dict, filter_ids: set[str]) -> dict | None:
        out = {}

        # copy scalar / metadata fields as-is
        for key in ("cve", "title", "cwe", "discovery_date", "release_date", "notes", "references", "ids"):
            if key in vuln:
                out[key] = vuln[key]

        # filter product_status lists
        if "product_status" in vuln:
            ps = vuln["product_status"]
            filtered_ps = {}
            for status_key in ("fixed", "known_affected", "known_not_affected", "under_investigation"):
                if status_key in ps:
                    filtered = [pid for pid in ps[status_key] if pid in filter_ids]
                    if filtered:
                        filtered_ps[status_key] = filtered
            if not filtered_ps:
                return None
            out["product_status"] = filtered_ps

        # filter remediations
        if "remediations" in vuln:
            out["remediations"] = self._filter_by_product_ids(vuln["remediations"], filter_ids)

        # filter threats
        if "threats" in vuln:
            out["threats"] = self._filter_by_product_ids(vuln["threats"], filter_ids)

        # filter flags
        if "flags" in vuln:
            out["flags"] = self._filter_by_product_ids(vuln["flags"], filter_ids)

        # filter scores
        if "scores" in vuln:
            filtered_scores = []
            for score in vuln["scores"]:
                products = [p for p in score.get("products", []) if p in filter_ids]
                if products:
                    s = copy.deepcopy(score)
                    s["products"] = products
                    filtered_scores.append(s)
            if filtered_scores:
                out["scores"] = filtered_scores

        return out

    def _filter_by_product_ids(self, items: list[dict], filter_ids: set[str]) -> list[dict]:
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
