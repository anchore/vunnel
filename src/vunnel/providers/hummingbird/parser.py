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

        # collect the set of hummingbird product IDs from the product tree
        hb_product_ids = self._find_hummingbird_product_ids(doc)
        if not hb_product_ids:
            return None

        cve_id = os.path.splitext(os.path.basename(path))[0]

        subsetted = self._subset_document(doc, hb_product_ids)
        if subsetted is None:
            return None

        return cve_id, subsetted

    # ── product tree inspection ───────────────────────────────────────

    def _find_hummingbird_product_ids(self, doc: dict) -> set[str]:
        """Walk the product tree and return all product_ids that are hummingbird-related.

        A product is hummingbird-related if:
        - It has a CPE matching the hummingbird prefix, OR
        - It appears in a relationship where relates_to_product_reference is a hummingbird product
        """
        product_tree = doc.get("product_tree", {})

        # pass 1: find direct hummingbird product ids from branches
        hb_ids: set[str] = set()
        self._collect_hb_ids_from_branches(product_tree.get("branches", []), hb_ids)

        if not hb_ids:
            return set()

        # pass 2: find relationship-derived product ids (e.g. package-in-platform)
        for rel in product_tree.get("relationships", []):
            if rel.get("relates_to_product_reference") in hb_ids or rel.get("product_reference") in hb_ids:
                fpn = rel.get("full_product_name", {})
                pid = fpn.get("product_id")
                if pid:
                    hb_ids.add(pid)

        return hb_ids

    def _collect_hb_ids_from_branches(self, branches: list[dict], hb_ids: set[str]) -> None:
        for branch in branches:
            product = branch.get("product")
            if product:
                helper = product.get("product_identification_helper", {})
                if _is_hummingbird_cpe(helper.get("cpe")):
                    pid = product.get("product_id")
                    if pid:
                        hb_ids.add(pid)
            self._collect_hb_ids_from_branches(branch.get("branches", []), hb_ids)

    # ── subsetting ────────────────────────────────────────────────────

    def _subset_document(self, doc: dict, hb_product_ids: set[str]) -> dict | None:
        """Create a valid CSAF VEX document containing only hummingbird data."""
        out = copy.deepcopy(doc)

        # subset product tree
        out["product_tree"] = self._subset_product_tree(doc["product_tree"], hb_product_ids)

        # subset vulnerabilities
        out["vulnerabilities"] = self._subset_vulnerabilities(doc.get("vulnerabilities", []), hb_product_ids)

        # drop vulns that ended up empty
        out["vulnerabilities"] = [v for v in out["vulnerabilities"] if v is not None]

        if not out["vulnerabilities"]:
            return None

        return out

    def _subset_product_tree(self, product_tree: dict, hb_product_ids: set[str]) -> dict:
        result: dict = {}

        # subset branches: keep branches that lead to a hummingbird product
        if "branches" in product_tree:
            result["branches"] = self._prune_branches(product_tree["branches"], hb_product_ids)

        # subset relationships: keep only those where the full_product_name.product_id is hummingbird
        if "relationships" in product_tree:
            result["relationships"] = [
                rel
                for rel in product_tree["relationships"]
                if rel.get("full_product_name", {}).get("product_id") in hb_product_ids
            ]

        return result

    def _prune_branches(self, branches: list[dict], hb_product_ids: set[str]) -> list[dict]:
        """Recursively prune branches, keeping only paths that lead to a hummingbird product."""
        kept = []
        for branch in branches:
            # check if this branch directly has a hummingbird product
            product = branch.get("product")
            is_hb = False
            if product and product.get("product_id") in hb_product_ids:
                is_hb = True

            # recurse into children
            pruned_children = self._prune_branches(branch.get("branches", []), hb_product_ids)

            if is_hb or pruned_children:
                new_branch = {k: v for k, v in branch.items() if k != "branches"}
                if pruned_children:
                    new_branch["branches"] = pruned_children
                kept.append(new_branch)

        return kept

    def _subset_vulnerabilities(self, vulnerabilities: list[dict], hb_product_ids: set[str]) -> list[dict | None]:
        return [self._subset_vulnerability(v, hb_product_ids) for v in vulnerabilities]

    def _subset_vulnerability(self, vuln: dict, hb_product_ids: set[str]) -> dict | None:
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
                    filtered = [pid for pid in ps[status_key] if pid in hb_product_ids]
                    if filtered:
                        filtered_ps[status_key] = filtered
            if not filtered_ps:
                return None
            out["product_status"] = filtered_ps

        # filter remediations
        if "remediations" in vuln:
            out["remediations"] = self._filter_by_product_ids(vuln["remediations"], hb_product_ids)

        # filter threats
        if "threats" in vuln:
            out["threats"] = self._filter_by_product_ids(vuln["threats"], hb_product_ids)

        # filter flags
        if "flags" in vuln:
            out["flags"] = self._filter_by_product_ids(vuln["flags"], hb_product_ids)

        # filter scores
        if "scores" in vuln:
            filtered_scores = []
            for score in vuln["scores"]:
                products = [p for p in score.get("products", []) if p in hb_product_ids]
                if products:
                    s = copy.deepcopy(score)
                    s["products"] = products
                    filtered_scores.append(s)
            if filtered_scores:
                out["scores"] = filtered_scores

        return out

    def _filter_by_product_ids(self, items: list[dict], hb_product_ids: set[str]) -> list[dict]:
        """Filter a list of objects that have a product_ids field, keeping only hummingbird product IDs."""
        result = []
        for item in items:
            pids = item.get("product_ids", [])
            filtered = [pid for pid in pids if pid in hb_product_ids]
            if filtered:
                new_item = copy.deepcopy(item)
                new_item["product_ids"] = filtered
                result.append(new_item)
        return result
