from __future__ import annotations

import bz2
import copy
import logging
import os
import tarfile
from typing import TYPE_CHECKING, Any

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

# Valid CPE prefixes for SLES platforms we want to include
SLES_CPE_PREFIXES = (
    "cpe:/o:suse:sles:",  # base SLES (e.g., cpe:/o:suse:sles:15:sp6)
    "cpe:/o:suse:sles-ltss:",  # LTSS (12+)
    "cpe:/o:suse:sles-bcl:",  # BCL
    "cpe:/o:suse:sles-espos:",  # ESPOS
    "cpe:/o:suse:suse_sles_ltss:",  # older LTSS (11)
)


def is_sles_cpe(cpe: str) -> bool:
    """Check if a CPE identifies a SLES platform we want to include.

    Valid CPEs have the format: cpe:/o:suse:<product>:<version>[:<sp>]
    Examples:
      cpe:/o:suse:sles:15:sp6 -> 6 parts (valid)
      cpe:/o:suse:sles-ltss:15 -> 5 parts (valid)
      cpe:/o:suse:sles:15:sp1:chost-amazon:... -> 8+ parts (invalid, cloud host image)

    Excludes SAP, Teradata, Desktop, HPC, Micro, cloud host images, and other variants.
    """
    if not cpe.startswith(SLES_CPE_PREFIXES):
        return False
    # cpe:/o:suse:sles:15:sp6 splits to ['cpe', '/o', 'suse', 'sles', '15', 'sp6'] = 6 parts
    # Cloud host images have more parts (e.g., cpe:/o:suse:sles:15:sp1:chost-amazon:...)
    parts = cpe.split(":")
    return len(parts) <= 6


def _collect_sles_platform_ids(branches: list[dict[str, Any]]) -> set[str]:
    """Recursively find all SLES platform branches (by CPE) and return their product_ids."""
    result: set[str] = set()
    for branch in branches:
        product = branch.get("product")
        if product:
            cpe = product.get("product_identification_helper", {}).get("cpe", "")
            product_id = product.get("product_id", "")
            if cpe and is_sles_cpe(cpe):
                result.add(product_id)
        # Recurse into sub-branches
        if "branches" in branch:
            result.update(_collect_sles_platform_ids(branch["branches"]))
    return result


def _collect_relationship_ids(
    product_tree: dict[str, Any],
    sles_platform_ids: set[str],
) -> tuple[set[str], set[str]]:
    """Collect product and package IDs from relationships that reference SLES platforms.

    Returns:
        A tuple of (kept_relationship_product_ids, sles_package_branch_ids)
    """
    kept_relationship_product_ids: set[str] = set()
    sles_package_branch_ids: set[str] = set()

    for rel in product_tree.get("relationships", []):
        if rel.get("relates_to_product_reference") in sles_platform_ids:
            full_product_name = rel.get("full_product_name", {})
            product_id = full_product_name.get("product_id", "")
            if product_id:
                kept_relationship_product_ids.add(product_id)
            product_reference = rel.get("product_reference", "")
            if product_reference:
                sles_package_branch_ids.add(product_reference)

    return kept_relationship_product_ids, sles_package_branch_ids


def _has_actionable_status(doc: dict[str, Any], kept_product_ids: set[str]) -> bool:
    """Check if any vulnerability has actionable statuses for SLES products."""
    actionable_types = ("fixed", "known_affected", "under_investigation", "recommended")

    for vuln in doc.get("vulnerabilities", []):
        product_status = vuln.get("product_status", {})
        for status_type in actionable_types:
            for product_id in product_status.get(status_type, []):
                if product_id in kept_product_ids:
                    return True
    return False


def _filter_product_tree(result: dict[str, Any], kept_product_ids: set[str], platform_ids: set[str], package_ids: set[str]) -> None:
    """Filter product_tree relationships and branches in place."""
    if "product_tree" not in result:
        return

    if "relationships" in result["product_tree"]:
        result["product_tree"]["relationships"] = [
            rel for rel in result["product_tree"]["relationships"] if rel.get("full_product_name", {}).get("product_id", "") in kept_product_ids
        ]

    if "branches" in result["product_tree"]:
        result["product_tree"]["branches"] = _filter_branches(
            result["product_tree"]["branches"],
            platform_ids,
            package_ids,
        )


def _filter_vulnerability_field(items: list[dict[str, Any]], key: str, kept_product_ids: set[str]) -> list[dict[str, Any]]:
    """Filter a list of vulnerability field items (remediations, threats, flags, etc.)."""
    for item in items:
        if key in item:
            item[key] = [pid for pid in item[key] if pid in kept_product_ids]
    return [item for item in items if item.get(key)]


def _filter_vulnerability(vuln: dict[str, Any], kept_product_ids: set[str]) -> None:
    """Filter a single vulnerability's product references in place."""
    status_types = ("fixed", "known_affected", "known_not_affected", "under_investigation", "recommended")

    if "product_status" in vuln:
        for status_type in status_types:
            if status_type in vuln["product_status"]:
                vuln["product_status"][status_type] = [pid for pid in vuln["product_status"][status_type] if pid in kept_product_ids]
                if not vuln["product_status"][status_type]:
                    del vuln["product_status"][status_type]

    if "remediations" in vuln:
        vuln["remediations"] = _filter_vulnerability_field(vuln["remediations"], "product_ids", kept_product_ids)

    if "scores" in vuln:
        vuln["scores"] = _filter_vulnerability_field(vuln["scores"], "products", kept_product_ids)

    if "threats" in vuln:
        vuln["threats"] = _filter_vulnerability_field(vuln["threats"], "product_ids", kept_product_ids)

    if "flags" in vuln:
        vuln["flags"] = _filter_vulnerability_field(vuln["flags"], "product_ids", kept_product_ids)


def subset_csaf_for_sles(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Subset a CSAF document to only include SUSE Linux Enterprise Server products.

    This filters all product-related fields to only include SLES products,
    maintaining document integrity. Returns None if no SLES products are found.

    Approach: Start from branches to find SLES platforms (by CPE), then use
    relationships to find all packages that belong to those platforms.

    Args:
        doc: A CSAF document as a dictionary

    Returns:
        A new CSAF document containing only SLES products, or None if no SLES products
    """
    product_tree = doc.get("product_tree", {})

    sles_platform_ids = _collect_sles_platform_ids(product_tree.get("branches", []))
    if not sles_platform_ids:
        return None

    kept_relationship_product_ids, sles_package_branch_ids = _collect_relationship_ids(product_tree, sles_platform_ids)
    if not kept_relationship_product_ids:
        return None

    if not _has_actionable_status(doc, kept_relationship_product_ids):
        return None

    result = copy.deepcopy(doc)
    _filter_product_tree(result, kept_relationship_product_ids, sles_platform_ids, sles_package_branch_ids)

    if "vulnerabilities" in result:
        for vuln in result["vulnerabilities"]:
            _filter_vulnerability(vuln, kept_relationship_product_ids)

    return result


def _strip_non_platform_cpe(branch: dict[str, Any]) -> dict[str, Any]:
    """Strip CPE from a branch if it's not a valid SLES platform CPE.

    Package branches may have application CPEs (cpe:2.3:a:...) that can have
    malformed versions. We strip these but preserve PURLs.
    """
    product = branch.get("product")
    if not product:
        return branch

    helper = product.get("product_identification_helper")
    if not helper:
        return branch

    cpe = helper.get("cpe", "")
    # Only keep CPEs that are valid SLES platform CPEs
    if cpe and not is_sles_cpe(cpe):
        new_branch = copy.deepcopy(branch)
        del new_branch["product"]["product_identification_helper"]["cpe"]
        # If helper is now empty (no purl either), remove it entirely
        if not new_branch["product"]["product_identification_helper"]:
            del new_branch["product"]["product_identification_helper"]
        return new_branch

    return branch


def _filter_branches(
    branches: list[dict[str, Any]],
    sles_platform_ids: set[str],
    sles_package_ids: set[str],
) -> list[dict[str, Any]]:
    """Recursively filter branches to only include SLES platforms and their packages.

    Args:
        branches: List of branch dictionaries to filter
        sles_platform_ids: Set of SLES platform IDs (e.g., "SUSE Linux Enterprise Server 15 SP6")
        sles_package_ids: Set of package product IDs (with PURLs) referenced by SLES relationships
    """
    result = []
    for branch in branches:
        product = branch.get("product")
        product_id = product.get("product_id") if product else None

        # Keep this branch if it's a SLES platform (has CPE) or a package we need (has PURL)
        if product_id and product_id in sles_platform_ids:
            # Platform branch - keep as-is (CPE is valid)
            result.append(branch)
            continue

        if product_id and product_id in sles_package_ids:
            # Package branch - strip any non-platform CPE but keep PURL
            result.append(_strip_non_platform_cpe(branch))
            continue

        # Recursively filter sub-branches
        if "branches" in branch:
            filtered_sub = _filter_branches(branch["branches"], sles_platform_ids, sles_package_ids)
            if filtered_sub:
                new_branch = copy.deepcopy(branch)
                new_branch["branches"] = filtered_sub
                result.append(new_branch)

    return result


class CSAFParser:
    """Parser for SLES vulnerability data from CSAF VEX format."""

    __csaf_url__ = "https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2"
    __archive_name__ = "csaf-vex.tar.bz2"

    def __init__(
        self,
        workspace: Workspace,
        allow_versions: list[str],
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.workspace = workspace
        self.allow_versions = allow_versions
        self.download_timeout = download_timeout
        self.urls: list[str] = []
        self.input_dir = os.path.join(workspace.input_path, "csaf")

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> CSAFParser:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass

    def _download(self) -> str:
        """Download and extract the CSAF VEX archive.

        Streams the download through bz2 decompression and tar extraction
        concurrently, avoiding the need to write the compressed archive to disk.
        """
        if not os.path.exists(self.input_dir):
            self.logger.debug(f"creating workspace for CSAF data at {self.input_dir}")
            os.makedirs(self.input_dir)

        self.logger.info(f"downloading and extracting CSAF VEX archive from {self.__csaf_url__}")
        self.urls.append(self.__csaf_url__)

        r = http.get(self.__csaf_url__, self.logger, stream=True, timeout=self.download_timeout)

        # Stream: HTTP response -> bz2 decompressor -> tar extractor
        # r.raw is the urllib3 HTTPResponse (file-like), BZ2File wraps it for decompression,
        # tarfile reads from that in streaming mode ("r|")
        with bz2.BZ2File(r.raw) as decompressor, tarfile.open(fileobj=decompressor, mode="r|") as tar:
            tar.extractall(path=self.input_dir, filter="data")

        return self.input_dir

    def get(self) -> Generator[tuple[str, str, dict[str, object]]]:
        """Yield vulnerability records from CSAF VEX data.

        Yields:
            Tuples of (namespace, vulnerability_id, record_payload)
        """
        import glob

        import orjson

        self._download()

        csaf_dir = os.path.join(self.input_dir, "csaf-vex")
        json_files = glob.glob(os.path.join(csaf_dir, "cve-*.json"))

        self.logger.info(f"processing {len(json_files)} CSAF documents")

        for json_path in json_files:
            try:
                with open(json_path, "rb") as f:
                    doc = orjson.loads(f.read())

                subset = subset_csaf_for_sles(doc)
                if subset is None:
                    continue

                # Extract CVE ID from the document
                cve_id = None
                for vuln in subset.get("vulnerabilities", []):
                    if "cve" in vuln:
                        cve_id = vuln["cve"]
                        break

                if not cve_id:
                    self.logger.debug(f"skipping {json_path}: no CVE ID found")
                    continue

                yield "sles", cve_id, subset

            except Exception:
                self.logger.exception(f"error processing {json_path}")
