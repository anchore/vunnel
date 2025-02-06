import logging
import os

from packageurl import PackageURL

from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.utils.csaf_types import CSAFDoc
from vunnel.workspace import Workspace


class CSAFParser:
    def __init__(self, workspace: Workspace, client: CSAFClient, logger: logging.Logger | None = None, download_timeout: int = 125):
        self.download_timeout = download_timeout
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)

        self.logger = logger
        self.advisory_download_path = os.path.join(self.workspace.input_path, "advisory_archive.tar.zst")
        self.advisories_path = os.path.join(self.workspace.input_path, "advisories")
        self._urls: set[str] = set()
        self.csaf_client: CSAFClient = client

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def platform_module_name_version_from_fpi(self, doc: CSAFDoc, fpi: str) -> tuple[str | None, str | None, str | None, str | None]:
        module = None
        plat_or_module = doc.product_tree.parent(fpi)
        if not plat_or_module:
            return None, None, None, None
        plat = doc.product_tree.parent(plat_or_module)
        if plat:
            module = plat_or_module.removeprefix(f"{plat}:")
            package = fpi.removeprefix(f"{plat}:{module}:")
        else:
            plat = plat_or_module
            package = fpi.removeprefix(f"{plat}:")

        version = None
        name = None
        purl = doc.product_tree.purl_for_product_id(package)

        if purl:
            if purl.startswith("pkg:rpmmod"):
                return None, None, None, None
            parsed_purl = PackageURL.from_string(purl)
            epoch = parsed_purl.qualifiers.get("epoch", "0") if isinstance(parsed_purl.qualifiers, dict) else "0"
            version = f"{epoch}:{parsed_purl.version}"
            name = parsed_purl.name
        else:
            self.logger.trace(f"no purl for {package} from {fpi}")  # type: ignore[attr-defined]

        platform_product_node = next((p for p in doc.product_tree.branches[0].product_name_branches() if p.product_id() == plat), None)
        platform_cpe = platform_product_node.cpe() if platform_product_node else None
        if not platform_cpe:
            self.logger.trace(f"no platform cpe for {plat} from {fpi}")  # type: ignore[attr-defined]
            return None, None, None, None

        if module:
            mod_purl = doc.product_tree.purl_for_product_id(module)
            if mod_purl:
                parsed_mod_purl = PackageURL.from_string(mod_purl)
                mod_version = parsed_mod_purl.version or ""
                if mod_version and ":" in mod_version:
                    mod_version = mod_version.split(":")[0]
                module = f"{parsed_mod_purl.name}:{mod_version}"
                self.logger.trace(f"module: {module} for {fpi} by {mod_purl}")  # type: ignore[attr-defined]
            else:
                self.logger.trace(f"no module purl for {module} from {fpi}")  # type: ignore[attr-defined]

        return platform_cpe, module, name, version

    def get_fix_info(self, cve_id: str, ar: dict[str, str | None], normalized_pkg_name: str | None) -> tuple[str | None, str | None]:  # noqa: PLR0911
        """
        Get fix information for an RHSA from the CSAF data.

        The `ar` dict is expected to have the following
        """
        fix_id = ar.get("advisory") or ar.get("rhsa_id")
        if not fix_id:
            print("no advisory")
            return None, None
        doc = self.csaf_client.csaf_doc_for_rhsa(fix_id)
        if not doc:
            return None, None
        vuln = next((v for v in doc.vulnerabilities if v.cve == cve_id), None)
        if not vuln:
            self.logger.trace(f"{cve_id}: {fix_id} CSAF doc does not claim to fix this CVE")  # type: ignore[attr-defined]
            return None, None
        remediation = next((r for r in vuln.remediations if r.category == "vendor_fix" and r.url and r.url.endswith(fix_id)), None)
        if not remediation:
            self.logger.trace(f"{cve_id} no remediation obj for {fix_id}")  # type: ignore[attr-defined]
            return None, None
        candidate_full_product_ids = remediation.product_ids
        ar_plat_cpe = ar.get("cpe") or ar.get("platform_cpe")
        if not ar_plat_cpe:
            print("no platform cpe")
            return None, None
        self.logger.trace(f"{cve_id} searching {fix_id} based on {ar_plat_cpe} and {normalized_pkg_name}")  # type: ignore[attr-defined]
        for fpi in candidate_full_product_ids:
            plat, module, name, version = self.platform_module_name_version_from_fpi(doc, fpi)
            if name == normalized_pkg_name and plat and plat.startswith(ar_plat_cpe):
                self.logger.trace(f"found match for {fpi}, {name}, {plat} against {ar_plat_cpe}: {normalized_pkg_name}")  # type: ignore[attr-defined]
                return version, module
        self.logger.trace(f"{cve_id} no match for {fix_id} against {ar_plat_cpe}: {normalized_pkg_name}")  # type: ignore[attr-defined]
        return None, None
