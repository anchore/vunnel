import logging
import os
from dataclasses import asdict, dataclass
from packageurl import PackageURL

from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.utils.vulnerability import CVSS
from vunnel.workspace import Workspace


@dataclass
class RHSAMetadata:
    issued: str
    updated: str
    ref_id: str
    cve: list[dict[str, str]]

    def to_payload(self):
        return {
            "Issued": self.issued,
            "Updated": self.updated,
            "RefID": self.ref_id,
            "CVE": self.cve,
        }


@dataclass
class RHSARecordVuln:
    name: str
    namespace: str
    severity: str
    description: str
    fixed_in: list[dict[str, str]]
    link: str
    metadata: RHSAMetadata
    cvss: list[CVSS]

    def to_payload(self):
        return {
            "Vulnerability": {
                "Name": self.name,
                "NamespaceName": self.namespace,
                "Description": self.description,
                "Severity": self.severity,
                "Link": self.link,
                "CVSS": [asdict(cvss) for cvss in self.cvss],
                "FixedIn": self.fixed_in,
                "Metadata": self.metadata.to_payload(),
            },
        }


ADVISORIES_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/archive_latest.txt"


class CSAFParser:
    def __init__(self, workspace: Workspace, logger=None, download_timeout=125):
        self.download_timeout = download_timeout
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)

        self.logger = logger
        self.advisory_download_path = os.path.join(self.workspace.input_path, "advisory_archive.tar.zst")
        self.advisories_path = os.path.join(self.workspace.input_path, "advisories")
        self._urls = set()
        self.csaf_client = CSAFClient(self.workspace, ADVISORIES_LATEST_URL, self.logger)

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def get_fix_information(self, rhsa_id: str, platform: str, package_name: str) -> tuple[str | None, str | None]:
        self.logger.info(f"Getting fix information for RHSA {rhsa_id}, platform {platform}, package {package_name}")
        doc = self.csaf_client.csaf_doc_for_rhsa(rhsa_id)
        product_candidates = [
            b.product_id()
            for b in doc.product_tree.branches[0].product_version_branches()
            if b.product_id() and b.product_id() == f"{package_name}.src"
        ]
        platform_candidates = [
            b.product_id()
            for b in doc.product_tree.branches[0].product_name_branches()
            if b.product_id() and b.cpe() and b.cpe().startswith(f"cpe:/o:redhat:enterprise_linux:{platform}")
        ]
        if not product_candidates or not platform_candidates:
            return None, None
        possible_full_product_ids = {
            f"{platform_candidate}:{product_candidate}" for platform_candidate in platform_candidates for product_candidate in product_candidates
        }
        print(f"possible_full_product_ids: {possible_full_product_ids}")
        possible_remediations = [r for v in doc.vulnerabilities for r in v.remediations if r.category == "vendor_fix" and r.url.endswith(rhsa_id)]
        relevant_full_product_ids = {
            full_product_id for full_product_id in possible_full_product_ids if full_product_id in doc.vulnerabilities[0].product_status.fixed
        }
        relevant_remediations = [r for r in possible_remediations if r.product_ids & relevant_full_product_ids]
        if not relevant_remediations:
            return None, None
        rem = relevant_remediations[0]
        full_product_ids = rem.product_ids & relevant_full_product_ids
        fpi = sorted(full_product_ids)[0]
        print(f"full_product_ids: {full_product_ids}")
        product_references = [r for r in doc.product_tree.relationships if r.full_product_name and r.full_product_name.product_id == fpi]
        if not product_references:
            print(f"no product references for {fpi}")
            return None, None
        product_reference = product_references[0]
        products = [p for p in doc.product_tree.branches[0].product_version_branches() if p.product_id() == product_reference.product_reference]
        if not products:
            print(f"no products for {product_reference}")
            return None, None
        product = products[0]
        purl = product.purl()
        if purl:
            # TODO: modules
            parsed_purl = PackageURL.from_string(purl)
            epoch = parsed_purl.qualifiers.get("epoch", "0")
            return f"{epoch}:{parsed_purl.version}", None

        return None, None
