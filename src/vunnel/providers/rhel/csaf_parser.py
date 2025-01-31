import logging
import os
from dataclasses import asdict, dataclass
import re
from packageurl import PackageURL

from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.utils.csaf_types import CSAFDoc
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

    def fix_information_for_module_itself(self, rhsa_id: str, platform: str, package_name: str) -> tuple[str | None, str | None]:
        print("calling MODULE ITSELF")

        doc = self.csaf_client.csaf_doc_for_rhsa(rhsa_id)
        appstream_candidates = [
            b.product_id()
            for b in doc.product_tree.branches[0].product_name_branches()
            if b.cpe() == f"cpe:/a:redhat:enterprise_linux:{platform}::appstream"
        ]

        module_product_candidates = [
            b.product_id()
            for b in doc.product_tree.branches[0].product_version_branches()
            if b.product_id() and b.purl() and b.purl().startswith("pkg:rpmmod")
        ]

        possible_full_product_ids = {
            f"{platform_candidate}:{product_candidate}"
            for platform_candidate in appstream_candidates
            for product_candidate in module_product_candidates
        }
        remediations = [
            r
            for v in doc.vulnerabilities
            for r in v.remediations
            if r.category == "vendor_fix" and r.url.endswith(rhsa_id) and r.product_ids & possible_full_product_ids
        ]
        if not remediations:
            return None, None
        rem = remediations[0]
        product_ids = rem.product_ids & possible_full_product_ids

        fpi = sorted(product_ids)[0]
        print(f"full_product_ids: {product_ids}")
        product_references = [r for r in doc.product_tree.relationships if r.full_product_name and r.full_product_name.product_id == fpi]

        if not product_references:
            print(f"no product references for {fpi}")
            return None, None
        product_reference = product_references[0]
        products = [p for p in doc.product_tree.branches[0].product_version_branches() if p.product_id() == product_reference.product_reference]
        product = products[0]
        purl = product.purl()
        if purl:
            # TODO: modules
            parsed_purl = PackageURL.from_string(purl)
            epoch = parsed_purl.qualifiers.get("epoch", "0")

            return f"{epoch}:{parsed_purl.version}", None
        return None, None

    def platform_module_name_version_from_fpi(self, doc: CSAFDoc, fpi: str) -> tuple[str | None, str | None, str | None, str | None]:
        module = None
        plat_or_module = doc.product_tree.parent(fpi)
        if not plat_or_module:
            return None, None, None, None
        plat = doc.product_tree.parent(plat_or_module)
        if plat:
            module = plat_or_module.removeprefix(f"{plat}:")
            # print(f"module: {module}")
            package = fpi.removeprefix(f"{plat}:{module}:")
            # print(f"trimming package: {package} by removeprefix {plat}:{module}: from {fpi}")
        else:
            plat = plat_or_module
            package = fpi.removeprefix(f"{plat}:")
            # print(f"trimming package: {package} by removeprefix {plat}: from {fpi}")

            # product_node = next(
            #     (
            #         p
            #         for p in doc.product_tree.branches[0].product_version_branches()
            #         if p.product_id() == package and p.purl() and p.purl().startswith("pkg:rpm")
            #     ),
            #     None,
            # )
            # if not product_node:
            #     print(f"no product node for {package} for {fpi}")
            #     raise Exception(f"no product node for {package} for {fpi}")
            # return None, None, None, None
        version = None
        name = None
        # if product_node:
        purl = doc.product_tree.purl_for_product_id(package)
        # print(f"purl: {purl} for {package} from {fpi}")
        if purl:
            parsed_purl = PackageURL.from_string(purl)
            epoch = parsed_purl.qualifiers.get("epoch", "0") if isinstance(parsed_purl.qualifiers, dict) else "0"
            version = f"{epoch}:{parsed_purl.version}"
            name = parsed_purl.name

        platform_product_node = next((p for p in doc.product_tree.branches[0].product_name_branches() if p.product_id() == plat), None)
        platform_cpe = platform_product_node.cpe() if platform_product_node else None
        if not platform_cpe:
            print(f"no platform cpe for {plat} from {fpi}")
            return None, None, None, None

        if module:
            mod_purl = doc.product_tree.purl_for_product_id(module)
            if mod_purl:
                parsed_mod_purl = PackageURL.from_string(mod_purl)
                mod_version = parsed_mod_purl.version or ""
                if mod_version and ":" in mod_version:
                    mod_version = mod_version.split(":")[0]
                module = f"{parsed_mod_purl.name}:{mod_version}"
                print(f"module: {module} for {fpi} by {mod_purl}")
            else:
                # turn a string like "postgresql:15-8090020240209124629.a75119d5"
                # into "postgresql:15"
                match = re.match(r".+(:\d{19}([:.])([0-9a-f]{1,8}|rhel\d+))$", module)
                print(f"{module} by regex for {fpi}")
                if match:
                    module = module.removesuffix(match.group(1))
                else:
                    print(f"no match for module {module}")

        return platform_cpe, module, name, version

    def get_fix_info_v2(self, cve_id: str, ar: dict, normalized_pkg_name) -> tuple[str | None, str | None]:
        """
        Get fix information for an RHSA from the CSAF data.

        The `ar` dict is expected to have the following
        """
        # TODO: just use purl names and platform CPEs to look for matches.
        # Then just figure out how to deal with the / in some packages.
        # namely data/rhel/input/cve/full/CVE-2023-39323 which has rhel8/go-toolset:1.20.10-3
        # print("WILL FIXED IN V2")
        # package is a string like "polkit-0:0.115-13.el8_5.2"
        # normalized_pkg_name is a string like "polkit"
        fix_id = ar.get("advisory") or ar.get("rhsa_id")  # TODO: WILLIAM! Clean up your room.
        if not fix_id:
            print("no advisory")
            return None, None
        doc = self.csaf_client.csaf_doc_for_rhsa(fix_id)
        vuln = next((v for v in doc.vulnerabilities if v.cve == cve_id), None)
        if not vuln:
            self.logger.trace(f"{cve_id}: {fix_id} CSAF doc does not claim to fix this CVE")
            return None, None
        remediation = next((r for r in vuln.remediations if r.category == "vendor_fix" and r.url and r.url.endswith(fix_id)), None)
        if not remediation:
            self.logger.trace(f"{cve_id} no remediation obj for {fix_id}")
            return None, None
        candidate_full_product_ids = remediation.product_ids
        ar_plat_cpe = ar.get("cpe") or ar.get("platform_cpe")
        if not ar_plat_cpe:
            print("no platform cpe")
            return None, None
        self.logger.trace(f"{cve_id} searching {fix_id} based on {ar_plat_cpe} and {normalized_pkg_name}")
        for fpi in candidate_full_product_ids:
            plat, module, name, version = self.platform_module_name_version_from_fpi(doc, fpi)
            if name == normalized_pkg_name and plat and plat.startswith(ar_plat_cpe):
                print(f"found match for {fpi}, {name}, {plat} against {ar_plat_cpe}: {normalized_pkg_name}")
                return version, module
            if name != normalized_pkg_name:
                # print(f"no match for {fpi}, {name} aginst {normalized_pkg_name}")
                pass
            if not plat:
                # print("no match because no platform")
                continue
            if not plat.startswith(ar_plat_cpe):
                # print(f"no match for {fpi}, {name}, {plat} against {ar_plat_cpe}")
                pass
        # print("search miss")
        return None, None
