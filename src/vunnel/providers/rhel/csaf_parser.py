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
            match = re.match(r".+(:\d{19}:[0-9a-f]{8})$", module)
            if match:
                # print(f"trimmed module: {module}")
                module = module.removesuffix(match.group(1))
                # print(f"trimmed module: {module}")
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
            print("no vuln")
            return None, None
        remediation = next((r for r in vuln.remediations if r.category == "vendor_fix" and r.url and r.url.endswith(fix_id)), None)
        if not remediation:
            print("no remediation")
            return None, None
        candidate_full_product_ids = remediation.product_ids
        ar_plat_cpe = ar.get("cpe") or ar.get("platform_cpe")
        if not ar_plat_cpe:
            print("no platform cpe")
            return None, None
        for fpi in candidate_full_product_ids:
            plat, module, name, version = self.platform_module_name_version_from_fpi(doc, fpi)
            if name == normalized_pkg_name and plat and plat.startswith(ar_plat_cpe):
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
        print("search miss")
        return None, None

    def get_fix_information(self, rhsa_id: str, platform: str, package_name: str, normalized_pkg_name: str) -> tuple[str | None, str | None]:
        """
        Get fix information from an RHSA for the given package.

        The real trick here is to figure out what kind of a thing the package name is. It can be:
        1. The name of a source RPM.
        2. The name of a module.
        3. The name of a member of a module.
        4. The name of a binary RPM.


        For case 1, a source RPM, we find a product version branch with a product_id that matches the `package` field of the
        affected release from Hydra. Then we try to find a full product ID by pre-pending matching platform IDs to the product ID.
        If one of those is listed as a pathected item in the RHSA, then we can parse the version off the purl from the original branch.

        For case 2, the name of a module itself, we tend to find a src RPM that has the same name as the module. If so, we can follow
        the same process as case 1.

        For case 3, the name of the member of a module, we need to find the module itself, and create a 3-part product ID (platform:module:member).
        We can do this by looking for `pkg:rpmmod` PURLs that have the same version suffix as the module member, and then looking for a child
        of this module that has the same name as the requested package. If we find a match, we can then construct candidate full product IDs
        by pre-pending platform IDs to the module ID and then the module member ID.
        If one of these is listed as a fixed item in the RHSA, we can parse the version off the PURL for the module member and return both the
        module name and the version from the module member.

        For case 4, this tends to be "we aren't in one of the other cases". This is similar to case 1, but we need to consider binary RPMs
        and not just source RPMs.

        Current TODOs:
        * probably pass in the whole `ar` dict/object instead of just the package name and platform. For example, we can use the CPE here.
        * clean up
        * decide if cases 2 and 3 are actually different - is this just the coincidental case where the module name and the member name are the same?
        * decide if cases 1 and 4 are really different. Does it matter which arch I pull the fix version from.
        * find CVEs that are examples of case 4 - "CVE-2024-20952" is a good candidate for "java-1.8.0-ibm-1:1.8.0.8.20-1.el8_9" and RHSA ID 2024:1481
        * get CVE-2024-8088 to parity for python39 and python39-devel
        * are there modules outside AppStreams?

        Separating cases based on inputs:

        1. We are given a string like "python3.12-0:3.12.5-2.el8_10" as the package name
        2. We are given a string like "python39:3.9-8100020240826142629.d47b87a4" as the package name. (This is the name of a module)
        3. We are given a string like "python39-devel:3.9-8100020240826142629.d47b87a4" as the package name. (This is the name of a member of a module, but the version of a module)
        4.
        """
        self.logger.info(f"Getting fix information for RHSA {rhsa_id}, platform {platform}, package {package_name}")
        doc = self.csaf_client.csaf_doc_for_rhsa(rhsa_id)
        # CASE 1: we are given the name-version string of a source RPM directly.
        src_rpm_product_candidates = [
            b.product_id()
            for b in doc.product_tree.branches[0].product_version_branches()
            if b.product_id() and b.product_id() == f"{package_name}.src"
        ]
        # if not src_rpm_product_candidates:
        #     # TODO: packageURL from string, and name
        #     src_rpm_product_candidates = [
        #         product_id
        #         for b in doc.product_tree.branches[0].product_version_branches()
        #         for purl in [b.purl()]
        #         for pkg_url in [PackageURL.from_string(purl) if purl else None]
        #         if purl and pkg_url and pkg_url.name == normalized_pkg_name and pkg_url.qualifiers.get("arch") == "src"
        #         for product_id in [b.product_id()]
        #     ]
        print(f"src_rpm_product_candidates: {src_rpm_product_candidates}")
        # module_product_candidates = [
        #     b.product_id()
        #     for b in doc.product_tree.branches[0].product_version_branches()
        #     if b.product_id() and b.purl() and b.purl().startswith("pkg:rpmmod")
        # ]
        # if module_product_candidates and not src_rpm_product_candidates:
        #     return self.fix_information_for_module_itself(rhsa_id, platform, package_name)
        platform_candidates = [
            b.product_id()
            for b in doc.product_tree.branches[0].product_name_branches()
            if b.product_id() and b.cpe() and b.cpe().startswith(f"cpe:/o:redhat:enterprise_linux:{platform}")
        ]
        if not src_rpm_product_candidates or not platform_candidates:
            return None, None
        possible_full_product_ids = {
            f"{platform_candidate}:{product_candidate}"
            for platform_candidate in platform_candidates
            for product_candidate in src_rpm_product_candidates
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
