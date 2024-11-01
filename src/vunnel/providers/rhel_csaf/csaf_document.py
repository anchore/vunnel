import re
from dataclasses import dataclass, field
from decimal import Decimal

import orjson
from cvss import CVSS2, CVSS3

from vunnel.utils.csaf_types import CSAF_JSON, CVSS_V2, CVSS_V3
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics, FixedIn, VendorAdvisory, AdvisorySummary

RHEL_FLAVOR_REGEXES = [
    r"^Red Hat Enterprise Linux (\d+)",
    r"Red Hat Enterprise Linux AppStream \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux BaseOS \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux \(v\. (\d+) server\)",
    r"^Red Hat Enterprise Linux Server \(v\. (\d+)\)",
    r"^Red Hat Enterprise Linux Desktop \(v\. (\d+) client\)",
    r"^Red Hat Enterprise Linux Desktop \(v\. (\d+)\)",
    r"^Red Hat Enterprise Linux Workstation \(v\. (\d+)\)"
    r"Red Hat Enterprise Linux Client Optional \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux Client \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux RT \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux for Real Time \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux Real Time \(v\. (\d+)\)",
    r"Red Hat CodeReady Linux Builder \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux ComputeNode Optional \(v\. (\d+)\)"
]

MODULE_VERSION_REGEX = r":(rhel)?\d+(\.\d)*:\d{19}:[a-fA-F0-9]{8}$"
PACKAGE_VERSION_REGEX = r"-(\d+):.*$"

SEVERITY_DICT = {
    "low": "Low",
    "moderate": "Medium",
    "important": "High",
    "critical": "Critical",
}

def cvss3_from_csaf_score(score: CVSS_V3, status: str = "draft") -> CVSS:
    cvss3_obj = CVSS3(score.vector_string)
    return CVSS(
        version=score.version,
        vector_string=score.vector_string,
        base_metrics=CVSSBaseMetrics(
            base_score=score.base_score,
            exploitability_score=float(cvss3_obj.esc.quantize(Decimal("1.0"))),
            impact_score=float(cvss3_obj.isc.quantize(Decimal("1.0"))),
            base_severity=cvss3_obj.severities()[0],
        ),
        status=status,
    )

def parse_severity(text: str) -> str | None:
    return SEVERITY_DICT.get(text)


# def cvss2_from_csaf_score(score: CVSS_V2, verified: bool) -> CVSS:
#     cvss2_obj = CVSS2(score.vector_string)
#     status = "draft"
#     if verified:
#         status = "verified"
#     return CVSS(
#         version=score.version,
#         vector_string=score.vector_string,
#         base_metrics=CVSSBaseMetrics(
#             base_score=score.base_score,
#             exploitability_score=float(cvss2_obj.esc.quantize(Decimal("1.0"))),
#             impact_score=float(cvss2_obj.isc.quantize(Decimal("1.0"))),
#             base_severity=cvss2_obj.severities()[0],
#         ),
#         status=status,
#     )


@dataclass(frozen=True, eq=True)
class ProductID:
    # product IDs are like "AppStream-9.1.0.Z.MAIN:firefox-debuginfo-0:102.10.0-1.el9_1.aarch64"
    # where the firstt part identifies a distribution and the last part identifies the product
    # and an optional middle part identifies the module if there is one.
    # for human display, we want the last part, or even the last part sans version info
    # but for looking up in the rest of the document, we want the full string.
    # therefore, make a dataclass that can be either
    distribution: str
    module: str | None
    product: str

    @classmethod
    def create(cls, distribution: str, module: str | None, product: str) -> "ProductID":
        # Some product IDs have 3 components, distro:module:product
        # like AppStream-8.9.0.Z.MAIN:nodejs:20:8090020231019152822:a75119d5:nodejs-packaging-0:2021.06-4.module+el8.9.0+19519+e25b965a.noarch
        # which means "for the RHEL 8 appstream, for the nodejs:20 module, the product nodejs-packaging-..."
        # whereas the modularity is for when product names have a / in them, like
        # "red_hat_enterprise_linux_8:nodejs:16/nodejs", which means
        # "for RHEL 8, for the module nodejs:16, the product nodejs"
        if module and "/" in product:
            raise ValueError(
                f"for {distribution}:{module}:{product}, cannot specify module via / delimit and explicit module element",
            )
        if "/" in product:
            m, _, p = product.partition("/")
        else:
            m = module
            p = product
        return cls(distribution=distribution, module=m, product=p)

    @property
    def full_product_id(self) -> str:
        return f"{self.distribution}:{self.module or ''}:{self.product}"

    @property
    def normalized_name(self) -> str:
        if self.module:
            return re.sub(MODULE_VERSION_REGEX, "", self.module)
        return re.sub(PACKAGE_VERSION_REGEX, "", self.product)

    @property
    def is_logical_product(self) -> bool:
        """is_logical_product returns true if the product would be reported
        in its own line in Red Hat vulnerability UIs, or should be its own line
        in grype-db. If the product is a module or a source RPM, return true"""
        if self.module and len(self.product) == 0:
            return True
        if self.product.endswith("arch=src") or self.product.endswith(".src"):
            return True
        return False


@dataclass
class RHEL_CSAFDocument:
    csaf: CSAF_JSON
    product_ids: dict[str, ProductID] = field(init=False)
    normalized_product_names_to_product_ids: dict[str, set[ProductID]] = field(init=False)
    distribution_ids_to_names: dict[str, str] = field(init=False)
    products_to_namespace: dict[ProductID, str] = field(init=False)
    namespaces_to_product_ids: dict[str, set[ProductID]] = field(init=False)
    products_to_purls: dict[ProductID, str] = field(init=False)
    cvss_objects_with_product_ids: list[tuple[CVSS, set[ProductID]]] = field(init=False)
    vendor_advisories_with_product_ids: list[VendorAdvisory, set[ProductID]] = field(init=False)
    product_ids_to_fixed_versions: dict[ProductID, list[FixedIn]] = field(init=False)
    severity: str = field(init=False)
    description: str = field(init=False)
    cve_id: str = field(init=False)
    vuln_url: str = field(init=False)


    def initialize_product_id_maps(self):
        parents = set(self.csaf.product_tree.product_id_to_parent.values())
        leaf_products = {key for key in self.csaf.product_tree.product_id_to_parent if key not in parents}
        for p in leaf_products:
            distribution = self.csaf.product_tree.first_parent(p)
            module = self.csaf.product_tree.second_parent(p)
            product_part = p.removeprefix(distribution).removeprefix(":")
            if module:
                module = module.removeprefix(distribution).removeprefix(":")
                product_part = product_part.removeprefix(module).removeprefix(":")
                module = module.removeprefix(distribution).removeprefix(":")
            self.product_ids[p] = ProductID.create(distribution=distribution, module=module, product=product_part)
        # reverse dictionary as well
        for k, v in self.product_ids.items():
            if v.normalized_name not in self.normalized_product_names_to_product_ids:
                self.normalized_product_names_to_product_ids[v.normalized_name] = set()
            self.normalized_product_names_to_product_ids[v.normalized_name].add(k)

    def initialize_distro_map(self):
        # make a map from distro IDs (like AppStream-GA:8.3.2)
        # to product names like "Red Hat Enterprise Linux AppStream (v. 9)"
        for distro_branch in self.csaf.product_tree.branches[0].product_name_branches():
            if distro_branch.product:
                self.distribution_ids_to_names[distro_branch.product.product_id] = distro_branch.product.name
        # use that map to map to make a map of product_ids to
        # to namespaces so that clients can easily get a vunnel namespace from each product id.
        for pid in self.product_ids.values():
            distro_name = self.distribution_ids_to_names.get(pid.distribution, "")
            for r in RHEL_FLAVOR_REGEXES:
                match = re.search(r, distro_name)
                if match:
                    version = match.group(1)
                    ns = f"rhel:{version}"
                    self.products_to_namespace[pid] = ns
                    if ns not in self.namespaces_to_product_ids:
                        self.namespaces_to_product_ids[ns] = set()
                    self.namespaces_to_product_ids[ns].add(pid)
                    break

    def initialize_purl_map(self):
        # initialize a dict[ProductID, str] so that clients can easily exchange
        # ProductID for a purl
        # map short product ids to purls
        # (for example "firefox-0:102.10.0-1.el9_1.x86_64" -> "pkg:rpm/redhat/firefox@102.10.0-1.el9_1?arch=x86_64")
        product_id_component_to_purl = {
            purl_branch.product.product_id: purl_branch.product.product_identification_helper.purl
            for purl_branch in self.csaf.product_tree.branches[0].product_version_branches()
            if purl_branch.product
            and purl_branch.product.product_identification_helper
            and purl_branch.product.product_identification_helper.purl
        }

        # go through the set of full product IDs
        # and, if the product component matches a value from the previous dictionary
        # associate it with the purl
        for pid in self.product_ids.values():
            if pid.product in product_id_component_to_purl:
                self.products_to_purls[pid] = product_id_component_to_purl[pid.product]

    def initialize_cvss_objects(self):
        for score in self.csaf.vulnerabilities[0].scores:
            # TODO: also handle cvss_v2
            if score.cvss_v3:
                product_set = {value for key, value in self.product_ids.items() if key in score.products}
                vunnel_cvss_obj = cvss3_from_csaf_score(
                    score.cvss_v3,
                    status=self.csaf.document.tracking.status,
                )
                self.cvss_objects_with_product_ids.append((vunnel_cvss_obj, product_set))

    def initialize_advisories_map(self):
        for rem in self.csaf.vulnerabilities[0].remediations:
            if rem.category != "vendor_fix":
                continue
            # make a vendor advisory from a url like
            # "https://access.redhat.com/errata/RHSA-2020:5246"
            _, _, advisory_id = rem.url.rpartition("/")
            summary = AdvisorySummary(ID=advisory_id, Link=rem.url)
            product_set = { value for key, value in self.product_ids.items() if key in rem.product_ids }
            advisory = VendorAdvisory(AdvisorySummary=[summary], NoAdvisory=False)
            self.vendor_advisories_with_product_ids.append((advisory, product_set))

    def initialize_fixed_ins(self):
        for str_id, pid in self.product_ids.items():
            # keep product IDs that appear literally in "known_affected"
            # or that look like patched modules or src rpms in "fixed"
            # as long as they aren't in "known_not_affected"
            not_fixed = (str_id in self.csaf.vulnerabilities[0].product_status.known_affected)
            fixed_and_src_rpm_or_module = pid.is_logical_product and str_id in self.csaf.vulnerabilities[0].product_status.fixed
            affected = str_id not in self.csaf.vulnerabilities[0].product_status.known_not_affected
            keep = affected and (not_fixed or fixed_and_src_rpm_or_module)
            if not keep:
                continue
            remediations = [r for r in self.csaf.vulnerabilities[0].remediations if r.category == "vendor_fix" and str_id in r.product_ids]
            fixes = []
            namespace = self.products_to_namespace.get(pid)
            if not namespace:
                continue
            vendor_advisory = None
            for va, pids in self.vendor_advisories_with_product_ids:
                if pid in pids:
                    vendor_advisory = va
                    break

            if not remediations:
                fixes.append(
                    FixedIn(Name=pid.normalized_name,
                            NamespaceName=namespace,
                            VersionFormat="rpm",
                            Version="None",
                            Module=pid.module,
                            VendorAdvisory=VendorAdvisory(NoAdvisory=True, AdvisorySummary=None),
                            ),
                )
            else:
                purl = self.products_to_purls.get(pid)
                if not purl:
                    raise ValueError(f"no purl for {pid.full_product_id}")
                version = purl.split("@")[1].split("?")[0]

                fixes.append(
                    FixedIn(Name=pid.normalized_name,
                            NamespaceName=namespace,
                            VersionFormat="rpm",
                            Version=version,
                            Module=pid.module,
                            VendorAdvisory=vendor_advisory,
                            ),
                )
            self.product_ids_to_fixed_versions[pid] = fixes

    def initialize_metadata(self):
        v = self.csaf.vulnerabilities[0]
        self.description = next((n.text for n in v.notes if n.category == "description"), "")
        self.cve_id = v.cve
        self.severity = parse_severity(self.csaf.document.aggregate_severity.text) or ""
        self.vuln_url = next((reference.url for reference in self.csaf.vulnerabilities[0].references if reference.category == "self"), "")

    def __post_init__(self) -> None:
        self.product_ids = {}
        self.normalized_product_names_to_product_ids = {}
        self.distribution_ids_to_names = {}
        self.products_to_namespace = {}
        self.namespaces_to_product_ids = {}
        self.products_to_purls = {}
        self.cvss_objects_with_product_ids = []
        self.vendor_advisories_with_product_ids = []
        self.product_ids_to_fixed_versions = {}

        self.initialize_product_id_maps()
        self.initialize_distro_map()
        self.initialize_purl_map()
        self.initialize_cvss_objects()
        self.initialize_advisories_map()
        self.initialize_fixed_ins()
        self.initialize_metadata()

    @classmethod
    def from_path(cls, path: str) -> "RHEL_CSAFDocument":
        with open(path) as fh:
            data = orjson.loads(fh.read())
            c = CSAF_JSON.from_dict(data)
            return cls(csaf=c)


# TEMP
if __name__ == "__main__":
    r = RHEL_CSAFDocument.from_path('./data/rhel_csaf/input/csaf/2020/cve-2020-13529.json')
    print(r.product_ids_to_fixed_versions)
