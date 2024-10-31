from decimal import Decimal
import re
from dataclasses import dataclass, field

from cvss import CVSS2, CVSS3

from vunnel.utils.csaf_types import CSAF_JSON, CVSS_V3, CVSS_V2
from vunnel.utils.vulnerability import VendorAdvisory, CVSS, FixedIn, CVSSBaseMetrics

RHEL_FLAVOR_REGEXES = [
    r"Red Hat Enterprise Linux AppStream \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux BaseOS \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux \(v\. (\d+) server\)",
    r"^Red Hat Enterprise Linux Server \(v\. (\d+)\)",
    r"^Red Hat Enterprise Linux Desktop \(v\. (\d+) client\)",
    r"^Red Hat Enterprise Linux Desktop \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux Client Optional \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux Client \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux RT \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux for Real Time \(v\. (\d+)\)",
    r"Red Hat Enterprise Linux Real Time \(v\. (\d+)\)",
    r"Red Hat CodeReady Linux Builder \(v\. (\d+)\)",
]

MODULE_VERSION_REGEX = r":(rhel)?\d+(\.\d)*:\d{19}:[a-fA-F0-9]{8}$"
PACKAGE_VERSION_REGEX = r"-(\d+):.*$"


def cvss3_from_csaf_score(score: CVSS_V3, verified: bool) -> CVSS:
    cvss3_obj = CVSS3(score.vector_string)
    status = "draft"
    if verified:
        status = "verified"
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
    modularity: str | None
    product: str

    @classmethod
    def create(cls, distribution: str, module: str | None, product: str) -> "ProductID":
        if "/" in product:
            modularity, _, p = product.partition("/")
        else:
            modularity = None
            p = product
        return cls(distribution=distribution, module=module, modularity=modularity, product=p)

    @property
    def full_product_id(self) -> str:
        return f"{self.distribution}:{self.module or ''}:{self.product}"

    @property
    def normalized_name(self) -> str:
        if self.module:
            return re.sub(MODULE_VERSION_REGEX, "", self.module)
        return re.sub(PACKAGE_VERSION_REGEX, "", self.product)


@dataclass
class RHEL_CSAFDocument:
    csaf: CSAF_JSON
    product_ids: dict[str, ProductID] = field(init=False)
    distribution_ids_to_names: dict[str, str] = field(init=False)
    products_to_namespace: dict[ProductID, str] = field(init=False)
    products_to_purls: dict[ProductID, str] = field(init=False)
    cvss_objects_with_product_ids: list[tuple[CVSS, set[ProductID]]] = field(init=False)
    product_ids_to_advisories: dict[ProductID, VendorAdvisory] = field(init=False)

    def initialize_product_id_map(self):
        parents = set(self.csaf.product_tree.product_id_to_parent.values())
        leaf_products = {key for key in self.csaf.product_tree.product_id_to_parent if key not in parents}
        for p in leaf_products:
            distribution = self.csaf.product_tree.first_parent(p)
            module = self.csaf.product_tree.second_parent(p)
            product_part = p.removeprefix(distribution)
            if module:
                product_part = product_part.removeprefix(module)
            self.product_ids[p] = ProductID.create(distribution=distribution, module=module, product=product_part)

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
                    self.products_to_namespace[pid] = f"rhel:{version}"

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
                doc_is_final = self.csaf.document.tracking.status == "final"
                vunnel_cvss_obj = cvss3_from_csaf_score(
                    score.cvss_v3,
                    verified=doc_is_final,
                )
                self.cvss_objects_with_product_ids.append((vunnel_cvss_obj, product_set))

    def __post_init__(self) -> None:
        self.product_ids = {}
        self.distribution_ids_to_names = {}
        self.products_to_namespace = {}
        self.products_to_purls = {}
        self.cvss_objects_with_product_ids = []

        self.initialize_product_id_map()
        self.initialize_distro_map()
        self.initialize_purl_map()
        self.initialize_cvss_objects()
