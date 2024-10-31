import re
from dataclasses import dataclass, field

from vunnel.utils.csaf_types import CSAF_JSON

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


@dataclass(frozen=True, eq=True)
class ProductID:
    distribution: str
    module: str | None
    product: str

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
    product_ids: set[ProductID] = field(init=False)
    distribution_ids_to_names: dict[str, str] = field(init=False)
    products_to_namespace: dict[ProductID, str] = field(init=False)
    products_to_purls: dict[ProductID, str] = field(init=False)

    def __post_init__(self) -> None:
        self.product_ids = set()
        self.distribution_ids_to_names = {}
        self.products_to_namespace = {}
        self.products_to_purls = {}
        # initialize product ids
        parents = set(self.csaf.product_tree.product_id_to_parent.values())
        leaf_products = {key for key in self.csaf.product_tree.product_id_to_parent if key not in parents}
        for p in leaf_products:
            distribution = self.csaf.product_tree.first_parent(p)
            module = self.csaf.product_tree.second_parent(p)
            product_part = p.removeprefix(distribution)
            if module:
                product_part = product_part.removeprefix(module)
            self.product_ids.add(ProductID(distribution=distribution, module=module, product=product_part))

        # map product ids to namespaces
        for distro_branch in self.csaf.product_tree.branches[0].product_name_branches():
            if distro_branch.product:
                self.distribution_ids_to_names[distro_branch.product.product_id] = distro_branch.product.name

        # map product ids to purls
        product_id_component_to_purl = {
            purl_branch.product.product_id: purl_branch.product.product_identification_helper.purl
            for purl_branch in self.csaf.product_tree.branches[0].product_version_branches()
            if purl_branch.product
            and purl_branch.product.product_identification_helper
            and purl_branch.product.product_identification_helper.purl
        }

        for pid in self.product_ids:
            distro_name = self.distribution_ids_to_names.get(pid.distribution, "")
            for r in RHEL_FLAVOR_REGEXES:
                match = re.search(r, distro_name)
                if match:
                    version = match.group(1)
                    self.products_to_namespace[pid] = f"rhel:{version}"
            if pid.product in product_id_component_to_purl:
                self.products_to_purls[pid] = product_id_component_to_purl[pid.product]
