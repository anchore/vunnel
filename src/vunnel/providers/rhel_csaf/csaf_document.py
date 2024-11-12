import re
from dataclasses import dataclass, field
from decimal import Decimal

import orjson
from cvss import CVSS2, CVSS3
from packageurl import PackageURL

from vunnel.utils.csaf_types import CSAF_JSON, CVSS_V2, CVSS_V3, Remediation
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics, FixedIn, VendorAdvisory, AdvisorySummary, Vulnerability

RHEL_CPE_REGEXES = [
    r"^cpe:/[ao]:redhat:enterprise_linux:(\d+)(::(client|server|workstation|appstream|baseos|realtime|crb|supplementary))*$",  # appstream has :a:
    r"^cpe:/a:redhat:rhel_extras_rt:(\d+)",
    r"^cpe:/a:redhat:rhel_extras_rt:(\d+)",
    r"^cpe:/a:redhat:rhel_virtualization:(\d+)(::(client|server))?",
]

MODULE_VERSION_REGEX = r":(rhel)?\d+(\.\d+)*:\d{19}:([a-fA-F0-9]{8}|rhel\d+)$"
PACKAGE_VERSION_REGEX = r"-(\d+):.*$"
PACKAGE_VERSION_REGEX_UNDER = r"-[\d_-]+$"

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
    return SEVERITY_DICT.get(text.lower())


# TODO: figure out cvss2 and 4
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
    raw: str  # the product ID as it appears in CSAF JSON
    distribution: str
    module: str | None
    product: str | None
    purl: PackageURL | None
    module_purl: PackageURL | None
    module_from_slash: bool = False

    @classmethod
    def create(cls,
               raw: str,
               distribution: str,
               module: str | None,
               product: str | None,
               package_url: str | None,
               module_purl: str | None) -> "ProductID":
        # Some product IDs have 3 components, distro:module:product
        # like AppStream-8.9.0.Z.MAIN:nodejs:20:8090020231019152822:a75119d5:nodejs-packaging-0:2021.06-4.module+el8.9.0+19519+e25b965a.noarch
        # which means "for the RHEL 8 appstream, for the nodejs:20 module, the product nodejs-packaging-..."
        # whereas the modularity is for when product names have a / in them, like
        # "red_hat_enterprise_linux_8:nodejs:16/nodejs", which means
        # "for RHEL 8, for the module nodejs:16, the product nodejs"
        module_from_slash = False
        if module and product and "/" in product:
            raise ValueError(
                f"for {distribution}:{module}:{product}, cannot specify module via / delimit and explicit module element",
            )
        if product and "/" in product:
            m, _, p = product.partition("/")
            module_from_slash = True
        else:
            m = module
            p = product
        purl = PackageURL.from_string(package_url) if package_url else None
        m_purl = PackageURL.from_string(module_purl) if module_purl else None
        return cls(raw=raw, distribution=distribution, module=m, product=p, module_from_slash=module_from_slash, purl=purl, module_purl=m_purl)

    @property
    def full_product_id(self) -> str:
        return self.raw


    @property
    def normalized_name(self) -> str:
        if self.product:
            name = re.sub(PACKAGE_VERSION_REGEX, "", self.product)
            name = re.sub(PACKAGE_VERSION_REGEX_UNDER, "", name)
        elif self.module:
            name = re.sub(MODULE_VERSION_REGEX, "", self.module)
        else:
            raise ValueError(f"for {self.full_product_id}, must set module or product")
        return name.lower()

    @property
    def module_name(self) -> str | None:
        if self.module_purl:
            if self.module_purl.version and ":" in self.module_purl.version:
                return f"{self.module_purl.name}:{self.module_purl.version.split(':')[0]}"
            return self.module_purl.name

        if self.module:
            return self.module

        return None

    @property
    def is_logical_product(self) -> bool:
        """is_logical_product returns true if the product would be reported
        in its own line in Red Hat vulnerability UIs, or should be its own line
        in grype-db. If the product is a module or a source RPM, return true"""
        if self.module and not self.product:
            return True  # modules are always logical products
        if self.product and self.product.endswith(".src"):
            return not self.module  # source RPMs are logical products unless descended from modules
        return False  # this is not a module or a src rpm - it's some component we shouldn't

    @property
    def version(self) -> str | None:
        if self.purl:
            version_maybe_epoch = self.purl.version
            epoch_qualifier = self.purl.qualifiers.get('epoch')
            # TODO: validate whether it's double specified?
            if re.match(r"^\d+:", version_maybe_epoch):
                return version_maybe_epoch
            elif epoch_qualifier:
                return f"{epoch_qualifier}:{version_maybe_epoch}"
            else:
                return f"0:{version_maybe_epoch}"
        return None


@dataclass
class RHEL_CSAFDocument:
    csaf: CSAF_JSON
    product_ids: dict[str, ProductID] = field(init=False)
    # logical_products: list[ProductID] = field(init=False)
    normalized_product_names_to_product_ids: dict[str, set[ProductID]] = field(init=False)
    distribution_ids_to_names: dict[str, str] = field(init=False)
    products_to_namespace: dict[ProductID, str] = field(init=False)
    namespaces_to_product_ids: dict[str, set[ProductID]] = field(init=False)
    products_to_purls: dict[ProductID, str] = field(init=False)
    cvss_objects_with_product_ids: list[tuple[CVSS, set[ProductID]]] = field(init=False)
    vendor_advisories_with_product_ids: list[VendorAdvisory, set[ProductID]] = field(init=False)
    product_ids_to_fixed_versions: dict[ProductID, list[FixedIn]] = field(init=False)
    namespaces_to_fixedins: dict[str, list[FixedIn]] = field(init=False)
    namespaces_to_vulnerabilities: dict[str, list[Vulnerability]] = field(init=False)
    severity: str = field(init=False)
    description: str = field(init=False)
    cve_id: str = field(init=False)
    vuln_url: str = field(init=False)

    def logical_products(self) -> list[ProductID]:
        """logical products returns a list of products that should be reported
        in a UI or to a user on a Grype match. It is the set of all modules, and
        all source RPMs that are not descended from modules, that are mentioned
        in the CSAF JSON that self was created from"""
        known_affected = [val for key, val in self.product_ids.items() if key in self.csaf.vulnerabilities[0].product_status.known_affected]
        under_investigation = [val for key, val in self.product_ids.items() if key in self.csaf.vulnerabilities[0].product_status.under_investigation]
        return [pid for pid in self.product_ids.values() if pid.is_logical_product] + known_affected + under_investigation

    def top_level_products(self) -> set[str]:
        return {
            b.name for b in self.csaf.product_tree.branches[0].branches
            if b.category == "product_version"
        }

    def initialize_product_id_maps(self):
        self.product_ids = {}
        str_ids_to_str_purls = {
            purl_branch.product.product_id: purl_branch.product.product_identification_helper.purl
            for purl_branch in self.csaf.product_tree.branches[0].product_version_branches()
            if purl_branch.product
            and purl_branch.product.product_identification_helper
            and purl_branch.product.product_identification_helper.purl
        }
        # self.logical_products = []
        parents = set(self.csaf.product_tree.product_id_to_parent.values())
        children = set(self.csaf.product_tree.product_id_to_parent.keys())
        modules = parents & children  # modules a products that a descended from a distro and have
        # components descended from them
        for m in modules:
            distro_part = self.csaf.product_tree.first_parent(m)
            module_part = m.removeprefix(distro_part).removeprefix(":")
            self.product_ids[m] = ProductID.create(raw=m,
                                                   distribution=distro_part,
                                                   module=module_part,
                                                   product=None,
                                                   package_url=str_ids_to_str_purls.get(module_part),
                                                   module_purl=None)  # TODO: really?
        leaf_products = children - parents
        for p in leaf_products:
            distribution = self.csaf.product_tree.first_parent(p)
            module = self.csaf.product_tree.second_parent(p)
            product_part = p.removeprefix(distribution).removeprefix(":")
            module_purl = None
            if module:
                module = module.removeprefix(distribution).removeprefix(":")
                product_part = product_part.removeprefix(module).removeprefix(":")
                module = module.removeprefix(distribution).removeprefix(":")
                module_purl = str_ids_to_str_purls.get(module)
            self.product_ids[p] = ProductID.create(raw=p,
                                                   distribution=distribution,
                                                   module=module,
                                                   product=product_part,
                                                   package_url=str_ids_to_str_purls.get(product_part),
                                                   module_purl=module_purl)
        # TODO: is this needed?
        # reverse dictionary as well
        for k, v in self.product_ids.items():
            if v.normalized_name not in self.normalized_product_names_to_product_ids:
                self.normalized_product_names_to_product_ids[v.normalized_name] = set()
            self.normalized_product_names_to_product_ids[v.normalized_name].add(k)

    def initialize_distro_map(self):
        # make a map from distro IDs (like AppStream-GA:8.3.2)
        # to product names like "Red Hat Enterprise Linux AppStream (v. 9)"
        distro_ids_to_cpe = {}
        for distro_branch in self.csaf.product_tree.branches[0].product_name_branches():
            if distro_branch.product:
                self.distribution_ids_to_names[distro_branch.product.product_id] = distro_branch.product.name
                pih = distro_branch.product.product_identification_helper
                if pih and pih.cpe:
                    distro_ids_to_cpe[distro_branch.product.product_id] = pih.cpe


        # use that map to map to make a map of product_ids to
        # to namespaces so that clients can easily get a vunnel namespace from each product id.
        for pid in self.product_ids.values():
            # distro_name = self.distribution_ids_to_names.get(pid.distribution, "")
            distro_cpe = distro_ids_to_cpe.get(pid.distribution, "")
            for r in RHEL_CPE_REGEXES:
                match = re.search(r, distro_cpe)
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

        # modules_to_purls = {
        #     purl_branch.product.product_id: purl_branch.product.product_identification_helper.purl
        #     for purl_branch in self.csaf.product_tree.branches[0].product_version_branches()
        #     if purl_branch.product
        #        and purl_branch.product.product_identification_helper
        #        and purl_branch.product.product_identification_helper.purl
        # }

        # go through the set of full product IDs
        # and, if the product component matches a value from the previous dictionary
        # associate it with the purl
        for pid in self.product_ids.values():
            if pid.product in product_id_component_to_purl:
                self.products_to_purls[pid] = product_id_component_to_purl[pid.product]
            elif pid.module in product_id_component_to_purl:
                self.products_to_purls[pid] = product_id_component_to_purl[pid.module]

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
            under_investigation = (str_id in self.csaf.vulnerabilities[0].product_status.under_investigation)
            fixed_and_src_rpm_or_module = pid.is_logical_product and str_id in self.csaf.vulnerabilities[0].product_status.fixed
            affected = str_id not in self.csaf.vulnerabilities[0].product_status.known_not_affected
            keep = affected and (not_fixed or under_investigation or fixed_and_src_rpm_or_module)
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
                for va, pids in self.vendor_advisories_with_product_ids:
                    if pid in pids:
                        vendor_advisory = va
                        break
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

    def initialize_namespaces_to_fixed_ins_and_vulnerabilities(self):
        self.namespaces_to_fixedins = {}
        self.namespaces_to_vulnerabilities = {}
        for ns, products in self.namespaces_to_product_ids.items():
            if ns not in self.namespaces_to_fixedins:
                self.namespaces_to_fixedins[ns] = []
            if ns not in self.namespaces_to_vulnerabilities:
                self.namespaces_to_vulnerabilities[ns] = []

            cvss_objects = [ c for c, prods in self.cvss_objects_with_product_ids
                             if any(p in prods for p in products)]
            for pid in products:
                fixed_in = None

                if self.is_fixed_src_rpm(pid) and not pid.module:
                    fixed_in = FixedIn(
                        Name=pid.normalized_name,
                        NamespaceName=ns,
                        VersionFormat="rpm",
                        Version=pid.version or "None", # TODO: the "or None" should be unreachable
                        Module=pid.module_name,
                        VendorAdvisory=self.best_applicable_vendor_advisory(pid),
                    )
                elif pid.module and not pid.product:
                    fixed_in = FixedIn(
                        Name=pid.normalized_name,
                        NamespaceName=ns,
                        VersionFormat="rpm",
                        Version=pid.version or "None", # TODO: the "or None" should be unreachable
                        Module=pid.module_name,
                        VendorAdvisory=self.best_applicable_vendor_advisory(pid),
                    )
                elif self.is_known_affected(pid):
                    fixed_in = FixedIn(
                        Name=pid.normalized_name,
                        NamespaceName=ns,
                        VersionFormat="rpm",
                        Version="None",
                        Module=pid.module_name,
                        VendorAdvisory=self.best_applicable_vendor_advisory(pid),
                    )
                if fixed_in:
                    self.namespaces_to_fixedins[ns].append(fixed_in)

            if self.namespaces_to_fixedins.get(ns):
                vuln = Vulnerability(
                    NamespaceName=ns,
                    Name=self.cve_id,
                    Description=self.description,
                    Severity=self.severity,
                    Link=self.vuln_url,
                    CVSS=cvss_objects,
                    FixedIn=sorted(self.namespaces_to_fixedins.get(ns), key=lambda f: (f.NamespaceName,f.Name,f.Module or "",f.Version)),
                )
                self.namespaces_to_vulnerabilities[ns].append(vuln)

    def best_applicable_vendor_advisory(self, pid) -> VendorAdvisory | None:
        vendor_advisory = None
        relevant_categories = {
            "no_fix_planned",
            "none_available",
            "vendor_fix",
        }
        applicable_remediations = [
            rem for rem in self.csaf.vulnerabilities[0].remediations
            if pid.full_product_id in rem.product_ids and rem.category in relevant_categories
        ]
        fixed_remediations = [
            rem for rem in applicable_remediations
            if rem.category == "vendor_fix"
        ]
        wont_fix_remediations = [
            rem for rem in applicable_remediations
            if (rem.category == "no_fix_planned" or
                (rem.category == "none_available" and rem.details == "Fix deferred")
                )
        ]
        if fixed_remediations and wont_fix_remediations:
            raise ValueError(f"for {pid.full_product_id}, found fixes and wont fix remediations")

        if fixed_remediations:
            fixed_remediations.sort(reverse=True, key=lambda x: x.url or "")
            return self.vendor_advisory_from_csaf_remediation(fixed_remediations[0])

        if wont_fix_remediations:
            return self.vendor_advisory_from_csaf_remediation(wont_fix_remediations[0])

        return None

    def vendor_advisory_from_csaf_remediation(self, rem: Remediation | None) -> VendorAdvisory | None:
        if not rem:
            return VendorAdvisory(NoAdvisory=False, AdvisorySummary=[])

        if rem.category == "vendor_fix":
            _, _, advisory_id = rem.url.rpartition("/")
            summary = AdvisorySummary(ID=advisory_id, Link=rem.url)
            return VendorAdvisory(AdvisorySummary=[summary], NoAdvisory=False)

        if rem.category == "no_fix_planned":
            return VendorAdvisory(NoAdvisory=True, AdvisorySummary=[])

        if rem.category == "none_available" and rem.details == "Fix deferred":
            return VendorAdvisory(NoAdvisory=True, AdvisorySummary=[])

        return VendorAdvisory(NoAdvisory=False, AdvisorySummary=[])

    def initialize_metadata(self):
        v = self.csaf.vulnerabilities[0]
        self.description = next((n.text for n in v.notes if n.category == "description"), "")
        self.cve_id = v.cve
        self.severity = parse_severity(self.csaf.document.aggregate_severity.text) or ""
        self.vuln_url = next((reference.url for reference in self.csaf.vulnerabilities[0].references if reference.category == "self"), "")

    def __post_init__(self) -> None:
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
        # self.initialize_fixed_ins2()
        self.initialize_metadata()
        self.initialize_namespaces_to_fixed_ins_and_vulnerabilities()

    def is_fixed_src_rpm(self, pid: ProductID) -> bool:
        # TODO: java-1.8.0-ibm-src should be a fixed product,
        # but has no src rpm by this naming convention
        return (pid.product
                and pid.product.endswith(".src")
                and any(pid.full_product_id
                    in r.product_ids for r
                    in self.csaf.vulnerabilities[0].remediations if r.category == "vendor_fix"))

    def is_known_affected(self, pid: ProductID) -> bool:
        return pid.full_product_id in self.csaf.vulnerabilities[0].product_status.known_affected

    def vulnerabilities_old(self, namespaces: set[str] | None = None) -> list[Vulnerability]:
        if namespaces is None:
            namespaces = {"rhel:5", "rhel:6", "rhel:7", "rhel:8", "rhel:9"}
        result = []
        logical_products = self.logical_products()
        top_level_product_names = self.top_level_products()
        for pid in logical_products:
            if pid in self.csaf.vulnerabilities[0].product_status.known_not_affected:
                continue
            named_for_top_level_product = (
                not top_level_product_names or
                any(RHEL_CSAFDocument.fuzzy_name_match(pid.normalized_name, tln) for tln in top_level_product_names))
            ns = self.products_to_namespace.get(pid)
            include = ns in namespaces and (named_for_top_level_product or self.is_fixed_src_rpm(pid))
            fixed_ins = self.product_ids_to_fixed_versions.get(pid)
            if include and fixed_ins:
                v = Vulnerability(
                    Name=self.cve_id,
                    NamespaceName=ns,
                    Description=self.description,
                    Severity=self.severity,
                    Link=self.vuln_url,
                    CVSS=[cvss for cvss, pids  in self.cvss_objects_with_product_ids if pid in pids],
                    FixedIn=fixed_ins,
                )
                result.append(v)
        return result

    def vulnerabilities(self, namespaces: set[str] | None = None) -> list[Vulnerability]:
        if namespaces is None:
            namespaces = {"rhel:5", "rhel:6", "rhel:7", "rhel:8", "rhel:9"}
        result = []
        for ns, vulns in self.namespaces_to_vulnerabilities.items():
            if ns in namespaces:
                result.extend(vulns)
        return result

    @classmethod
    def fuzzy_name_match(cls, a: str, b: str) -> bool:
        # TODO: is this better accomplished by referencing RHSAs?
        a = re.sub(r"\d+", "", a.lower())
        b = re.sub(r"\d+", "", b.lower())
        if 'kernel' in b or 'kernel' in a:
            a = a.removesuffix("-alt")
            b = b.removesuffix("-alt")
            a = a.removesuffix("-rt")
            b = b.removesuffix("-rt")
            a = a.removeprefix("realtime-")
            b = b.removeprefix("realtime-")
        return a in b or b in a  # TODO: which way?

    @classmethod
    def from_path(cls, path: str) -> "RHEL_CSAFDocument":
        with open(path) as fh:
            data = orjson.loads(fh.read())
            c = CSAF_JSON.from_dict(data)
            return cls(csaf=c)


# TEMP
import sqlite3
import os

KNOWN_WEIRD_PATHS = {
    # "data/rhel_csaf/input/csaf/2017/cve-2017-7541.json" : "kernel-rt"
    ## JVM ISSUES!
    ## JVM src rpms sometimes look like
    ## Supplementary-8.5.0.Z.MAIN:java-1.8.0-ibm-src-1:1.8.0.7.5-1.el8_5.x86_64
    "data/rhel_csaf/input/csaf/2019/cve-2019-2983.json" : "jvm ibm is weird",
    "data/rhel_csaf/input/csaf/2017/cve-2017-10295.json" : "jvm is weird",
    "data/rhel_csaf/input/csaf/2018/cve-2018-2790.json" : "jvm is weird",
    # "data/rhel_csaf/input/csaf/2022/cve-2022-21341.json" : "java-1.8.0-ibm is being weird",
    ## Extra packages I think are correct to include
    "data/rhel_csaf/input/csaf/2020/cve-2020-26116.json": "adds python27, but I think correctly",
    "data/rhel_csaf/input/csaf/2022/cve-2022-0435.json" : "adds kpatch-patch, but I think correctly",
    "data/rhel_csaf/input/csaf/2020/cve-2020-10768.json": "adds kpatch-patch, but I think correctly",
    "data/rhel_csaf/input/csaf/2022/cve-2022-41222.json": "adds kpatch-patch, but I think correctly",
    "data/rhel_csaf/input/csaf/2019/cve-2019-15239.json": "adds kpatch-patch, but I think correctly",
    "data/rhel_csaf/input/csaf/2022/cve-2022-27650.json" : "adds container-tools, but I think correctly",
    # "data/rhel_csaf/input/csaf/2021/cve-2021-3507.json" : "adds 'virt",

    ## Extra packages from module stuff
    "data/rhel_csaf/input/csaf/2023/cve-2023-45287.json" : "modules!!!",
    "data/rhel_csaf/input/csaf/2020/cve-2020-13956.json": "modules!!!",

    ## Extra packages and I don't know why
    "data/rhel_csaf/input/csaf/2021/cve-2021-30749.json": "probably need to query RHSA data: gtk3 should be excluded but isn't",
    "data/rhel_csaf/input/csaf/2023/cve-2023-41081.json" : "mod_proxy_cluster is included but shouldn't be; no idea yet",
}


EXPECTED_EXTRA_NAMES = {
    ## Extra packages I think are correct to include
    "data/rhel_csaf/input/csaf/2020/cve-2020-26116.json": { "python27" },
    "data/rhel_csaf/input/csaf/2022/cve-2022-0435.json" : { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2020/cve-2020-10768.json": { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2022/cve-2022-41222.json": { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2019/cve-2019-15239.json": { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2019/cve-2019-14835.json": { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2023/cve-2023-0386.json": { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2022/cve-2022-0330.json": { "kpatch-patch" },
    "data/rhel_csaf/input/csaf/2022/cve-2022-27650.json" : { "container-tools" },
}

def get_package_names(cve_id: str) -> set[str]:
    db_path = "~/Library/Caches/grype/db/5/vulnerability.db"

    # Expand `~` to the full home directory path
    db_path = os.path.expanduser(db_path)

    # Connect to the database
    with sqlite3.connect(db_path) as conn:
        # Create a cursor to execute the query
        cursor = conn.cursor()

        # Define the query with a placeholder for the CVE ID
        query = """
            SELECT DISTINCT package_name
            FROM vulnerability
            WHERE id LIKE ? AND namespace LIKE "%red%"
        """

        # Execute the query, passing the CVE ID as a parameter
        cursor.execute(query, (cve_id,))

        # Fetch all results and convert them to a set of strings
        package_names = {row[0] for row in cursor.fetchall()}

    return package_names

def kinda_same_package(human_name: str, machine_name: str) -> bool:
    # TODO: is this better accomplished by referencing RHSAs?
    m = re.sub(r"\d+", "", machine_name.lower())
    h = re.sub(r"\d+", "", human_name.lower())
    if 'kernel' in h or 'kernel' in m:
        m = m.removesuffix("-alt")
        h = h.removesuffix("-alt")
        m = m.removesuffix("-rt")
        h = h.removesuffix("-rt")
        m = m.removeprefix("realtime-")
        h = h.removeprefix("realtime-")
    return m in h or h in m # TODO: which way?

def main(json_path):
    cve_id = json_path.split("/")[-1].removesuffix(".json").upper()
    r = RHEL_CSAFDocument.from_path(json_path)
    namespaces_to_care_about = {"rhel:5", "rhel:6", "rhel:7", "rhel:8", "rhel:9"}
    logical_products = r.logical_products()
    logical_products_in_namespaces = [p for p in logical_products if
                                      r.products_to_namespace.get(p) in namespaces_to_care_about]
    top_level_names = r.top_level_products()
    # try grepping with top-level product
    logical_products_to_care_about = [p for p in logical_products_in_namespaces if any(kinda_same_package(n, p.normalized_name) for n in top_level_names) or not top_level_names or r.is_fixed_src_rpm(p)]
    new_names = {l.normalized_name for l in logical_products_to_care_about}
    old_names = get_package_names(cve_id)
    extra = new_names - old_names
    missing = old_names - new_names
    if extra:
        print("NEW NAMES INTRODUCED BY CHANGE")
        print(extra)
    if missing:
        print("OLD NAMES LOST BY CHANGE")
        print(missing)
    if extra or missing:
        print(f"failed! {cve_id} from {json_path}")
        print("try again!")
        print(f"poetry run python {sys.argv[0]} {json_path}")
        sys.exit(1)
    else:
        print(f"great victory! no diff for {cve_id} from {json_path}")

def alt_main(json_path):
    cve_id = json_path.split("/")[-1].removesuffix(".json").upper()
    r = RHEL_CSAFDocument.from_path(json_path)
    new_names = {
        f.Name for v in r.vulnerabilities() for f in v.FixedIn
    }
    old_names = get_package_names(cve_id)
    extra = new_names - old_names
    allowed_extra = EXPECTED_EXTRA_NAMES.get(json_path, set())
    extra = extra - allowed_extra
    missing = old_names - new_names
    if extra:
        print("NEW NAMES INTRODUCED BY CHANGE")
        print(extra)
    if missing:
        print("OLD NAMES LOST BY CHANGE")
        print(missing)
    if extra or missing:
        print(f"failed! {cve_id} from {json_path}")
        print("try again!")
        print(f"poetry run python {sys.argv[0]} {json_path}")
        sys.exit(1)
    else:
        print(f"great victory! no diff for {cve_id} from {json_path}")

if __name__ == "__main__":
    import sys
    for json_path in sys.argv[1:]:
        if not json_path:
            continue
        if json_path in KNOWN_WEIRD_PATHS:
            print(f"skipping {json_path}: {KNOWN_WEIRD_PATHS[json_path]}")
            continue
        try:
            alt_main(json_path)
        except Exception as e:
            print(f"Exception! {e}")
            print("try again!")
            print(f"poetry run python {sys.argv[0]} {sys.argv[1]}")
            raise e

