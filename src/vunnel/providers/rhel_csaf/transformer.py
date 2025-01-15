import re

from packageurl import PackageURL

from vunnel.utils.csaf_types import CSAFDoc, Remediation, Score
from vunnel.utils.vulnerability import CVSS, AdvisorySummary, FixedIn, VendorAdvisory, Vulnerability

RHEL_CPE_REGEXES = [
    # AppStream sometimes has ":a:" in CPE, not ":o:"
    r"^cpe:/[ao]:redhat:enterprise_linux:(\d+)(::(client|server|workstation|appstream|baseos|realtime|crb|supplementary))*$",
    r"^cpe:/a:redhat:rhel_extras_rt:(\d+)",
    r"^cpe:/a:redhat:rhel_extras_rt:(\d+)",
    r"^cpe:/a:redhat:rhel_virtualization:(\d+)(::(client|server))?",
]

SEVERITY_DICT = {
    "low": "Low",
    "moderate": "Medium",
    "important": "High",
    "critical": "Critical",
}

# Product names like this are rarely vulnerable in and of themselves, but
# are listed in the RHEL CSAF data only because their src RPM or module
# versioned
DENY_SUBSTRINGS = ["-langpack-", "-debug", "-debuginfo"]


class NamespaceMatcher:
    def __init__(self, csaf: CSAFDoc, skip_namespaces: set[str] | None = None):
        prefixes_to_namespaces = {}
        self.skip_namespaces = skip_namespaces or set()
        for b in csaf.product_tree.branches[0].product_name_branches():
            prefix = b.product_id()
            cpe = b.cpe()
            if not (cpe and prefix):
                continue
            for r in RHEL_CPE_REGEXES:
                match = re.search(r, cpe)
                if match:
                    version = match.group(1)
                    ns = f"rhel:{version}"
                    prefixes_to_namespaces[prefix] = ns
        self.prefixes_to_namespaces = prefixes_to_namespaces

    def namespace_from_product_id(self, pid: str) -> str | None:
        for prefix, ns in self.prefixes_to_namespaces.items():
            if ns in self.skip_namespaces:
                continue
            if pid.startswith(prefix):
                return ns
        return None


class NameFilter:
    def __init__(self, csaf: CSAFDoc):
        self.affected_top_level_products: set[str] = set()
        for b in csaf.product_tree.branches[0].branches:
            if b.category == "product_version" and b.product and b.product.product_id:
                self.affected_top_level_products.add(b.product.product_id)

        self.versionless_source_rpms: set[str] = set()
        self.rpm_module_names: set[str] = set()
        for b in csaf.product_tree.branches[0].product_version_branches():
            maybe_purl = b.purl()
            if maybe_purl:
                purl = PackageURL.from_string(maybe_purl)
                if purl and purl.qualifiers and isinstance(purl.qualifiers, dict):  # noqa: SIM102
                    if purl.qualifiers.get("arch") in ["src", "noarch"] and not purl.version:
                        self.versionless_source_rpms.add(purl.name)

                if purl.type == "rpmmod" and purl.name:
                    self.rpm_module_names.add(purl.name)
        self.all_expected_names = self.affected_top_level_products | self.rpm_module_names | self.versionless_source_rpms

    def include(self, product_name: str, module_name: str | None) -> bool:
        if module_name:
            return product_name in self.all_expected_names
        return not any(deny in product_name for deny in DENY_SUBSTRINGS)


def base_vulnerability(csaf: CSAFDoc, namespace_name: str) -> Vulnerability:
    if len(csaf.vulnerabilities) != 1:
        raise ValueError("unexpected document type; RHEL VEX CSAF documents should have exactly 1 vulnerability per document")
    cve_id = csaf.vulnerabilities[0].cve
    severity = SEVERITY_DICT.get(csaf.document.aggregate_severity.text.lower(), "Unknown")
    description = next((n.text for n in csaf.vulnerabilities[0].notes if n.category == "description"), "")
    link = next((r.url for r in csaf.vulnerabilities[0].references or [] if r.category == "self"), "")
    return Vulnerability(
        Name=cve_id,
        NamespaceName=namespace_name,
        Description=description,
        Severity=severity,
        Link=link,
        CVSS=[],
        FixedIn=[],
    )


def parse_cvss(scores: list[Score], status: str, full_product_id: str) -> CVSS | None:
    for s in scores:
        if full_product_id in s.products and s.cvss_v3:
            return s.to_vunnel_cvss(status)
    return None


def marked_will_not_fix(remediations: list[Remediation], qpi: str) -> bool:
    return any(r for r in remediations if qpi in r.product_ids and r.category == "no_fix_planned")


def vulnerabilities_by_namespace(  # noqa: C901, PLR0912, PLR0915
    csaf: CSAFDoc,
    skip_namespaces: set[str] | None = None,
) -> dict[str, Vulnerability]:
    """
    namespace -> vulnerabilities -> fixed-ins
    {
        "rhel:8": [
            {
              "Name": "CVE-12345",
              "FixedIn": [],
            }
        ]
    }
    """
    if len(csaf.vulnerabilities) != 1:
        # This parser was probably called on a CSAFDoc that's not a RHEL CSAF VEX doc, for example on an RHSA CSAFDoc.
        # It doesn't know how to parse those.
        raise ValueError("unexpected document type; RHEL VEX CSAF documents should have exactly 1 vulnerability per document")

    vuln = csaf.vulnerabilities[0]
    if not vuln.product_status:
        return {}

    if not csaf.product_tree.branches:
        return {}

    ns_matcher = NamespaceMatcher(csaf=csaf, skip_namespaces=skip_namespaces)
    ns_to_vulnerability = {}
    module_pid_to_purl = {}
    # Keep a map of product IDs that represent modules to the PURLs
    # so that we can accurately get module version info later.
    for b in csaf.product_tree.branches[0].product_version_branches():
        if b.product and b.product.product_identification_helper and b.product.product_identification_helper.purl:
            purl_str = b.product.product_identification_helper.purl
            purl = PackageURL.from_string(purl_str)
            if purl.type == "rpmmod":
                module_pid_to_purl[b.product.product_id] = purl

    name_filter = NameFilter(csaf=csaf)
    seen_already = set()

    for b in csaf.product_tree.branches[0].product_version_branches():
        if b.product and b.product.product_identification_helper and b.product.product_identification_helper.purl:
            purl_str = b.product.product_identification_helper.purl
            purl = PackageURL.from_string(purl_str)
            if purl.type not in ["rpm", "rpmmod"]:
                continue
            product_id = b.product.product_id
            qualified_product_ids = [
                r.full_product_name.product_id for r in csaf.product_tree.relationships if r.product_reference == product_id
            ]

            for qpi in qualified_product_ids:
                if qpi in vuln.product_status.known_not_affected or qpi in vuln.product_status.under_investigation:
                    continue
                name = purl.name

                namespace_name = ns_matcher.namespace_from_product_id(qpi)
                if not namespace_name:
                    continue
                if namespace_name not in ns_to_vulnerability:
                    ns_to_vulnerability[namespace_name] = base_vulnerability(csaf, namespace_name)
                version_format = "rpm"
                version = "None"
                module = None
                if purl.type == "rpmmod":
                    if purl.namespace:
                        if not purl.namespace.startswith("redhat/"):
                            # We see two kinds of "rpmmod" type PURLs:
                            # "pkg:rpmmod/redhat/ruby@3.0:8060020220810162001:ad008a3a"
                            # with namespace "redhat" (no /) and "pkg:rpmmod/redhat/ruby:2.6/ruby"
                            # with namespace "redhat/ruby:2.6".
                            # The second kind is really a package namespaced into a module
                            # e.g ruby as part of ruby:2.6 module, and we should keep those.
                            # The first kind is a module going to contain many packages, and we'll
                            # pick those when we do the component packages.
                            continue
                        module = purl.namespace.removeprefix("redhat/")
                else:  # "rpm"
                    module_pid = None
                    parent = csaf.product_tree.parent(qpi)
                    if not parent:
                        # TODO: log a warning - got a leaf product with no parent distro or module
                        continue
                    grand_parent = csaf.product_tree.parent(parent or "NONE")
                    if grand_parent:
                        module_pid = parent.removeprefix(grand_parent).removeprefix(":")
                    if not module_pid:
                        module_pid = csaf.product_tree.second_parent(qpi)
                    if module_pid:
                        module_purl = module_pid_to_purl.get(module_pid)
                        if module_purl and module_purl.version:
                            module = f"{module_purl.name}:{module_purl.version.split(':')[0]}"
                if qpi in vuln.product_status.fixed:
                    # a module might be patched all at once, in which case
                    # there are "fixed" products that were never vulnerable.
                    # Check whether each fixed product was reported in the top of the
                    # doc before emitting a FixedIn for it.
                    # Therefore, only include packages that are part of a module if the
                    # name filter includes them
                    if not name_filter.include(purl.name, module):
                        continue
                    if purl.version:
                        version = purl.version
                    remediations = [r for r in vuln.remediations if qpi in r.product_ids and r.category == "vendor_fix"]
                    if remediations and remediations[0].url:
                        vendor_advisory = VendorAdvisory(
                            NoAdvisory=False,
                            AdvisorySummary=[
                                AdvisorySummary(Link=remediations[0].url or "", ID=remediations[0].url.split("/")[-1]),
                            ],
                        )
                elif qpi in vuln.product_status.known_affected:
                    vendor_advisory = VendorAdvisory(NoAdvisory=marked_will_not_fix(vuln.remediations, qpi), AdvisorySummary=[])
                    version = "None"

                if version != "None" and ":" not in version:
                    epoch = purl.qualifiers.get("epoch", "0") if purl.qualifiers and isinstance(purl.qualifiers, dict) else "0"
                    version = f"{epoch}:{version}"

                fi_tuple = (name, namespace_name, version_format, version, module)
                if fi_tuple in seen_already:
                    continue

                seen_already.add(fi_tuple)

                fixed_in = FixedIn(
                    Name=name,
                    NamespaceName=namespace_name,
                    VersionFormat=version_format,
                    Version=version,
                    VendorAdvisory=vendor_advisory,
                    Module=module,
                )
                ns_to_vulnerability[namespace_name].FixedIn.append(fixed_in)
                # The CSAF spec permits many scores to be defined per document,
                # associating each score with a set of product IDs. Vunnel permits
                # many scores per vulnerability record, but no way to associate
                if not ns_to_vulnerability[namespace_name].CVSS:
                    maybe_cvss = parse_cvss(csaf.vulnerabilities[0].scores, csaf.document.tracking.status, qpi)
                    if maybe_cvss:
                        ns_to_vulnerability[namespace_name].CVSS.append(maybe_cvss)

    return ns_to_vulnerability
