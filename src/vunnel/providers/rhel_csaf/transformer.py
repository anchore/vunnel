import re

from packageurl import PackageURL

from vunnel.utils.csaf_types import CSAFDoc, Score
from vunnel.utils.vulnerability import CVSS, AdvisorySummary, FixedIn, VendorAdvisory, Vulnerability

RHEL_CPE_REGEXES = [
    r"^cpe:/[ao]:redhat:enterprise_linux:(\d+)(::(client|server|workstation|appstream|baseos|realtime|crb|supplementary))*$",  # appstream has :a:
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


class NamespaceMatcher:
    def __init__(self, csaf: CSAFDoc):
        prefixes_to_namespaces = {}
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
            if pid.startswith(prefix):
                return ns
        return None


class NameFilter:
    def __init__(self, csaf: CSAFDoc):
        affected_top_level_products = []
        for b in csaf.product_tree.branches[0].branches:
            if b.category == "product_version" and b.product and b.product.product_id:
                affected_top_level_products.append(b.product.product_id)

        versionless_source_rpms = []
        rpm_module_names = []
        for b in csaf.product_tree.branches[0].product_version_branches():
            maybe_purl = b.purl()
            if maybe_purl:
                purl = PackageURL.from_string(maybe_purl)
                if purl and purl.qualifiers and isinstance(purl.qualifiers, dict):  # noqa: SIM102
                    if purl.qualifiers.get("arch") in ["src", "noarch"] and not purl.version:
                        versionless_source_rpms.append(purl.name)

                if purl.type == "rpmmod" and purl.name:
                    rpm_module_names.append(purl.name)
        self.included = set(affected_top_level_products + versionless_source_rpms + rpm_module_names)

    def include(self, product_name: str) -> bool:
        return product_name in self.included


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

    ns_matcher = NamespaceMatcher(csaf=csaf)
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
                vendor_advisory = VendorAdvisory(NoAdvisory=True, AdvisorySummary=[])
                name = purl.name

                namespace_name = ns_matcher.namespace_from_product_id(qpi)
                if not namespace_name:
                    continue
                if skip_namespaces and namespace_name in skip_namespaces:
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
                    if module and not name_filter.include(purl.name):
                        continue
                    if purl.version:
                        version = purl.version
                    remediations = [r for r in vuln.remediations if qpi in r.product_ids]
                    if remediations and remediations[0].url:
                        vendor_advisory = VendorAdvisory(
                            NoAdvisory=False,
                            AdvisorySummary=[
                                AdvisorySummary(Link=remediations[0].url or "", ID=remediations[0].url.split("/")[-1]),
                            ],
                        )
                elif qpi in vuln.product_status.known_affected:
                    version = "None"
                elif qpi in vuln.product_status.known_not_affected:
                    continue
                elif qpi in vuln.product_status.under_investigation:
                    # TODO: should this be configurable?
                    continue

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
