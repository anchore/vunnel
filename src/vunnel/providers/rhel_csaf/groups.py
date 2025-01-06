from packageurl import PackageURL

from vunnel.providers.rhel_csaf.transformer import NamespaceMatcher
from vunnel.utils.csaf_types import CSAF_JSON
from vunnel.utils.vulnerability import (AdvisorySummary, FixedIn,
                                        VendorAdvisory, Vulnerability)


class RedHatCSAFWrapper:
    def __init__(self, csaf: CSAF_JSON):
        self.csaf = csaf


def all_the_groups(csaf: CSAF_JSON) -> dict[str, Vulnerability]:
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
    cve_id = csaf.vulnerabilities[0].cve
    severity = csaf.document.aggregate_severity.text
    link = "TODO"
    description = "TODO"

    ns_matcher = NamespaceMatcher(csaf=csaf)
    ns_to_vulnerability = {}
    module_pid_to_purl = {}
    for b in csaf.product_tree.branches[0].product_version_branches():
        if b.product and b.product.product_identification_helper and b.product.product_identification_helper.purl:
            purl_str = b.product.product_identification_helper.purl
            purl = PackageURL.from_string(purl_str)
            if purl.type == "rpmmod":
                module_pid_to_purl[b.product.product_id] = purl

    affected_top_level_products = []
    for b in csaf.product_tree.branches[0].branches:
        if b.category == "product_version" and b.product and b.product.product_id:
            affected_top_level_products.append(b.product.product_id)

    for b in csaf.product_tree.branches[0].product_version_branches():
        if b.product and b.product.product_identification_helper and b.product.product_identification_helper.purl:
            purl_str = b.product.product_identification_helper.purl
            purl = PackageURL.from_string(purl_str)
            if purl.type not in ["rpm", "rpmmod"]:
                continue
            if purl.name not in affected_top_level_products:
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
                if namespace_name not in ns_to_vulnerability:
                    ns_to_vulnerability[namespace_name] = Vulnerability(
                        Name=cve_id,
                        NamespaceName=namespace_name,
                        Description=description,
                        Severity=severity or "Unknown",
                        Link=link,
                        FixedIn=[],
                        CVSS=[],
                    )
                version_format = "rpm"
                version = "None"
                module = None
                if purl.type == "rpmmod":
                    if not purl.namespace.startswith("redhat/"):
                        # We see two kinds of "rpmmod" type PURLs:
                        # "pkg:rpmmod/redhat/ruby@3.0:8060020220810162001:ad008a3a"
                        # and "pkg:rpmmod/redhat/ruby:2.6/ruby"
                        # The second part is really a package namespaced into a module
                        # e.g ruby as part of ruby:2.6 module, and we should keep those.
                        # The first case is going to contain many packages, and we'll
                        # pick those when we do the component packages.
                        continue
                    module = purl.namespace.removeprefix("redhat/")
                else:  # "rpm"
                    module_pid = csaf.product_tree.second_parent(qpi)
                    if module_pid:
                        module_purl = module_pid_to_purl.get(module_pid)
                        if module_purl:
                            module = f"{module_purl.name}:{module_purl.version.split(':')[0]}"
                if qpi in csaf.vulnerabilities[0].product_status.fixed:
                    if purl.version:
                        version = purl.version
                    remediations = [r for r in csaf.vulnerabilities[0].remediations if qpi in r.product_ids]
                    if remediations:
                        vendor_advisory = VendorAdvisory(
                            NoAdvisory=False,
                            AdvisorySummary=[
                                AdvisorySummary(Link=remediations[0].url or "", ID=remediations[0].url.split("/")[-1])
                            ],
                        )
                elif qpi in csaf.vulnerabilities[0].product_status.known_affected:
                    version = "None"
                elif qpi in csaf.vulnerabilities[0].product_status.known_not_affected:
                    continue
                elif qpi in csaf.vulnerabilities[0].product_status.under_investigation:
                    # TODO: is this right?
                    continue

                if version != "None" and ":" not in version:
                    if purl.qualifiers and isinstance(purl.qualifiers, dict):
                        epoch = purl.qualifiers.get("epoch", "0")
                    else:
                        epoch = "0"
                    version = f"{epoch}:{version}"

                fixed_in = FixedIn(
                    Name=name,
                    NamespaceName=namespace_name,
                    VersionFormat=version_format,
                    Version=version,
                    VendorAdvisory=vendor_advisory,
                    Module=module,
                )
                ns_to_vulnerability[namespace_name].FixedIn.append(fixed_in)

    return ns_to_vulnerability
