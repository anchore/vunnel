import re
from typing import Callable

from vunnel.utils.csaf_types import CSAF_JSON
from vunnel.utils.vulnerability import FixedIn, VendorAdvisory, Vulnerability

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
    def __init__(self, csaf: CSAF_JSON):
        prefixes_to_namespaces = {}
        for b in csaf.product_tree.branches[0].product_name_branches():
            if not b.product:
                continue
            if not b.product.product_id:
                continue
            if not b.product.product_identification_helper:
                continue
            if not b.product.product_identification_helper.cpe:
                continue
            cpe = b.product.product_identification_helper.cpe
            prefix = b.product.product_id
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


def fixed_in_from_product_id(csaf: CSAF_JSON, product_id: str, namespace: str, fixed: bool) -> FixedIn:
    version = ""
    if not fixed:
        version = "None"

    va = VendorAdvisory(NoAdvisory=True, AdvisorySummary=[])
    if fixed:
        # TODO: get the fix info from the csaf doc
        pass
    return FixedIn(
        Name="TODO",
        Module="TODO",
        VendorAdvisory=va,
        NamespaceName=namespace,
        VersionFormat="rpm",
        Version=version,
    )


def src_only(_csaf: CSAF_JSON, product_id: str) -> bool:
    return product_id.endswith(".src")


def transform_csaf_json(csaf_json: CSAF_JSON, filter: Callable[[CSAF_JSON, str], bool] = src_only) -> list[Vulnerability]:
    ns_matcher = NamespaceMatcher(csaf=csaf_json)
    vuln_dicts = []

    if filter is None:
        filter = lambda _a, _b: True

    for v in csaf_json.vulnerabilities:
        ns_to_vulns = {}
        cve_name = v.cve
        severity = SEVERITY_DICT.get(csaf_json.document.aggregate_severity.text.lower()) or ""
        link = next((reference.url for reference in v.references or [] if reference.category == "self"), "")
        description = next((n.text for n in v.notes if n.category == "description"), "")
        for fixed_product_id in sorted(list(v.product_status.fixed)):
            if not filter(csaf_json, fixed_product_id):
                continue
            ns = ns_matcher.namespace_from_product_id(fixed_product_id)
            if ns and not ns in ns_to_vulns:
                ns_to_vulns[ns] = Vulnerability(
                    Name=cve_name,
                    NamespaceName=ns,
                    Description=description,
                    Severity=severity,
                    Link=link,
                    CVSS=[],
                    FixedIn=[],
                )
            if ns:
                ns_to_vulns[ns].FixedIn.append(fixed_in_from_product_id(csaf_json, fixed_product_id, ns, True))

        for vulnerable_product_id in sorted(list(v.product_status.known_affected)):
            # if not filter(csaf_json, vulnerable_product_id):
            #     continue
            ns = ns_matcher.namespace_from_product_id(vulnerable_product_id)
            if ns and not ns in ns_to_vulns:
                ns_to_vulns[ns] = Vulnerability(
                    Name=cve_name,
                    NamespaceName=ns,
                    Description=description,
                    Severity=severity,
                    Link=link,
                    CVSS=[],
                    FixedIn=[],
                )
            if ns:
                ns_to_vulns[ns].FixedIn.append(fixed_in_from_product_id(csaf_json, vulnerable_product_id, ns, False))

        for likely_vulnerable_product_id in sorted(list(v.product_status.under_investigation)):
            # TODO: convert to "None" fixed in
            pass
        vuln_dicts.append(ns_to_vulns)

    return [vuln for vuln_dict in vuln_dicts for vuln in vuln_dict.values()]
