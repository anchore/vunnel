from decimal import Decimal
import logging
import os
import re
from collections import defaultdict
from collections.abc import Generator

from cvss import CVSS3

from vunnel.utils import http
from vunnel.utils.archive import extract
from vunnel.utils.csaf_types import CSAF_JSON, CVSS_V3 as CSAF_CVSS_V3, from_path
from vunnel.utils.vulnerability import FixedIn, Vulnerability, CVSS, CVSSBaseMetrics
from vunnel.workspace import Workspace

namespace = "rhel"

VEX_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt"
SEVERITY_DICT = {
    "low": "Low",
    "moderate": "Medium",
    "important": "High",
    "critical": "Critical",
}


def get_severity(sev: str) -> str | None:
    return SEVERITY_DICT.get(sev)


def trim_rpm_version_suffix(product_id: str) -> str:
    version_suffix = r"-(\d+):.*$"
    return re.sub(version_suffix, "", product_id)


def purl_to_rpm_version(purl: str | None) -> str | None:
    # "pkg:rpmmod/redhat/mariadb@10.3:8060020220715055054:ad008a3a"
    # or
    # "pkg:rpm/redhat/mysql-selinux@1.0.5-1.el9_0?arch=noarch"
    if not purl:
        return None
    match = re.search(r"@([^?]+)", purl)
    return match.group(1) if match else None


RHEL_VERSIONS_TO_NAMESPACES = {
    "5": "rhel:5",
    "6": "rhel:6",
    "7": "rhel:7",
    "8": "rhel:8",
    "9": "rhel:9",
}

LANGPACK_RE = r"-langpack(-[a-z]{2,3})?"

APP_STREAM_RE = r"Red Hat Enterprise Linux AppStream \(v\. (\d+)\)"
BASE_OS_RE = r"Red Hat Enterprise Linux BaseOS \(v\. (\d+)\)"
RHEL_5_SERVER_RE = r"Red Hat Enterprise Linux \(v\. (\d+) server\)"
RHEL_5_SERVER_RE2 = r"^Red Hat Enterprise Linux Server \(v\. (\d+)\)"
RHEL_CLIENT_OLD_RE = r"^Red Hat Enterprise Linux Desktop \(v\. (\d+) client\)"
RHEL_DESKTOP_RE = r"^Red Hat Enterprise Linux Desktop \(v\. (\d+)\)"
RHEL_CLIENT_OPTIONAL_RE = r"Red Hat Enterprise Linux Client Optional \(v\. (\d+)\)"
RHEL_CLIENT_RE = r"Red Hat Enterprise Linux Client \(v\. (\d+)\)"
RHEL_RT_RE = r"Red Hat Enterprise Linux RT \(v\. (\d+)\)"
RHEL_RT_RE2 = r"Red Hat Enterprise Linux for Real Time \(v\. (\d+)\)"
RHEL_RT_RE3 = r"Red Hat Enterprise Linux Real Time \(v\. (\d+)\)"
RHEL_CRB_RE = r"Red Hat CodeReady Linux Builder \(v\. (\d+)\)"


def namespace_or_none_if_ignored(distro_like_name: str) -> str | None:
    result = None
    version = None
    res = [
        APP_STREAM_RE,
        BASE_OS_RE,
        RHEL_5_SERVER_RE,
        RHEL_5_SERVER_RE2,
        RHEL_CLIENT_OLD_RE,
        RHEL_DESKTOP_RE,
        RHEL_CLIENT_OPTIONAL_RE,
        RHEL_CLIENT_RE,
        RHEL_RT_RE,
        RHEL_RT_RE2,
        RHEL_RT_RE3,
        RHEL_CRB_RE,
    ]
    for r in res:
        match = re.search(r, distro_like_name)
        if match:
            version = match.group(1)
            break
    if not version and " " in distro_like_name:
        distro, v = distro_like_name.rsplit(" ", 1)
        if distro == "Red Hat Enterprise Linux":
            version = v

    if version:
        result = RHEL_VERSIONS_TO_NAMESPACES.get(version)

    return result


def cvss_from_csaf_score(score: CSAF_CVSS_V3, verified: bool) -> CVSS:
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


class Parser:
    def __init__(
        self,
        workspace: Workspace,
        download_timeout=None,
        skip_namespaces=None,
        logger=None,
    ):
        self.workspace = workspace
        self.download_timeout = download_timeout if isinstance(download_timeout, int) else 125
        self.skip_namespaces = skip_namespaces if isinstance(skip_namespaces, list) else ["rhel:3", "rhel:4"]
        self.rhsa_dict = None
        self.urls = []

        self.download_path = os.path.join(self.workspace.input_path, "vex_archive.tar.zst")
        self.csaf_path = os.path.join(self.workspace.input_path, "csaf")

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def download(self):
        latest_resp = http.get(url=VEX_LATEST_URL, logger=self.logger)
        archive_filename = latest_resp.content.decode()
        archive_url = VEX_LATEST_URL.replace("archive_latest.txt", archive_filename)
        self.urls = [archive_url]
        with http.get(archive_url, logger=self.logger, stream=True) as resp, open(self.download_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):  # 64k chunks
                if chunk:
                    fh.write(chunk)

    def extract_all(self):
        os.makedirs(self.csaf_path, exist_ok=True)
        extract(self.download_path, self.csaf_path)

    def fetch(self):
        self.download()
        self.extract_all()

    def _csaf_vex_files(self) -> Generator[str]:
        for root, _, files in os.walk(self.csaf_path):
            for file in files:
                if file.endswith(".json"):
                    yield os.path.join(root, file)

    def process(self) -> Generator[tuple[str, str, Vulnerability]]:
        for file_path in self._csaf_vex_files():
            try:
                csaf_doc = from_path(file_path)
                yield from self._process_csaf(csaf_doc)
            except Exception as e:
                self.logger.warning(f"failed to process {file_path}: {e}")
                # TODO: fail gracefully; for now warn each failure
                raise e

    def _process_csaf(self, csaf_doc: CSAF_JSON) -> Generator[tuple[str, str, Vulnerability]]:
        for i in range(len(csaf_doc.vulnerabilities)):
            yield from self._process_csaf_vuln(csaf_doc, i)

    def _process_csaf_vuln(self, csaf_doc: CSAF_JSON, vuln_index: int) -> Generator[tuple[str, str, Vulnerability]]:
        v = csaf_doc.vulnerabilities[vuln_index]
        vuln_id = v.cve
        vuln_records = []
        unaffected = set(v.product_status.known_not_affected) if v.product_status else set()
        description = next((n.text for n in v.notes if n.category == "description"), "")
        vuln_url = next((r.url for r in v.references if r.category == "self"), "")
        fixed = set(v.product_status.fixed) if v.product_status else set()
        not_fixed = set(v.product_status.known_affected) if v.product_status else set()
        severity = get_severity(csaf_doc.document.aggregate_severity.text)
        products = []
        ids_to_first_parents = {pid: csaf_doc.product_tree.first_parent(pid) for pid in unaffected | fixed | not_fixed}
        ids_to_second_parents = {pid: csaf_doc.product_tree.second_parent(pid) for pid in unaffected | fixed | not_fixed}
        distro_ids_to_names = {
            b.product.product_id: b.product.name for b in csaf_doc.product_tree.branches[0].product_name_branches() if b.product
        }
        product_ids_to_purls = {
            b.product.product_id: b.product.product_identification_helper.purl
            for b in csaf_doc.product_tree.branches[0].product_version_branches()
            if b.product and b.product.product_identification_helper
        }

        # TODO: make this dict[str,str] where keys are original ids and values are cleaned up ids
        def clean_product_id(pid: str) -> str:
            second_parent = ids_to_second_parents.get(pid)
            p = pid
            if second_parent:
                p = second_parent
                p = re.sub(r":(rhel)?\d+(\.\d)*:\d{19}:[a-fA-F0-9]{8}$", "", p)
            p = trim_rpm_version_suffix(p)
            p = p.removeprefix(ids_to_first_parents.get(pid, ""))
            p = p.removeprefix(":").removesuffix("-headers")
            return p.lower()

        products = [trim_rpm_version_suffix(p) for p in fixed | not_fixed]
        products = [p.removeprefix(ids_to_first_parents.get(p, "")) for p in products]
        products = [p.removeprefix(":") for p in products]
        product_ids_to_logical_products = {p: clean_product_id(p) for p in fixed | not_fixed}
        product_ids_to_namespaces = {
            p: namespace_or_none_if_ignored(distro_ids_to_names.get(ids_to_first_parents.get(p, ""), ""))
            for p in unaffected | fixed | not_fixed
        }

        product_ids_to_rhsa_fixes = {}
        for r in v.remediations:
            if r.category == "vendor_fix" and r.url:
                for product_id in r.product_ids:
                    product_ids_to_rhsa_fixes[product_id] = r.url.split("/")[-1]

        source_rpm_ids = csaf_doc.product_tree.branches[0].source_rpm_product_ids()
        rpm_module_branches = {
            b.product.product_id
            for b in csaf_doc.product_tree.product_branches()
            if b.product
            and b.product.product_identification_helper
            and b.product.product_identification_helper.purl
            and "rpmmod" in b.product.product_identification_helper.purl
        }

        namespace_to_logical_product_name_to_fixed_ins: dict[str, dict[str, list[FixedIn]]] = defaultdict(
            lambda: defaultdict(list),
        )
        full_product_id_to_cvss: dict[str, CVSS] = {}
        for s in v.scores:
            if s.cvss_v3:
                cvss_obj = cvss_from_csaf_score(s.cvss_v3, verified=csaf_doc.document.tracking.status == "final")
                for p in s.products:
                    full_product_id_to_cvss[p] = cvss_obj

        for full_product_id, logical_product_name in product_ids_to_logical_products.items():
            namespace = product_ids_to_namespaces.get(full_product_id)
            if not namespace:
                continue
            keep = False
            for srpm_id in source_rpm_ids:
                if csaf_doc.product_tree.has_ancestor(full_product_id, srpm_id) or full_product_id.endswith(srpm_id):
                    keep = True
            module_branch = next((m for m in rpm_module_branches if m in full_product_id), None)
            if module_branch:
                keep = True
            if "/" in logical_product_name:
                logical_product_name = logical_product_name.split("/")[1]
            if full_product_id in not_fixed:
                namespace_to_logical_product_name_to_fixed_ins[namespace][logical_product_name].append(
                    FixedIn(
                        Name=logical_product_name,
                        NamespaceName=namespace,
                        Version="None",
                        VersionFormat="rpm",
                        Module=None,  # TODO: we need to put something here
                        VendorAdvisory=None,  # TODO: we probably know what this is from the fixed data
                    ),
                )
                continue
            if not keep:
                continue
            if full_product_id not in ids_to_second_parents:  # this is not a module
                # TODO: this is really a module?
                logical_id = full_product_id.removeprefix(ids_to_first_parents[full_product_id])
                purl = product_ids_to_purls[logical_id]
                version = purl_to_rpm_version(purl)
                if not version:
                    self.logger.warning(
                        f"skipping {full_product_id} / {logical_product_name} because could not get version from {purl}",
                    )
                    continue
                namespace_to_logical_product_name_to_fixed_ins[namespace][logical_product_name].append(
                    FixedIn(
                        Name=logical_product_name,
                        NamespaceName=namespace,
                        Version=version,
                        VersionFormat="rpm",
                        Module=None,  # TODO: we need to put something here
                        VendorAdvisory=None,  # TODO: we probably know what this is from the fixed data
                    ),
                )

        for ns, package_to_fixedins in namespace_to_logical_product_name_to_fixed_ins.items():
            vuln_records.append(
                Vulnerability(
                    Name=vuln_id,
                    NamespaceName=ns,
                    Description=description,
                    Severity=severity,
                    Link=vuln_url,
                    CVSS=list(full_product_id_to_cvss.values()),  # TODO: account for different CVSS for different products
                    FixedIn=[fixed_in for fixed_ins_list in package_to_fixedins.values() for fixed_in in fixed_ins_list],
                ),
            )

        for vr in vuln_records:
            yield vr.NamespaceName, vuln_id, vr

    def get(self, skip_if_exists=False) -> Generator[tuple[str, str, dict]]:
        # TODO: configurable to skip exists
        # self.fetch()
        for namespace, vuln_id, record in self.process():
            yield namespace, vuln_id, record.to_payload()
