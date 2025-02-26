from collections.abc import Generator, Iterable
import logging
import os
from pathlib import Path
import re
from typing import Any

from cpe import CPE
import mashumaro

from vunnel.utils import http
from vunnel.utils.archive import extract
from vunnel.utils.csaf_types import Branch, CSAFDoc, from_path as csaf_from_path
from vunnel.utils.vulnerability import FixedIn, VendorAdvisory, Vulnerability
from vunnel.workspace import Workspace


class CSAFParser:
    __csaf_url_template__ = "https://ftp.suse.com/pub/projects/security/csaf-vex/{}"
    __tar_url__ = "https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2"
    __csaf_dir_path__ = "csaf"
    __source_dir_path__ = "source"

    def __init__(
        self,
        workspace: Workspace,
        allow_versions: list[str],
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.csaf_dir = os.path.join(workspace.input_path, self.__source_dir_path__, self.__csaf_dir_path__)
        self.allow_versions = allow_versions
        self.download_timeout = download_timeout
        self.urls = []
        self.logger = logger or logging.getLogger("sles-csaf-parser")

    def download(self):
        if not os.path.exists(self.csaf_dir):
            os.makedirs(self.csaf_dir)
        csaf_tar_path = os.path.join(self.csaf_dir, "csaf-vex.tar.bz2")
        csaf_changes_path = os.path.join(self.csaf_dir, "changes.csv")
        self.logger.info("Downloading CSAF files")
        # download and extract the tar bz2 file
        print(f"Downloading {self.__tar_url__}")
        with http.get(self.__tar_url__, self.logger, stream=True, timeout=self.download_timeout) as r, open(csaf_tar_path, "wb") as fh:
            for chunk in r.iter_content(chunk_size=65536):
                fh.write(chunk)

        print(f"Extracting {csaf_tar_path}")
        extract(csaf_tar_path, self.csaf_dir)

        # scrape the main URL for the mod time on the tarball (yes, really)
        # and persist it in the workspace

        # download the changes
        # with (
        #     http.get(self.__csaf_url_template__.format("changes.csv"), self.logger, timeout=self.download_timeout) as r,
        #     open(csaf_changes_path, "wb") as fh,
        # ):
        #     for chunk in r.iter_content(chunk_size=8192):
        #         fh.write(chunk)

        # sort the changes descending by date (second column, newest first)

        # re-download JSONs from the CSV until we hit a date before the mod time on the tarball

    def not_fixed_from_product_id(self, doc: CSAFDoc, pid: str, ns: str) -> FixedIn | None:
        parent = doc.product_tree.parent(pid)
        if not parent:
            return None
        name = pid.removeprefix(parent).removeprefix(":")
        return FixedIn(
            Name=name,
            NamespaceName=ns,
            VersionFormat="rpm",
            Module=None,
            VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
            Version="",
            VulnerableRange=None,
        )

    def fixed_from_product_id(self, doc: CSAFDoc, pid: str, ns: str) -> FixedIn | None:
        # pid is like "SUSE Linux Enterprise Server 12 SP5-LTSS:curl-8.0.1-11.105.1"
        parent = doc.product_tree.parent(pid)
        if not parent:
            return None
        name_dash_version = pid.removeprefix(parent).removeprefix(":")
        # name is like "libcurl-devel-8.0.1-150400.5.62.1"
        # semver_regex = r"(\d+\.\d+\.\d+)"
        # build_id_regex = r"(-(\d+)(\.\d+)*)?"
        # version_match = re.match(r"-(\d+\.\d+\.\d+-\d+(\.\d+)*)", name_dash_version)
        # version = f"0:{version_match.group(1)}" if version_match and version_match.group(1) else ""
        # name = name_dash_version.removesuffix(version_match.group(0)) if version_match else name_dash_version
        if "-" in name_dash_version:
            # There could be dashes in the package name, and between the
            # semver and build info part of the version, so we get to do actual
            # parsing here.
            name = ""
            version = ""
            for part in name_dash_version.split("-"):
                if not version and re.match(r"\d+\.\d+\.\d+", part):
                    version = part  # semver part of the version
                elif version and re.match(r"\d+(\.\d+)*", part):
                    version += f"-{part}"  # build info part of the version
                else:
                    name = f"{name}-{part}" if name else part
        else:
            name = name_dash_version
            version = ""

        return FixedIn(
            Name=name,
            NamespaceName=ns,
            VersionFormat="rpm",
            Module=None,
            VendorAdvisory=VendorAdvisory(NoAdvisory=False, AdvisorySummary=[]),
            Version=version,
            VulnerableRange=None,
        )

    def get_allowed_platforms(self, product_name_pranches: Iterable[Branch]) -> dict[str, str]:
        result = {}
        allowed_sles_flavors = {"sles", "sles-ltss", "sles-ltss-extended-security", "suse_sles_ltss"}
        for branch in product_name_pranches:
            cpe = branch.cpe()
            pid = branch.product_id()
            if cpe and pid:
                # match = re.match(r"cpe:/o:suse:sles([-_]ltss([-_]extended[-_]security)?)?:(?P<major_version>\d+)(:sp(?P<minor_version>\d+))?", cpe)
                # if match:
                #     version = int(match.group("major_version"))
                #     if version in self.allow_versions:
                #         self.logger.debug(f"found CPE {cpe} for {pid} on {branch.name}")
                #         sp = match.group("minor_version")
                #         sp_str = f".{sp}" if sp else ""
                #         result[pid] = f"sles:{version}{sp_str}"
                #     else:
                #         self.logger.debug(f"Skipping {pid} with CPE {cpe}: not in allowed versions {self.allow_versions}")
                # else:
                #     pass
                #     # self.logger.debug(f"Skipping {pid} with CPE {cpe}: not SLES")
                try:
                    cpe_obj = CPE(cpe, CPE.VERSION_2_2)

                    # for some reason, the CPE library returns lists for vendor, product, version, and update
                    vendor = cpe_obj.get_vendor()
                    vendor = vendor[0] if vendor else vendor
                    product = cpe_obj.get_product()
                    product = product[0] if product else product
                    version = cpe_obj.get_version()
                    version = version[0] if version else version
                    update = cpe_obj.get_update()
                    update = update[0] if update else update
                    is_sles = product and product.lower().replace("_", "-") in allowed_sles_flavors
                    allowed_version = version in self.allow_versions
                    if vendor == "suse" and is_sles and allowed_version:
                        self.logger.debug(f"found CPE {cpe} for {pid} on {branch.name}")
                        update_str = f".{update.removeprefix('sp')}" if update else ""
                        result[pid] = f"sles:{version}{update_str}"
                except ValueError:
                    pass
                    # self.logger.debug(f"Skipping {pid} with bad CPE {cpe}")
                except NotImplementedError:
                    pass
                    # self.logger.debug(f"Skipping {pid} with bad CPE {cpe}")

        return result

    def transform_to_vulnerabilities(self, doc: CSAFDoc) -> list[tuple[str, str, Vulnerability]]:
        """transform the CSAF document into a list of vulnerabilities"""

        # SLES data includes many nearly-blanks documents for rejected or disputed CVEs
        # so defend against empty data.
        if not doc.product_tree:
            return []
        if not doc.product_tree.branches:
            return []
        if not doc.vulnerabilities:
            return []

        allowed_prefixes = []
        prefix_to_ns = self.get_allowed_platforms(doc.product_tree.branches[0].product_name_branches())
        allowed_prefixes = [f"{p}:" for p in prefix_to_ns]

        # these files are named like "cve-2022-1234.json" so expect one CVE per file
        vuln = doc.vulnerabilities[0]
        cve_id = vuln.cve
        if not allowed_prefixes:
            self.logger.debug(f"Skipping {cve_id} because no relevant platforms based on allowed versions {self.allow_versions}")
            return []
        description = next((n.text for n in vuln.notes if n.title == "CVE Description"), "")
        sles_severity = doc.document.aggregate_severity.text
        link = next((r.url for r in doc.document.references if r.summary == cve_id), "")
        ns_to_package_vulns = {}
        for affected in vuln.product_status.known_affected:
            prefix = next((p for p in allowed_prefixes if affected.startswith(p)), None)
            self.logger.debug(f"In {cve_id}, checking {affected} with prefix {prefix}")
            if prefix:
                ns = prefix_to_ns[prefix.removesuffix(":")]
                not_fixed = self.not_fixed_from_product_id(doc, affected, ns)
                if not_fixed and ns not in ns_to_package_vulns:
                    ns_to_package_vulns[ns] = Vulnerability(
                        Name=cve_id,
                        NamespaceName=ns,
                        Description=description,
                        Severity=sles_severity,  # TODO: probably need to normalize
                        Link=link,
                        CVSS=[],
                        FixedIn=[],
                    )
                if not_fixed:
                    ns_to_package_vulns[ns].FixedIn.append(not_fixed)

        remediation = next((r for r in vuln.remediations if r.category == "vendor_fix"), None)
        if remediation:
            for pid in remediation.product_ids:
                prefix = next((p for p in allowed_prefixes if pid.startswith(p)), None)
                if prefix:
                    ns = prefix_to_ns[prefix.removesuffix(":")]
                    fixed_in = self.fixed_from_product_id(doc, pid, ns)
                    if fixed_in and ns not in ns_to_package_vulns:
                        ns_to_package_vulns[ns] = Vulnerability(
                            Name=cve_id,
                            NamespaceName=ns,
                            Description=description,
                            Severity=sles_severity,  # TODO: probably need to normalize
                            Link=link,
                            CVSS=[],
                            FixedIn=[],
                        )
                    if fixed_in:
                        ns_to_package_vulns[ns].FixedIn.append(fixed_in)

        return [(ns, cve_id, v) for ns, v in ns_to_package_vulns.items()]

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        # self.download()
        csaf_vex_dir = Path(self.csaf_dir) / "csaf-vex"
        for csaf_file in csaf_vex_dir.glob("*.json"):
            try:
                self.logger.debug(f"Parsing {csaf_file}")
                doc = csaf_from_path(str(csaf_file))
                vulns = self.transform_to_vulnerabilities(doc)
                self.logger.debug(f"Found {len(vulns)} vulnerabilities in {csaf_file}")
                for ns, cve_id, vuln in vulns:
                    yield ns, cve_id, vuln.to_payload()
            except mashumaro.exceptions.InvalidFieldValue as e:
                self.logger.error(f"Failed to parse {csaf_file}: {e}")


if __name__ == "__main__":
    # debug imports

    import orjson
    import subprocess
    from vunnel.utils.csaf_types import Document, AggregateSeverity, Distribution, Note, Publisher, Reference, ProductTree, Vulnerability as CSAFVuln

    def format_json_in_place(file_path: str):
        subprocess.run(f"jq . {file_path} > tmp.json && mv tmp.json {file_path}", shell=True, check=True)

    workspace = Workspace(root=str(Path.cwd() / "data"), name="sles")
    logger = logging.getLogger("sles-csaf-parser")
    logger.setLevel(logging.DEBUG)
    parser = CSAFParser(workspace, ["11", "12", "15"])
    csaf_vex_dir = Path(parser.csaf_dir) / "csaf-vex"
    failed_files = []
    # for csaf_file in csaf_vex_dir.glob("*.json"):
    #     try:
    #         doc = csaf_from_path(str(csaf_file))
    #         for ns, cve_id, vuln in parser.transform_to_vulnerabilities(doc):
    #             print(ns, cve_id, vuln)
    #     except mashumaro.exceptions.InvalidFieldValue as e:
    #         print(f"Failed to parse {csaf_file}: {e}")
    #         # if "REJECTED" not in csaf_file.read_text():
    #         #     failed_files.append(csaf_file)
    #         # else:
    #         #     print(f"Skipping rejected file {csaf_file}")
    # if failed_files:
    #     print("Failed to parse the following files:")
    # for f in failed_files:
    #     print(f"- {f}")
    # data/sles/input/source/csaf/csaf-vex/cve-2018-5134.json
    csaf_path = "/Users/willmurphy/work/vunnel/data/sles/input/source/csaf/csaf-vex/cve-2019-9924.json"
    format_json_in_place(csaf_path)

    doc = csaf_from_path(csaf_path)
    vulns = parser.transform_to_vulnerabilities(doc)
    print(f"Found {len(vulns)} vulnerabilities")
    for ns, cve_id, vuln in vulns:
        for fixed_in in vuln.FixedIn:
            print(ns, cve_id, f"{fixed_in.Name} @ {fixed_in.Version}")
