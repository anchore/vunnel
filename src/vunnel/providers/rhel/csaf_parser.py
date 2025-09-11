import logging

from packageurl import PackageURL

from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.utils.csaf_types import CSAFDoc
from vunnel.workspace import Workspace


def is_rpm_module_purl(purl: PackageURL) -> bool:
    # Previously RedHat denoted modules with a custom purl type of rpmmod, but now they use an rpmmod
    # qualifier on an rpm purl type, so we need to be able to handle either variation
    if purl.type == "rpmmod":
        return True

    return bool(isinstance(purl.qualifiers, dict) and purl.qualifiers.get("rpmmod"))


def resolve_module_name_from_purl(purl: PackageURL) -> str:
    if purl.type == "rpmmod":
        # The prior redhat module purl looked like pkg:rpmmod/redhat/ruby@2.5:8090020230627084142:b46abd14
        # and we want ruby:2.5 back from that
        mod_version = purl.version or ""
        if mod_version and ":" in mod_version:
            # module versions often look like "2.7:8080020230427102918:63b34585",
            # but we want something like "2.7", so that "modularity: ruby:2.7" can be
            # written into the grype DB.
            mod_version = mod_version.split(":")[0]
        return f"{purl.name}:{mod_version}"

    # The newer format with an rpmmod qualifier on an rpm purl looks like pkg:rpm/redhat/ruby@2.5?rpmmod=ruby:2.5:8090020230627084142:b46abd14,
    # so we can just take the purl components directly
    return f"{purl.name}:{purl.version}"


class CSAFParser:
    """
    CSAFParser is a class that encapsulates transforming CSAF advisory JSON, which is in a broad format
    and requires significant interpretation to make matching data out of it. The primary interface is
    the get_fix_info method, which takes a CVE ID and a parsed affected release object from the Hydra API, and
    returns fixed version and module information for the given CVE, for the package and platform.
    """

    def __init__(self, workspace: Workspace, client: CSAFClient, logger: logging.Logger | None = None, download_timeout: int = 125):
        self.download_timeout = download_timeout
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)

        self.logger = logger
        self._urls: set[str] = set()
        self.csaf_client: CSAFClient = client

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def platform_module_name_version_from_fpi(self, doc: CSAFDoc, fpi: str) -> tuple[str | None, str | None, str | None, str | None]:
        """
        Given a CSAF document and a full product ID, return the platform, module, name, and version identified
        by the product ID. This essentially de-references a string like
        "AppStream-8.8.0.Z.MAIN.EUS:ruby-2.7.8-139.module+el8.8.0+18745+f1bef313.src.rpm-ruby:2.7"
        Into it's component information: this is a RHEL 8 package, from the ruby:2.7 module, and the package is
        ruby at version 0:2.7.8-139.module+el8.8.0+18745+f1bef313.

        For FPIs without modules, the format is simply:
        "AppStream-9.2.0.Z.EUS:sudo-0:1.9.5p2-9.el9_2.2.x86_64"

        It would be tempting to simply parse this information out of the string full product ID, but this is challenging because
        there are a variable number of :, since : is used to separate both elements of the product ID and elements of the package
        version, for example, and multiple numbers of -, since - is allowed in package names and is used to separate parts of the
        package version. Therefore, rely on relationships encoded in the document structure to parse this.

        The convention is that a full product ID takes the form {platform}:{package}.rpm-{module} where there is
        a module and {platform}:{package} where there is not. The document contains a relationship structure
        that allows unambiguous parsing to extract the package component and obtain the associated PURL.
        """

        # The CSAF document only associates purls with ID segments, but associates fixes with full product IDs.
        # That is, given a string like "{platform}:{package}.rpm-{module}" or "{platform}:{package}" extract the
        # "{package}" part and ask the CSAF Doc for the associated PURL in order to unambiguously parse a name
        # and version from the PURL.

        # extract the platform (parent) from the FPI and then get the package portion
        # modules are now specified at the end after ".rpm-" if present
        module = None
        version = None
        name = None
        plat = doc.product_tree.parent(fpi)
        if not plat:
            return None, None, None, None
        package = fpi.removeprefix(f"{plat}:")
        module_fields = package.split(".rpm-")
        if len(module_fields) > 1:
            module = module_fields[-1]

        purl = doc.product_tree.purl_for_product_id(package)
        if purl:
            parsed_purl = PackageURL.from_string(purl)
            epoch = parsed_purl.qualifiers.get("epoch", "0") if isinstance(parsed_purl.qualifiers, dict) else "0"
            version = f"{epoch}:{parsed_purl.version}"
            name = parsed_purl.name
        else:
            self.logger.trace(f"no purl for {package} from {fpi}")  # type: ignore[attr-defined]

        # The CSAF docuemnt product tree has some branches of type product name, and some of type product version.
        # Product version branches are modules and RPMs, and are identified by PURLs. Prduct name branches are platforms,
        # and are identified by CPEs. Iterate the product name branches to find the CPE for the platform component found.
        platform_product_node = next((p for p in doc.product_tree.branches[0].product_name_branches() if p.product_id() == plat), None)
        platform_cpe = platform_product_node.cpe() if platform_product_node else None
        if not platform_cpe:
            self.logger.trace(f"no platform cpe for {plat} from {fpi}")  # type: ignore[attr-defined]
            # this product cannot be attributed to any vunnel namespace, so drop it.
            return None, None, None, None

        # This is enuogh information to compare to an affected release and decide that
        # the patch is about the same package whose vulnerability is mentioned in the CSAF document.
        return platform_cpe, module, name, version

    # note: this is really taking an ar dict because of a circular import issue. It should be taking an AffectedRelease object.
    def get_fix_info(self, cve_id: str, ar: dict[str, str | None], normalized_pkg_name: str) -> tuple[str | None, str | None]:
        """
        Given a CVE ID, an affected release object, and the normalized name of the affected package,
        interrogate CSAF RHSA data to look for an advisory that tells us what version of the package is
        fixed, and the modularity of the package if any.

        The `ar` dict is expected to have the following
        """
        fix_id = ar.get("rhsa_id")
        if not fix_id:
            # This affected release does not reference an advisory; assume it isn't fixed
            return None, None
        doc = self.csaf_client.csaf_doc_for_rhsa(fix_id)
        if not doc:
            # There was no document available for the referenced RHSA. This is unexpected,
            # but logged in the csaf client.
            return None, None

        # The CSAF spec allows N vulnerabilities per document. Find the first one whose CVE matches
        # the CVE ID we're looking for fix info for.
        vuln = next((v for v in doc.vulnerabilities if v.cve == cve_id), None)
        if not vuln:
            self.logger.trace(f"{cve_id}: {fix_id} CSAF doc does not claim to fix this CVE")  # type: ignore[attr-defined]
            return None, None

        # There are multiple remediations in a CSAF doc, including ones that say things like "no fix available".
        # Choose the "vendor_fix" type remediation that corresponds to the advisory ID mentioned in the affected release.
        remediation = next((r for r in vuln.remediations if r.category == "vendor_fix" and r.url and r.url.endswith(fix_id)), None)
        if not remediation:
            self.logger.trace(f"{cve_id} no remediation obj for {fix_id}")  # type: ignore[attr-defined]
            return None, None

        # assume that one of the products listed as rebuilt due to the advisory indicates the first fixed
        # version of the package.
        candidate_full_product_ids = remediation.product_ids
        ar_plat_cpe = ar.get("platform_cpe")
        if not ar_plat_cpe:
            self.logger.trace(f"{cve_id} no platform cpe for {fix_id}")  # type: ignore[attr-defined]
            return None, None
        self.logger.trace(f"{cve_id} searching {fix_id} based on {ar_plat_cpe} and {normalized_pkg_name}")  # type: ignore[attr-defined]

        return self.best_version_module_from_fpis(doc, fix_id, candidate_full_product_ids, normalized_pkg_name, ar_plat_cpe)

    def best_version_module_from_fpis(
        self,
        doc: CSAFDoc,
        fix_id: str,
        candidate_product_ids: list[str],
        normalized_pkg_name: str,
        ar_plat_cpe: str,
    ) -> tuple[str | None, str | None]:
        """
        Loop over all candidate product IDs, that is, all product IDs that were patched by the RHSA in question,
        and ask the CSAF document for their platform, module, name, and version.
        Return the first version and module for the first product ID whose package name matches the
        normalized package name from Hydra, and whose platform CPE starts with the platform CPE from Hydra.
        """

        backup_module, backup_version = None, None
        for fpi in candidate_product_ids:
            plat, module, name, version = self.platform_module_name_version_from_fpi(doc, fpi)
            # use startswith because we see things like cpe:/a:redhat:enterprise_linux:8 in hydra returns
            # and cpe:/o:redhat:enterprise_linux:8::appstream in CSAF docs.
            if name == normalized_pkg_name and plat and plat.startswith(ar_plat_cpe):
                # The names match and the platforms line up, so this is possibly a match.
                # However, verions like like "0:1.4.7-3.ael7b_1" are "alternative" and we should only return
                # them if we can't find a better match.
                if version and "ael" in version:
                    self.logger.trace(f"found alternative match for {fpi}, {name}, {plat} against {ar_plat_cpe}: {normalized_pkg_name}")  # type: ignore[attr-defined]
                    backup_module, backup_version = module, version
                    continue
                self.logger.trace(f"found match for {fpi}, {name}, {plat} against {ar_plat_cpe}: {normalized_pkg_name}")  # type: ignore[attr-defined]
                return version, module
        if backup_version:
            self.logger.trace(  # type: ignore[attr-defined]
                f"returning alternative match {backup_version} (module: {backup_module}) for {fix_id} against {ar_plat_cpe}: {normalized_pkg_name}",
            )
        return backup_version, backup_module
