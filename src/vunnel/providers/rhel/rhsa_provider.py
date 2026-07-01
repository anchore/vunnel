import logging
from abc import ABC, abstractmethod

from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.providers.rhel.csaf_parser import CSAFParser
from vunnel.workspace import Workspace


class AffectedRelease:
    def __init__(  # noqa: PLR0913
        self,
        name: str | None = None,
        version: str | None = None,
        platform: str | None = None,
        rhsa_id: str | None = None,
        module: str | None = None,
        package: str | None = None,
        product_id: str | None = None,
        channels: list[str] | None = None,
    ) -> None:
        self.name: str | None = name
        self.version: str | None = version
        self.platform: str | None = platform
        self.rhsa_id: str | None = rhsa_id
        self.module: str | None = module
        self.package: str | None = package  # the raw "package" field from Hydra JSON API
        self.platform_cpe: str | None = None  # the CPE for the platform, if available
        # The matched CSAF full product id (FPI) that supplied this fix's version. Unlike platform/cpe
        # it encodes the target RHEL minor stream, so it is what lets us tell same-base per-stream
        # fixes apart. Populated during the RHSA lookup; may be None for non-CSAF-sourced versions.
        self.product_id: str | None = product_id
        # The sorted, deduped set of extended-support channel tokens (e.g. ["aus", "eus"]) that this
        # exact build is delivered through. Empty means the build is generally available (shipped via a
        # normal/GA/non-extended channel). Computed across all FPIs for the build during the RHSA lookup.
        self.channels: list[str] = channels or []

    def as_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "version": self.version,
            "platform": self.platform,
            "rhsa_id": self.rhsa_id,
            "module": self.module,
            "package": self.package,
            "platform_cpe": self.platform_cpe,
            "product_id": self.product_id,
        }


class RHSAProvider(ABC):
    """
    RHSAProvider is an abstract class that encapsulates the ability of the RHEL Parser to ask for
    fixed information about a given CVE. The CSAFRHSAProvider encapsulates parsing fixed data and
    module data out of the CSAF Advisory JSON files. (The OVAL-based implementation has been removed;
    CSAF is now the only source of RHSA data.)

    The interface only allows asking for fixed information about one package as affected by one CVE at a time.
    The reason is that the RHEL Hydra Data is used to control which CVEs and packages are reported by Vunnel.

    In other words, the CSAF (and likely the OVAL) data have fix information that should not be included in the
    Grype database, so the main parser filters the Hydra API responses to learn which CVEs and packages are
    relevant to Vunnel, and then asks the RHSAProvider for the fixed information about those specific CVEs and
    packages.

    The primary reason is that the CSAF data as currently published indicates that every package that was rebuilt
    as part of a given RHSA is fixed by that RHSA, even if prior versions were not vulnerable. So for example, if
    a large module is rebuilt due to a security issue in one of its source RPMs, the CSAF data will indicate that
    every package in that module is fixed by the RHSA, even if the security issue only affected one package. This bloats
    the database and leads to false positives (and to indirect matches becoming direct matches incorrectly). Therefore,
    let the Hydra API control which CVEs and packages are reported by Vunnel, and then ask the RHSAProvider for the
    fixed information about those specific CVEs and packages.

    Secondarily, this preserves the contract that already existed between the parts of the OVAL-based RHEL parser
    """

    def __init__(self, workspace: Workspace, download_timeout_seconds: int, logger: logging.Logger):
        """
        Initialize the RHSAProvider with a workspace, configuration, and logger.

        :param workspace: The workspace directory.
        :param config: Configuration settings as a dictionary.
        :param logger: Logger instance for logging.
        """
        self.workspace = workspace
        self.request_timeout = download_timeout_seconds
        self.logger = logger
        self.urls: list[str] = []

    @abstractmethod
    def get_fixed_version_and_module(
        self,
        cve_id: str,
        ar: AffectedRelease,
        override_package_name: str | None,
    ) -> tuple[str | None, str | None, str | None, list[str]]:
        """
        Retrieve the fixed version, module, matched product_id, and channel set for a given RHSA ID, platform, and package name.

        :param rhsa_id: The RHSA ID (e.g., "RHSA-2025:1234").
        :param platform: The platform (e.g., "RHEL 8").
        :param package_name: The name of the package (e.g., "httpd").
        :return: A tuple of (fixed version, module, matched product_id, channels). The product_id encodes the
            target RHEL minor stream and is used to disambiguate same-base per-stream fixes. channels is the
            sorted set of extended-support channel tokens (empty when the build is generally available).
        """


class CSAFRHSAProvider(RHSAProvider):
    """
    CSAFRHSAProvider is an adapter between the main RHEL Parser, and the CSAFParser, which knows how to
    answer questions about CSAF data. It is the only RHSA data source the RHEL parser uses.
    """

    def __init__(
        self,
        workspace: Workspace,
        download_timeout_seconds: int,
        logger: logging.Logger,
        skip_download: bool,
        csaf_max_workers: int,
    ):
        """
        Initialize the CSAFRHSAProvider with a workspace, configuration, and logger.

        :param workspace: The workspace directory.
        :param config: Configuration settings as a dictionary.
        :param logger: Logger instance for logging.
        :param skip_download: Whether to skip downloading data.
        :param csaf_max_workers: Maximum number of workers for CSAF operations.
        """
        super().__init__(workspace, download_timeout_seconds, logger)
        self.logger.debug("parsing RHSA data using RHEL csaf parser")
        client = CSAFClient(workspace, logger, skip_download=skip_download, max_workers=csaf_max_workers)
        self.csaf_parser = CSAFParser(
            workspace,
            client,
            download_timeout=download_timeout_seconds,
            logger=logging.getLogger("rhel.csaf_parser.CSAFParser"),
        )
        self.urls.extend(self.csaf_parser.urls)

    def get_fixed_version_and_module(
        self,
        cve_id: str,
        ar: AffectedRelease,
        override_package_name: str | None,
    ) -> tuple[str | None, str | None, str | None, list[str]]:
        """
        Retrieve the fixed version, module, matched product_id, and channel set for a given RHSA ID, platform, and package name.

        :param cve_id: The CVE being parsed, (e.g., "CVE-2021-1234").
        :param ar: an AffectedRelease object
        :param override_package_name: an override package name (e.g., "httpd") to use instead of ar.name
        :return: A tuple of (fixed version, module, matched product_id, channels).
        """
        normalized_package_name = override_package_name or ar.name

        if not normalized_package_name:
            return None, None, None, []
        return self.csaf_parser.get_fix_info(cve_id, ar.as_dict(), normalized_package_name)
