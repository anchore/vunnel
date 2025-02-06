import logging
import os
import re
from abc import ABC, abstractmethod

from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.providers.rhel.csaf_parser import CSAFParser
from vunnel.providers.rhel.oval_parser import Parser as OVALParser
from vunnel.utils.oval_parser import Config as OVALConfig
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
    ) -> None:
        self.name: str | None = name
        self.version: str | None = version
        self.platform: str | None = platform
        self.rhsa_id: str | None = rhsa_id
        self.module: str | None = module
        self.package: str | None = package  # the raw "package" field from Hydra JSON API
        self.platform_cpe: str | None = None  # the CPE for the platform, if available

    def as_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "version": self.version,
            "platform": self.platform,
            "rhsa_id": self.rhsa_id,
            "module": self.module,
            "package": self.package,
            "platform_cpe": self.platform_cpe,
        }


class RHSAProvider(ABC):
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
    def get_fixed_version_and_module(self, cve_id: str, ar: AffectedRelease, override_package_name: str | None) -> tuple[str | None, str | None]:
        """
        Retrieve the fixed version and module for a given RHSA ID, platform, and package name.

        :param rhsa_id: The RHSA ID (e.g., "RHSA-2025:1234").
        :param platform: The platform (e.g., "RHEL 8").
        :param package_name: The name of the package (e.g., "httpd").
        :return: A tuple containing the fixed version and module.
        """


class OVALRHSAProvider(RHSAProvider):
    def __init__(self, workspace: Workspace, download_timeout_seconds: int, logger: logging.Logger, rhsa_dir_path: str):
        """
        Initialize the OVALRHSAProvider with a workspace, configuration, and logger.

        :param workspace: The workspace directory.
        :param config: Configuration settings as a dictionary.
        :param logger: Logger instance for logging.
        """
        super().__init__(workspace, download_timeout_seconds, logger)
        if not os.path.exists(rhsa_dir_path):
            self.logger.debug(f"creating workspace for rhsa source data at {rhsa_dir_path}")
            os.makedirs(rhsa_dir_path)

        # initialize config
        oval_parser_config = OVALConfig()

        # regexes
        oval_parser_config.tag_pattern = re.compile(r"\{http://oval.mitre.org/XMLSchema/.*\}(\w*)")
        oval_parser_config.ns_pattern = re.compile(r"(\{http://oval.mitre.org/XMLSchema/.*\})\w*")
        oval_parser_config.is_installed_pattern = re.compile(r"Red Hat Enterprise Linux (\d+).*is installed")
        oval_parser_config.pkg_version_pattern = re.compile(r"(.*) is earlier than (.*)")
        oval_parser_config.pkg_module_pattern = re.compile(r"Module (.*) is enabled")
        oval_parser_config.signed_with_pattern = re.compile(r"(.*) is signed with (.*) key")
        oval_parser_config.platform_version_pattern = re.compile(r"Red Hat Enterprise Linux (\d+)")

        # xpath queries
        oval_parser_config.title_xpath_query = "{0}metadata/{0}title"
        oval_parser_config.severity_xpath_query = "{0}metadata/{0}advisory/{0}severity"
        oval_parser_config.platform_xpath_query = "{0}metadata/{0}affected/{0}platform"
        oval_parser_config.date_issued_xpath_query = "{0}metadata/{0}advisory/{0}issued"
        oval_parser_config.date_updated_xpath_query = "{0}metadata/{0}advisory/{0}updated"
        oval_parser_config.description_xpath_query = "{0}metadata/{0}description"
        oval_parser_config.sa_ref_xpath_query = '{0}metadata/{0}reference[@source="RHSA"]'
        oval_parser_config.cve_xpath_query = "{0}metadata/{0}advisory/{0}cve"
        oval_parser_config.criteria_xpath_query = "{0}criteria"
        oval_parser_config.criterion_xpath_query = ".//{0}criterion"

        # maps
        oval_parser_config.severity_dict = {
            "low": "Low",
            "moderate": "Medium",
            "important": "High",
            "critical": "Critical",
        }

        # string formats
        oval_parser_config.ns_format = "{}"
        self.oval_parser = OVALParser(
            workspace,
            oval_parser_config,
            logger=logging.getLogger("rhel.oval_parser.Parser"),
            download_timeout=self.request_timeout,
        )
        self.logger.debug("parsing RHSA data using RHEL oval parser")
        self.rhsa_dict = self.oval_parser.get()
        self.urls.extend(self.oval_parser.urls)

        if not self.rhsa_dict:
            raise Exception("RHSA data not initialized")

    @classmethod
    def from_rhsa_dict(cls, rhsa_dict) -> "OVALRHSAProvider":  # type: ignore[no-untyped-def]
        """
        Create an OVALRHSAProvider instance from a vulnerability dictionary.

        :return: An OVALRHSAProvider instance.
        """
        instance = cls.__new__(cls)
        instance.rhsa_dict = rhsa_dict
        return instance

    # def get_fixed_version_and_module(self, rhsa_id: str | None, platform: str | None, package_name: str | None) -> tuple[str | None, str | None]:
    def get_fixed_version_and_module(self, cve_id: str, ar: AffectedRelease, override_package_name: str | None) -> tuple[str | None, str | None]:
        """
        Retrieve the fixed version and module for a given RHSA ID, platform, and package name.

        :param package_name: The name of the package (e.g., "httpd").
        :return: A tuple containing the fixed version and module.
        """
        rhsa_id = ar.rhsa_id
        platform = ar.platform
        if self.rhsa_dict is None:
            self.rhsa_dict = self.oval_parser.get()
        _, p = self.rhsa_dict.get((rhsa_id, platform), (None, None))
        package_name = override_package_name or ar.name
        if p:
            fixed_ver, module_name = next(
                ([item["Version"], item.get("Module")] for item in p["Vulnerability"]["FixedIn"] if item["Name"] == package_name),
                [None, None],
            )
            return fixed_ver, module_name
        return None, None


class CSAFRHSAProvider(RHSAProvider):
    def __init__(self, workspace: Workspace, download_timeout_seconds: int, logger: logging.Logger):
        """
        Initialize the CSAFRHSAProvider with a workspace, configuration, and logger.

        :param workspace: The workspace directory.
        :param config: Configuration settings as a dictionary.
        :param logger: Logger instance for logging.
        """
        super().__init__(workspace, download_timeout_seconds, logger)
        self.logger.debug("parsing RHSA data using RHEL csaf parser")
        client = CSAFClient(workspace, logger)
        self.csaf_parser = CSAFParser(
            workspace,
            client,
            download_timeout=download_timeout_seconds,
            logger=logging.getLogger("rhel.csaf_parser.CSAFParser"),
        )
        self.urls.extend(self.csaf_parser.urls)

    def get_fixed_version_and_module(self, cve_id: str, ar: AffectedRelease, override_package_name: str | None) -> tuple[str | None, str | None]:
        """
        Retrieve the fixed version and module for a given RHSA ID, platform, and package name.

        :param cve_id: The CVE being parsed, (e.g., "CVE-2021-1234").
        :param ar: an AffectedRelease object
        :param override_package_name: an override package name (e.g., "httpd") to use instead of ar.name
        :return: A tuple containing the fixed version and module.
        """
        normalized_package_name = override_package_name or ar.name
        return self.csaf_parser.get_fix_info(cve_id, ar.as_dict(), normalized_package_name)
