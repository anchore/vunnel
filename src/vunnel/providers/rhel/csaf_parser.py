import logging
import os
from dataclasses import asdict, dataclass

from vunnel.providers.rhel import Config
from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.utils.lazy_dict import LazyDict
from vunnel.utils.vulnerability import CVSS
from vunnel.workspace import Workspace


from collections.abc import Callable
from typing import Generic, TypeVar


@dataclass
class RHSAMetadata:
    issued: str
    updated: str
    ref_id: str
    cve: list[dict[str, str]]

    def to_payload(self):
        return {
            "Issued": self.issued,
            "Updated": self.updated,
            "RefID": self.ref_id,
            "CVE": self.cve,
        }


@dataclass
class RHSARecordVuln:
    name: str
    namespace: str
    severity: str
    description: str
    fixed_in: list[dict[str, str]]
    link: str
    metadata: RHSAMetadata
    cvss: list[CVSS]

    def to_payload(self):
        return {
            "Vulnerability": {
                "Name": self.name,
                "NamespaceName": self.namespace,
                "Description": self.description,
                "Severity": self.severity,
                "Link": self.link,
                "CVSS": [asdict(cvss) for cvss in self.cvss],
                "FixedIn": self.fixed_in,
                "Metadata": self.metadata.to_payload(),
            },
        }


ADVISORIES_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/archive_latest.txt"


class CSAFParser:
    def __init__(self, workspace: Workspace, config: Config, logger=None, download_timeout=125):
        self.config = config
        self.download_timeout = download_timeout
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)

        self.logger = logger
        self.advisory_download_path = os.path.join(self.workspace.input_path, "advisory_archive.tar.zst")
        self.advisories_path = os.path.join(self.workspace.input_path, "advisories")
        self._urls = set()
        self.csaf_client = CSAFClient(self.workspace, ADVISORIES_LATEST_URL, self.logger)

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def parse(self, args: tuple[str, str]) -> tuple[str, dict[str, dict]]:
        name, namespace = args
        csaf = self.csaf_client.csaf_doc_for_rhsa(name)
        raise NotImplementedError("Implement parsing of CSAF doc")

    def get(self) -> dict[(str, str), (str, dict[str, dict])]:
        return LazyDict[tuple[str, str], tuple[str, dict[str, dict]]](compute=self.parse)
