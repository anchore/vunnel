import logging
from dataclasses import asdict, dataclass

from vunnel.providers.rhel import Config
from vunnel.utils.vulnerability import CVSS


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


class CSAFParser:
    def __init__(self, workspace, config: Config, logger=None, download_timeout=125):
        self.config = config
        self.download_timeout = download_timeout
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)

        self.logger = logger
        self._urls = set()

    @property
    def urls(self) -> list[str]:
        return list(self._urls)

    def parse(self) -> dict[str, dict]:
        raise NotImplementedError

    def get(self) -> dict[(str, str), (str, dict[str, dict])]:
        # todo: download and extract
        return self.parse()
