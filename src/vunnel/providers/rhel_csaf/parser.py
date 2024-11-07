import logging
import os
from collections.abc import Generator

from vunnel.providers.rhel_csaf.csaf_document import RHEL_CSAFDocument
from vunnel.utils import http
from vunnel.utils.archive import extract
from vunnel.utils.vulnerability import Vulnerability
from vunnel.workspace import Workspace


VEX_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt"

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
        self.logger.debug("starting of RHEL CSAF parser")

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
                self.logger.debug(f"processing {file_path}")
                r_doc = RHEL_CSAFDocument.from_path(file_path)
                for vuln in r_doc.vulnerabilities():
                    yield vuln.NamespaceName, vuln.Name, vuln

            except Exception as e:
                self.logger.warning(f"failed to process {file_path}: {e}")

    def get(self, skip_if_exists=False) -> Generator[tuple[str, str, dict]]:
        self.fetch()
        for namespace, vuln_id, record in self.process():
            yield namespace, vuln_id, record.to_payload()

