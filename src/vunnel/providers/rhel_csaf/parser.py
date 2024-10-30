import os

from vunnel.utils import http, rpm
from vunnel.workspace import Workspace

namespace = "rhel"

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

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def download(self):
        latest_resp = http.get(url=VEX_LATEST_URL, logger=self.logger)
        archive_filename = latest_resp.content.decode()
        archive_url = VEX_LATEST_URL.replace("archive_latest.txt", archive_filename)
        download_path = os.path.join(self.workspace.input_path, "vex_archive.tar.zst")
        with http.get(archive_url, logger=self.logger, stream=True) as resp, open(download_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):  # 64k chunks
                if chunk:
                    fh.write(chunk)

    def get(self, skip_if_exists=False):
        self.download()
