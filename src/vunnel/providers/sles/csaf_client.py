from __future__ import annotations

import os
import tarfile
from typing import TYPE_CHECKING

from vunnel.utils import http_wrapper as http
from vunnel.utils.csaf_types import CSAFDoc

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

    from vunnel.workspace import Workspace

CSAF_VEX_ARCHIVE_URL = "https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2"


class SLESCSAFClient:
    """Downloads SUSE's CSAF VEX archive and stream-parses it in place.

    SUSE publishes the whole corpus as a single (non-dated, stable-URL) tarball, and
    its own changes.csv is always older than the archive itself (confirmed: the
    archive's Last-Modified trails changes.csv's by ~37 minutes live, and every one of
    changes.csv's 64k rows is already reflected in the archive's own per-doc revision
    history) -- so, unlike RHEL/hummingbird's CSAF clients, there's no changes.csv or
    deletions.csv catch-up dance needed here (deletions.csv doesn't even exist for this
    feed). The archive is downloaded once to the workspace input dir and then read
    directly out of the tarball member-by-member -- no extractall() of ~64k individual
    JSON files to disk.
    """

    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger,
        archive_url: str = CSAF_VEX_ARCHIVE_URL,
        download_timeout: int = 125,
        skip_download: bool = False,
    ):
        self.workspace = workspace
        self.logger = logger
        self.archive_url = archive_url
        self.download_timeout = download_timeout
        self.skip_download = skip_download
        self.archive_path = os.path.join(workspace.input_path, "csaf-vex.tar.bz2")

    def download(self) -> None:
        if self.skip_download:
            self.logger.info("skipping download in SLES CSAF client")
            return

        if not os.path.exists(self.workspace.input_path):
            os.makedirs(self.workspace.input_path)

        self.logger.info(f"downloading {self.archive_url}")
        with (
            http.get(self.archive_url, self.logger, stream=True, timeout=self.download_timeout) as response,
            open(self.archive_path, "wb") as fh,
        ):
            for chunk in response.iter_content(chunk_size=65536):  # 64k chunks
                if chunk:
                    fh.write(chunk)

    def iter_docs(self) -> Generator[tuple[str, CSAFDoc]]:
        """Stream-parse the (already downloaded) archive, yielding (cve_id, doc) per member.

        Non-JSON members (the .asc/.sha256 siblings, directory entries) are skipped.
        A member that fails to parse is logged and skipped rather than aborting the run.
        """
        if not os.path.exists(self.archive_path):
            raise FileNotFoundError(f"CSAF VEX archive not found at {self.archive_path!r}; call download() first")

        with tarfile.open(self.archive_path, mode="r:bz2") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith(".json"):
                    continue

                fh = tar.extractfile(member)
                if fh is None:
                    continue

                cve_id = os.path.splitext(os.path.basename(member.name))[0]
                try:
                    doc = CSAFDoc.from_json(fh.read())
                except Exception:
                    self.logger.warning(f"failed to parse CSAF VEX doc {member.name!r}, skipping")
                    continue

                yield cve_id, doc
