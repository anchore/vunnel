import concurrent.futures
import contextlib
import csv
import logging
import os
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

from vunnel.providers.rhel_csaf.transformer import vulnerabilities_by_namespace
from vunnel.utils import http
from vunnel.utils.archive import extract
from vunnel.utils.csaf_types import from_path
from vunnel.utils.vulnerability import Vulnerability
from vunnel.workspace import Workspace

VEX_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt"
VEX_CHANGES_URL = "https://security.access.redhat.com/data/csaf/v2/vex/changes.csv"
VEX_DELETIONS_URL = "https://security.access.redhat.com/data/csaf/v2/vex/deletions.csv"
ADVISORIES_LATEST_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/archive_latest.txt"


class Parser:
    def __init__(
        self,
        workspace: Workspace,
        download_timeout: int | None = None,
        skip_namespaces: list[str] | None = None,
        logger: logging.Logger | None = None,
    ):
        self.workspace = workspace
        self.download_timeout = download_timeout if isinstance(download_timeout, int) else 125
        self.skip_namespaces = skip_namespaces if isinstance(skip_namespaces, list) else ["rhel:3", "rhel:4"]
        self.rhsa_dict = None
        self.urls: list[str] = []
        self.vex_archive_date: datetime | None = None

        self.download_path = os.path.join(self.workspace.input_path, "vex_archive.tar.zst")
        self.advisory_download_path = os.path.join(self.workspace.input_path, "advisory_archive.tar.zst")
        self.csaf_path = os.path.join(self.workspace.input_path, "csaf")
        os.makedirs(self.csaf_path, exist_ok=True)
        self.advisories_path = os.path.join(self.workspace.input_path, "advisories")

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.logger.debug("starting of RHEL CSAF parser")

    def get_archive_date(self, archive_filename: str) -> datetime:
        date_part = archive_filename.removeprefix("csaf_vex_").removesuffix(".tar.zst")
        return datetime.strptime(date_part, "%Y-%m-%d").replace(tzinfo=timezone.utc)  # noqa: UP017

    def download_stream(self, url: str, dest: str) -> None:
        with http.get(url, logger=self.logger, stream=True) as resp, open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):  # 64k chunks
                if chunk:
                    fh.write(chunk)

    def download_vex_archive(self) -> None:
        latest_resp = http.get(url=VEX_LATEST_URL, logger=self.logger)
        archive_filename = latest_resp.content.decode()
        self.vex_archive_date = self.get_archive_date(archive_filename)
        archive_url = VEX_LATEST_URL.replace("archive_latest.txt", archive_filename)
        self.urls = [archive_url]
        self.download_stream(archive_url, self.download_path)
        changes_path = os.path.join(self.csaf_path, "changes.csv")
        self.download_stream(VEX_CHANGES_URL, changes_path)
        deletions_path = os.path.join(self.csaf_path, "deletions.csv")
        self.download_stream(VEX_DELETIONS_URL, deletions_path)

    def extract_all(self) -> None:
        os.makedirs(self.csaf_path, exist_ok=True)
        extract(self.download_path, self.csaf_path)

    def process_changes_and_deletions(self) -> None:
        """process the changes and deletions. deletions.csv is the list of CSAF JSON
        files that have been deleted. Download it and loop over it, deleting all
        referenced files. changes.csv is a date-sorted list of when each CSAF JSON
        file changed. Download it, and loop over the rows, until we get back to the
        date of the archive, keeping a list of unique files, to get the set of files
        that have changed since the archive was published. Re-download all of them, over-writing
        whatever data was in the archive."""
        changes_path = os.path.join(self.csaf_path, "changes.csv")
        deletions_path = os.path.join(self.csaf_path, "deletions.csv")
        with open(deletions_path, newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                deleted_fragment = row[0]
                # suppress FileNotFound because deleting the same file twice
                # should no-op rather than raise an error
                with contextlib.suppress(FileNotFoundError):
                    os.remove(os.path.join(self.csaf_path, deleted_fragment))
        seen_files = set()
        with open(changes_path, newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                # row is like "2021/cve-2021-47265.json","2024-11-08T18:28:22+00:00"
                changed_file = row[0]
                date_str = row[1]
                change_date = datetime.fromisoformat(date_str)
                if self.vex_archive_date and change_date < self.vex_archive_date:
                    break
                if changed_file in seen_files:
                    continue
                seen_files.add(changed_file)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(
                    self.download_stream,
                    url=VEX_LATEST_URL.replace("archive_latest.txt", changed_file),
                    dest=os.path.join(self.csaf_path, changed_file),
                ): changed_file
                for changed_file in seen_files
            }
            concurrent.futures.wait(futures.keys())
            for future, changed_file in futures.items():
                if future.exception() is not None:
                    self.logger.warning(f"Failed to download {changed_file}: {future.exception()}")

    def fetch(self) -> None:
        self.download_vex_archive()
        self.extract_all()
        self.process_changes_and_deletions()

    def _csaf_vex_files(self) -> Generator[str]:
        for root, _, files in os.walk(self.csaf_path):
            for file in files:
                if file.endswith(".json"):
                    yield os.path.join(root, file)

    def process(self) -> Generator[tuple[str, str, Vulnerability]]:
        for file_path in self._csaf_vex_files():
            try:
                self.logger.debug(f"processing {file_path}")
                c = from_path(file_path)
                ns_to_vulns = vulnerabilities_by_namespace(c, set(self.skip_namespaces))
                for ns, vuln in ns_to_vulns.items():
                    yield ns, vuln.Name, vuln

            except Exception as e:
                self.logger.warning(f"failed to process {file_path}: {e}")

    def get(self, skip_if_exists: bool = False) -> Generator[tuple[str, str, dict[str, Any]]]:
        self.fetch()
        for namespace, vuln_id, record in self.process():
            yield namespace, vuln_id, record.to_payload()
