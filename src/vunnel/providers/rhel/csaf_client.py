import concurrent.futures
import contextlib
import csv
import logging
import os
from datetime import UTC, datetime

from vunnel.utils import http
from vunnel.utils.archive import extract
from vunnel.utils.csaf_types import CSAFDoc
from vunnel.utils.csaf_types import from_path as csaf_from_path
from vunnel.workspace import Workspace


class RedHatAdvisoryID:
    RH_URL_PREFIX = "https://access.redhat.com/errata/"

    def __init__(self, rhsa: str):
        rhsa = rhsa.upper()
        rhsa = rhsa.removeprefix(__class__.RH_URL_PREFIX)
        if "-" and ":" in rhsa:
            self.year = rhsa.split("-")[0].split(":")[0]
            self.rhsa = rhsa
        else:
            raise ValueError(f"Invalid RHSA ID: {rhsa}, please provide like RHSA-2021:1234")

    def advisory_url(self) -> str:
        return f"{__class__.RH_URL_PREFIX}{self.rhsa}"

    def advisory_year(self) -> str:
        return self.year

    def advisory_id(self) -> str:
        return self.rhsa

    def advisory_kind(self) -> str:
        if self.rhsa.startswith("RHSA"):
            return "security"
        if self.rhsa.startswith("RHBA"):
            return "bugfix"
        if self.rhsa.startswith("RHEA"):
            return "enhancement"
        return "unknown"


class CSAFClient:
    def __init__(self, workspace: Workspace, latest_url: str, logger: logging.Logger):
        self.workspace = workspace
        self.latest_url = latest_url
        self.latest_filename = "archive_latest.txt"
        self.archive_latest_url = None
        self.archive_date = None
        self.logger = logger
        self.csaf_path = os.path.join(self.workspace.input_path, "csaf")

    def _changes_url(self) -> str:
        return self.latest_url.replace(self.latest_filename, "changes.csv")

    def _deletions_url(self) -> str:
        return self.latest_url.replace(self.latest_filename, "deletions.csv")

    def _archive_url(self) -> str:
        if not self.archive_latest_url:
            latest_resp = http.get(self.latest_url, logger=self.logger)
            latest_name = latest_resp.text.strip()
            self.archive_latest_url = self.latest_url.replace(self.latest_filename, latest_name)
            date_part = latest_name.removeprefix("csaf_advisories_").removesuffix(".tar.zst")
            self.archive_date = datetime.strptime(date_part, "%Y-%m-%d").replace(tzinfo=UTC)
        return self.archive_latest_url

    def _local_archive_path(self) -> str:
        return os.path.join(self.workspace.input_path, self.archive_latest_url.split("/")[-1])

    def _local_changes_path(self) -> str:
        return os.path.join(self.workspace.input_path, "changes.csv")

    def _local_deletions_path(self) -> str:
        return os.path.join(self.workspace.input_path, "deletions.csv")

    def _download_stream(self, url: str, path: str):
        with http.get(url, path, logger=self.logger, stream=True) as response, open(path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=65536):  # 64k chunks
                if chunk:
                    fh.write(chunk)

    def process_changes_and_deletions(self) -> None:
        """process the changes and deletions. deletions.csv is the list of CSAF JSON
        files that have been deleted. Download it and loop over it, deleting all
        referenced files. changes.csv is a date-sorted list of when each CSAF JSON
        file changed. Download it, and loop over the rows, until we get back to the
        date of the archive, keeping a list of unique files, to get the set of files
        that have changed since the archive was published. Re-download all of them, over-writing
        whatever data was in the archive."""
        changes_path = self._local_changes_path()
        deletions_path = self._local_deletions_path()
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
                if self.archive_date and change_date < self.archive_date:
                    break
                if changed_file in seen_files:
                    continue
                seen_files.add(changed_file)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(
                    self._download_stream,
                    url=self.latest_url.replace("archive_latest.txt", changed_file),
                    path=os.path.join(self.csaf_path, changed_file),
                ): changed_file
                for changed_file in seen_files
            }
            concurrent.futures.wait(futures.keys())
            for future, changed_file in futures.items():
                if future.exception() is not None:
                    self.logger.warning(f"Failed to download {changed_file}: {future.exception()}")

    def _download_and_update_archive(self):
        archive_path = self._local_archive_path()
        self._download_stream(self._archive_url(), archive_path)
        self._download_stream(self._changes_url(), os.path.join(self.workspace.input_path, "changes.csv"))
        self._download_stream(self._deletions_url(), os.path.join(self.workspace.input_path, "deletions.csv"))
        extract(archive_path, self.csaf_path)
        self.process_changes_and_deletions()

    def year_from_rhsa_id(self, rhsa_id: RedHatAdvisoryID) -> str:
        # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhba-2024_0599.json
        return os.path.join(self.csaf_path, rhsa_id.advisory_year(), rhsa_id.advisory_id().lower().replace(":", "_") + ".json")

    def csaf_doc_for_rhsa(self, rhsa: str) -> CSAFDoc:
        """Get the CSAF document for a given RHSA ID"""
        # TODO: pull through cache instead of big up front download?
        if not os.path.exists(self.csaf_path):
            self._download_and_update_archive()
        return csaf_from_path(self.year_from_rhsa_id(RedHatAdvisoryID(rhsa)))
