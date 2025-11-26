from __future__ import annotations

import copy
import gzip
import hashlib
import logging
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel import workspace


class Parser:
    _release_ = "rolling"
    _secdb_dir_ = "secdb"
    _security_reference_url_ = "https://security.secureos.io"

    def __init__(  # noqa: PLR0913
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else None
        self.url = url
        self.namespace = namespace
        self.security_reference_url = security_reference_url.strip("/") if security_reference_url else Parser._security_reference_url_
        self.urls: list[str] = []
        # Default filename for secdb (same as fixture filename)
        self._db_filename = "secdb.json"

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    @staticmethod
    def _extract_filename_from_url(url: str) -> str:
        return os.path.basename(urlparse(url).path)

    def build_reference_links(self, vulnerability_id: str) -> list[str]:
        urls = []
        if vulnerability_id.startswith("CVE-"):
            urls.append(f"{self.security_reference_url}/{vulnerability_id}")
        links = vulnerability.build_reference_links(vulnerability_id)
        if links:
            urls.extend(links)
        return urls

    def _verify_sha256(self, file_path: str, expected_sha256: str) -> bool:
        """Verify the SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        calculated_hash = sha256_hash.hexdigest()
        return calculated_hash == expected_sha256

    def _download(self) -> None:
        """
        Downloads secureos sec db files
        :return:
        """
        if not os.path.exists(self.secdb_dir_path):
            os.makedirs(self.secdb_dir_path, exist_ok=True)

        self.fixdater.download()

        try:
            # First, fetch the latest.json metadata
            self.logger.info(f"downloading {self.namespace} metadata from {self.url}")
            r = http.get(self.url, self.logger, timeout=self.download_timeout)
            self.urls.append(self.url)

            metadata = orjson.loads(r.content)
            latest_url = metadata.get("latest_url")
            expected_sha256 = metadata.get("sha256")

            if not latest_url or not expected_sha256:
                raise ValueError("latest.json must contain 'latest_url' and 'sha256' fields")

            self.logger.info(f"downloading {self.namespace} secdb from {latest_url}")
            self.urls.append(latest_url)

            # Download the gzipped secdb file
            r = http.get(latest_url, self.logger, stream=True, timeout=self.download_timeout)

            gz_filename = self._extract_filename_from_url(latest_url)
            gz_file_path = os.path.join(self.secdb_dir_path, gz_filename)

            with open(gz_file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)

            # Verify SHA256
            self.logger.info(f"verifying SHA256 hash of {gz_filename}")
            if not self._verify_sha256(gz_file_path, expected_sha256):
                raise ValueError(f"SHA256 verification failed for {gz_filename}")

            self.logger.info("SHA256 verification successful")

            # Extract the gzipped file
            json_filename = gz_filename.replace(".gz", "")
            json_file_path = os.path.join(self.secdb_dir_path, json_filename)

            self.logger.info(f"extracting {gz_filename} to {json_filename}")
            with gzip.open(gz_file_path, "rb") as f_in, open(json_file_path, "wb") as f_out:
                f_out.write(f_in.read())

            # Store the extracted filename for loading
            self._db_filename = json_filename

        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        """
        Loads the secdb json and yields it
        :return:
        """
        try:
            db_file_path = os.path.join(self.secdb_dir_path, self._db_filename)
            self.logger.debug(f"loading secdb data from: {db_file_path}")

            with open(db_file_path, "rb") as fh:
                dbtype_data_dict = orjson.loads(fh.read())
                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} sec db data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param data:
        :return:
        """

        vuln_dict = {}

        self.logger.debug("normalizing vulnerability data")

        for el in data["packages"]:
            pkg_el = el["pkg"]

            pkg = pkg_el["name"]
            for fix_version in pkg_el["secfixes"]:
                vids = []
                if pkg_el["secfixes"][fix_version]:
                    for rawvid in pkg_el["secfixes"][fix_version]:
                        tmp = rawvid.split()
                        for newvid in tmp:
                            if newvid not in vids:
                                vids.append(newvid)

                for vid in vids:
                    if vid not in vuln_dict:
                        # create a new record
                        vuln_dict[vid] = copy.deepcopy(vulnerability.vulnerability_element)
                        vuln_record = vuln_dict[vid]
                        reference_links = self.build_reference_links(vid)

                        # populate the static information about the new vuln record
                        vuln_record["Vulnerability"]["Name"] = str(vid)
                        vuln_record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)

                        if reference_links:
                            vuln_record["Vulnerability"]["Link"] = reference_links[0]

                        vuln_record["Vulnerability"]["Severity"] = "Unknown"
                    else:
                        vuln_record = vuln_dict[vid]

                    # SET UP fixedins
                    ecosystem = self.namespace + ":" + str(release)
                    fixed_el = {
                        "Name": pkg,
                        "Version": fix_version,
                        "VersionFormat": "apk",
                        "NamespaceName": ecosystem,
                    }

                    result = self.fixdater.best(
                        vuln_id=str(vid),
                        cpe_or_package=pkg,
                        fix_version=fix_version,
                        ecosystem=ecosystem,
                    )
                    if result and result.date:
                        fixed_el["Available"] = {
                            "Date": result.date.isoformat(),
                            "Kind": result.kind,
                        }

                    fixed_in = vuln_record["Vulnerability"]["FixedIn"]
                    if isinstance(fixed_in, list):
                        fixed_in.append(fixed_el)

        return vuln_dict

    @property
    def target_url(self) -> str:
        return self.url

    def get(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        """
        Download, load and normalize secureos sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        # load the data
        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
