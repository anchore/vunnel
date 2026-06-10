from __future__ import annotations

import abc
import concurrent.futures
import copy
import logging
import os
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import cvss
import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability, osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType


class Parser(abc.ABC):
    """Generic implementation of a feed parser for Chainguard and Wolfi, which both secdb and osv build on"""
    _release_ = "rolling"
    _input_dir_: str = ""
    _security_reference_url_ = "https://images.chainguard.dev/security"

    def __init__(  # noqa: PLR0913
        self,
        workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
        skip_download: bool = False,
        max_workers: int = 64,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.download_timeout = download_timeout
        self.input_dir_path = os.path.join(workspace.input_path, self._input_dir_)
        self.metadata_url = url.strip("/") if url else ""
        self.url = url
        self.namespace = namespace
        self.security_reference_url = (
            security_reference_url.strip("/") if security_reference_url else self._security_reference_url_
        )
        self.skip_download = skip_download
        self.max_workers = max_workers

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    @staticmethod
    def _extract_filename_from_url(url):
        return os.path.basename(urlparse(url).path)

    def build_reference_links(self, vulnerability_id: str) -> list[str]:
        urls = []
        urls.append(f"{self.security_reference_url}/{vulnerability_id}")
        urls.extend(vulnerability.build_reference_links(vulnerability_id))
        return urls

    @abc.abstractmethod
    def _download(self) -> None: ...

    @abc.abstractmethod
    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]: ...

    @abc.abstractmethod
    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]: ...

    @property
    def target_url(self) -> str:
        return self.url

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """
        Download, load and normalize feed data into vulnerability records.

        Output conforms to the vunnel OS vulnerability schema (schema.OSSchema, default v1.1.0):
        https://github.com/anchore/vunnel/blob/main/schema/vulnerability/os/schema-1.1.0.json
        """
        self._download()
        for release, data in self._load():
            yield release, self._normalize(release, data)


class SecDBParser(Parser):
    _input_dir_ = "secdb"

    def __init__(# noqa: PLR0913
        self,
        workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
        skip_download: bool = False,
        max_workers: int = 8,
    ):
        self._db_filename = self._extract_filename_from_url(url)
        super().__init__(
            workspace,
            url,
            namespace,
            fixdater,
            download_timeout,
            logger,
            security_reference_url,
            skip_download=skip_download,
            max_workers=max_workers,
        )

    def _download(self) -> None:
        if self.skip_download:
            self.logger.info(f"skip_download is enabled for {self.namespace} secdb feed")
            return

        if not os.path.exists(self.input_dir_path):
            os.makedirs(self.input_dir_path, exist_ok=True)

        self.fixdater.download()

        try:
            self.logger.info(f"downloading {self.namespace} secdb {self.url}")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = os.path.join(self.input_dir_path, self._db_filename)
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        try:
            with open(f"{self.input_dir_path}/{self._db_filename}") as fh:
                dbtype_data_dict = orjson.loads(fh.read())
                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} sec db data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        """Normalize a wolfi/chainguard secdb document into vunnel OS-schema records.

        Returns a ``{vuln_id: record}`` mapping where each ``record`` conforms to
        the vunnel OS vulnerability schema (schema.OSSchema, default v1.1.0):
        https://github.com/anchore/vunnel/blob/main/schema/vulnerability/os/schema-1.1.0.json

        Example output for a single vulnerability::

            {
                "CVE-2022-30065": {
                    "Vulnerability": {
                        "Name": "CVE-2022-30065",
                        "NamespaceName": "wolfi:rolling",
                        "Link": "https://images.chainguard.dev/security/CVE-2022-30065",
                        "Severity": "Unknown",
                        "Description": "",
                        "Metadata": {},
                        "CVSS": [],
                        "FixedIn": [
                            {
                                "Name": "busybox",
                                "Version": "1.35.0-r3",
                                "VersionFormat": "apk",
                                "NamespaceName": "wolfi:rolling",
                                "Available": {"Date": "2022-05-30", "Kind": "commit"},
                            }
                        ],
                    }
                }
            }

        Args:
            release: Release name, e.g. ``"rolling"``. Used to build ``NamespaceName``.
            data: Parsed secdb document (output of :meth:`_load`).
        """
        vuln_dict: dict[str, Any] = {}

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
                        vuln_dict[vid] = copy.deepcopy(vulnerability.vulnerability_element)
                        vuln_record = vuln_dict[vid]
                        reference_links = self.build_reference_links(vid)

                        vuln_record["Vulnerability"]["Name"] = str(vid)
                        vuln_record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)

                        if reference_links:
                            # TODO: Support multiple links
                            vuln_record["Vulnerability"]["Link"] = reference_links[0]

                        vuln_record["Vulnerability"]["Severity"] = "Unknown"
                    else:
                        vuln_record = vuln_dict[vid]

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
                        # as of today, there isn't any good candidate for a fix date. In the future
                        # we might be able to use the date on the aports commit that added the fix.
                        # candidates=[],
                    )
                    if result:
                        fixed_el["Available"] = {
                            "Date": result.date.isoformat(),
                            "Kind": result.kind,
                        }

                    vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return vuln_dict


class OSVParser(Parser):
    _input_dir_ = "osv"
    _cga_id_re = re.compile(r"^CGA(-[23456789cfghjmpqrvwx]{4}){3}$")

    def _download(self) -> None:
        '''
        Download all OSV entry files based on the index file at self.url, which should point to the
        top level all.json file. For each entry in the index, we construct the URL for the individual
        entry file and download it to the input directory.
        '''
        self.fixdater.download()

        if self.skip_download:
            self.logger.info(f"skip_download is enabled for {self.namespace} osv feed")
            return

        if not os.path.exists(self.input_dir_path):
            os.makedirs(self.input_dir_path, exist_ok=True)

        try:
            self.logger.info(f"downloading {self.namespace} osv index {self.url}")
            # self.url should point to the top level all.json file, e.g.
            # https://packages.cgr.dev/chainguard/v2/osv/all.json
            r = http.get(self.url, self.logger, timeout=self.download_timeout)
            index = orjson.loads(r.content)

            base_url = self.url.rsplit("/", 1)[0]
            # Download all entries in the index concurrently using a thread pool,
            # which should speed up the download process significantly since there are thousands of entries.
            # We construct the URL for each entry by appending the entry ID and .json to the base URL
            # e.g. https://packages.cgr.dev/chainguard/v2/osv/CGA-2255-2h2p-73q2.json
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for entry in index:
                    entry_id = entry["id"]
                    if not entry_id or not self._cga_id_re.match(entry_id):
                        self.logger.warning(f"skipping osv entry with invalid id: {entry_id!r}")
                        continue
                    futures.append(
                        executor.submit(self._download_single_file, f"{base_url}/{entry_id}.json", f"{entry_id}.json"),
                    )
                # surface the first exception (if any) — matches prior behavior where a single
                # failure aborted the batch via the outer try/except
                done, _not_done = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)
                for future in done:
                    future.result()
        except Exception:
            self.logger.exception(f"ignoring error processing osv for {self.url}")

    def _download_single_file(self, url: str, filename: str) -> None:
        '''
        Download a single OSV entry file given its URL and the desired filename.
        '''
        file_path = os.path.join(self.input_dir_path, filename)
        self.logger.info(f"downloading {self.namespace} osv entry {filename}")
        r = http.get(url, self.logger, stream=True, timeout=self.download_timeout)
        with open(file_path, "wb") as fp:
            for chunk in r.iter_content():
                fp.write(chunk)

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        try:
            # for each file we have downloaded, which should be every json file in the index, load it
            # and yield the data for normalization
            for filename in os.listdir(self.input_dir_path):
                if not filename.endswith(".json"):
                    continue
                self.logger.info(f"loading {self.namespace} osv data from {filename}")
                with open(os.path.join(self.input_dir_path, filename)) as fh:
                    data = orjson.loads(fh.read())
                    yield self._release_, data
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} osv data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        """
        Normalize one OSV record to match vunnel requirements. Currently, the OSV schema used 
        by vunnel matches Chainguard, so this is a noop.

        Output conforms to the vunnel OS vulnerability schema (schema.OSVSchema, default v1.7.0):
        https://github.com/anchore/vunnel/blob/main/schema/vulnerability/osv/schema-1.7.0.json

        Input shape reference (Chainguard OSV):
        https://packages.cgr.dev/chainguard/v2/osv/CGA-2255-2h2p-73q2.json
        """
        # we map the osv id to the osv data to keep consistency in the secdb parser, which
        # does this for ease of identifying the associated vulnerability when writing records.
        # IE: {"CGA-1234-5678-9abc": {<full osv record>}}
        osv.patch_fix_date(data, self.fixdater)
        return {data['id']: data}