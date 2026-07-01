from __future__ import annotations

import abc
import copy
import logging
import os
import re
import tarfile
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv, vulnerability

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
    def _load(self) -> Generator[tuple[str, dict[str, Any]]]: ...

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
            raise

    def _load(self) -> Generator[tuple[str, dict[str, Any]]]:
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
    _cga_id_re  = re.compile(r"^CGA(-[23456789cfghjmpqrvwx]{4}){3}$")
    _tar_file   = "chainguard.tar.gz"

    def _download(self) -> None:
        """
        Download the OSV tar.gz archive from self.url and save it to the input directory.
        The archive contains individual OSV JSON files, one per advisory.
        """
        self.fixdater.download()

        if self.skip_download:
            self.logger.info(f"skip_download is enabled for {self.namespace} osv feed")
            return

        if not os.path.exists(self.input_dir_path):
            os.makedirs(self.input_dir_path, exist_ok=True)

        try:
            # download the tar file
            self.logger.info(f"downloading {self.namespace} osv {self.url}")
            self._download_stream(self.url, os.path.join(self.input_dir_path, self._tar_file), self.download_timeout)
        except Exception:
            self.logger.exception(f"ignoring error downloading osv feed for {self.url}")
            raise

    def _download_stream(self, url: str, path: str, timeout: int) -> None:
        with http.get(url, logger=self.logger, stream=True, timeout=timeout) as response, open(path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=65536):  # 64k chunks
                if chunk:
                    fh.write(chunk)

    def _load(self) -> Generator[tuple[str, dict[str, Any]]]:
        self.logger.info(f"load files for {self.namespace} osv feed")
        try:
            with tarfile.open(os.path.join(self.input_dir_path, self._tar_file), mode="r:gz") as tf:
                for member in tf:
                    n = member.name
                    if not n.endswith(".json"):
                        continue
                    if not self._cga_id_re.match(n.removesuffix(".json")):
                        self.logger.warning(f"encountered invalid json file f{n} in osv tar.gz")
                        continue
                    f = tf.extractfile(member)
                    if not f:
                        continue

                    yield self._release_, orjson.loads(f.read())
        except FileNotFoundError as e:
            self.logger.exception(f"failed to open {self.namespace} osv file {e.filename}: {e.strerror}")
            raise
        except tarfile.TarError as e:
            self.logger.exception(f"failed to extract {self.namespace} tar file: {e}")
            raise
        except orjson.JSONDecodeError as e:
            self.logger.exception(f"failed to parse {self.namespace} osv data: {e}")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:
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
        vulnid = data.get("id")
        if vulnid is None:
            self.logger.warning(f"data missing id: {data}")
            return None
        return {vulnid: data}
