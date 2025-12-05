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

    @staticmethod
    def _parse_apk_version(ver: str) -> tuple[list[int | str], int]:
        """
        Parse APK version into (version_parts, revision).
        E.g., "9.3.2-r2" -> ([9, 3, 2], 2)
        """
        revision = 0
        version_str = ver

        # Extract revision suffix if present (e.g., "-r2")
        if "-r" in ver:
            parts = ver.rsplit("-r", 1)
            version_str = parts[0]
            try:
                revision = int(parts[1])
            except ValueError:
                revision = 0

        # Parse version parts (e.g., "9.3.2" -> [9, 3, 2])
        version_parts: list[int | str] = []
        for part in version_str.replace("-", ".").split("."):
            try:
                version_parts.append(int(part))
            except ValueError:
                version_parts.append(part)

        return version_parts, revision

    @staticmethod
    def _compare_apk_versions(ver_a: str, ver_b: str) -> int:
        """
        Compare APK versions. Returns -1 if ver_a < ver_b, 0 if equal, 1 if ver_a > ver_b.
        APK versions typically follow the pattern: VERSION-rREVISION (e.g., 9.3.2-r2)
        """
        if ver_a == ver_b:
            return 0

        parts_a, rev_a = Parser._parse_apk_version(ver_a)
        parts_b, rev_b = Parser._parse_apk_version(ver_b)

        # Compare version parts
        for i in range(max(len(parts_a), len(parts_b))):
            a_part = parts_a[i] if i < len(parts_a) else 0
            b_part = parts_b[i] if i < len(parts_b) else 0

            # Handle mixed int/str comparison
            if isinstance(a_part, int) and isinstance(b_part, int):
                cmp_result = (a_part > b_part) - (a_part < b_part)
            else:
                # String comparison for non-numeric parts
                a_str, b_str = str(a_part), str(b_part)
                cmp_result = (a_str > b_str) - (a_str < b_str)

            if cmp_result != 0:
                return cmp_result

        # Version parts are equal, compare revisions
        return (rev_a > rev_b) - (rev_a < rev_b)

    @staticmethod
    def _get_base_version_with_r0(ver: str) -> str:
        """
        Get the base version with -r0 suffix.
        E.g., "9.3.2-r2" -> "9.3.2-r0"
        """
        if "-r" in ver:
            base = ver.rsplit("-r", 1)[0]
            return f"{base}-r0"
        return f"{ver}-r0"

    def _sort_secfix_versions(self, secfixes: dict[str, list[str]]) -> list[str]:
        """
        Sort secfixes versions from smallest to largest, excluding special versions like "0".
        """
        from functools import cmp_to_key

        versions = [v for v in secfixes if v not in ("0", "None", None, "")]
        return sorted(versions, key=cmp_to_key(self._compare_apk_versions))

    @staticmethod
    def _extract_vids(raw_vids: list[str] | None) -> list[str]:
        """Extract unique vulnerability IDs from raw secfixes entries."""
        vids: list[str] = []
        if raw_vids:
            for rawvid in raw_vids:
                for newvid in rawvid.split():
                    if newvid not in vids:
                        vids.append(newvid)
        return vids

    def _get_or_create_vuln_record(self, vuln_dict: dict[str, Any], vid: str, release: str) -> dict[str, Any]:
        """Get existing or create new vulnerability record."""
        if vid not in vuln_dict:
            vuln_dict[vid] = copy.deepcopy(vulnerability.vulnerability_element)
            vuln_record = vuln_dict[vid]
            reference_links = self.build_reference_links(vid)

            vuln_record["Vulnerability"]["Name"] = str(vid)
            vuln_record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)
            vuln_record["Vulnerability"]["Severity"] = "Unknown"

            if reference_links:
                vuln_record["Vulnerability"]["Link"] = reference_links[0]
        return vuln_dict[vid]

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize all the sec db entries into vulnerability payload records.
        For each package, versions are sorted smallest to largest to properly assign VulnerableRange.
        """
        vuln_dict: dict[str, Any] = {}
        # Track (vid, pkg) pairs we've seen to know if current version is the smallest
        seen_vid_pkg: set[tuple[str, str]] = set()

        self.logger.debug("normalizing vulnerability data")

        for el in data["packages"]:
            pkg_el = el["pkg"]
            pkg = pkg_el["name"]
            secfixes = pkg_el["secfixes"]

            # Sort versions smallest to largest (excluding special versions like "0")
            sorted_versions = self._sort_secfix_versions(secfixes)
            # Process all versions (sorted first, then special versions like "0")
            all_versions = sorted_versions + [v for v in secfixes if v not in sorted_versions]

            for fix_version in all_versions:
                vids = self._extract_vids(secfixes[fix_version])

                for vid in vids:
                    vuln_record = self._get_or_create_vuln_record(vuln_dict, vid, release)
                    ecosystem = self.namespace + ":" + str(release)

                    fixed_el: dict[str, Any] = {
                        "Name": pkg,
                        "Version": fix_version,
                        "VersionFormat": "apk",
                        "NamespaceName": ecosystem,
                    }

                    # Add VulnerableRange for non-first versions with revision > 0
                    vid_pkg_key = (vid, pkg)
                    is_first = vid_pkg_key not in seen_vid_pkg
                    is_real_version = fix_version not in ("0", "None", None, "")
                    if is_real_version:
                        seen_vid_pkg.add(vid_pkg_key)
                        _, revision = self._parse_apk_version(fix_version)
                        if not is_first and revision > 0:
                            base_r0 = self._get_base_version_with_r0(fix_version)
                            fixed_el["VulnerableRange"] = f">={base_r0}, <{fix_version}"

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
