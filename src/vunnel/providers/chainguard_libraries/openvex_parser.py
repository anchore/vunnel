from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import orjson
from packageurl import PackageURL

from vunnel.providers.wolfi.parser import CGParser
from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace


class OpenVEXParser(CGParser):
    _openvex_dir_ = "openvex"
    _security_reference_url_ = "https://images.chainguard.dev/security"

    def __init__(  # noqa: PLR0913
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
    ):
        """
        :param workspace.Workspace workspace: workspace to use for downloads and storage
        :param str url: The url of the openvex all.json file
        :param str namespace:
        :param int download_timeout:
        :param logging.Logger logger:
        :type string security_reference_url: location for security information
        """
        self.download_timeout = download_timeout
        self.namespace = namespace

        # where to store feed files
        self.output_path = os.path.join(workspace.input_path, self._openvex_dir_)

        # openvex feed and security info urls
        if not url:
            raise ValueError("openvex url must be provided")
        self.url = url.strip("/")
        self.security_reference_url = security_reference_url.strip("/") if security_reference_url else OpenVEXParser._security_reference_url_

        # results in stripping `all.json` from feed url
        self._base_url = urljoin(self.url, ".")

        # typically all.json
        self._index_filename = self._extract_filename_from_url(self.url)

        # working dir to avoid relative folder nonsense
        self._cwd = os.getcwd()
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)

    @staticmethod
    def _extract_filename_from_url(url: str) -> str:
        return os.path.basename(urlparse(url).path)

    def _get_index_path(self) -> str:
        return os.path.join(self.output_path, self._index_filename)

    def build_reference_links(self, vulnerability_id: str) -> list[str]:
        urls = [f"{self.security_reference_url}/{vulnerability_id}"]
        additional_links = vulnerability.build_reference_links(vulnerability_id)
        if additional_links:
            urls.extend(additional_links)
        return urls

    def _download(self, filename: str) -> None:
        """
        Downloads chainguard openvex file from <self._base_url> and saves in <self.output_dir>
        :return:
        """
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path, exist_ok=True)
        try:
            uri_path = urljoin(self._base_url, filename)
            filepath = os.path.join(self._cwd, self.output_path, filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.logger.info(f"downloading {self.namespace} openvex {uri_path} to {filepath}")
            r = http.get(uri_path, self.logger, stream=True, timeout=self.download_timeout)
            with open(filepath, "wb+") as f:
                for chunk in r.iter_content():
                    f.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        """
        Loads all openvex json files and yields them
        :yields:
            str: ecosystem name (derived from directory name of the processed file)
            dict: [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        """
        for d, _, files in os.walk(self.output_path):
            for file in files:
                # skip the index file, usually all.json
                if os.path.basename(file) == self._index_filename:
                    continue

                path = os.path.join(d, file)
                dir_name = os.path.basename(d)
                try:
                    self.logger.info(f"reading {path}")
                    with open(path, "rb") as f:
                        # yield [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
                        openvex_doc_dict = orjson.loads(f.read())
                        yield dir_name, openvex_doc_dict
                except Exception:
                    self.logger.exception(f"failed to load {self.namespace} openvex data: {path}")
                    raise

    def _normalize(self, doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """
        Normalize all the openvex entries into an array of openvex statements
        :param release:
        :param data: [openvex document](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        :return: Tuple[str, dict] where dict is an openvex statement
        """
        # ignore invalid docs
        if "statements" not in doc:
            return {}
        # format as vuln_id -> statement for provider
        return {
            # https://github.com/openvex/spec?tab=readme-ov-file#what-does-an-openvex-document-look-like
            name: self._clean_statements(statement)
            for statement in doc["statements"]
            if (name := statement.get("vulnerability", {}).get("name", None))
        }

    def _clean_statements(self, statement: dict[str, Any]) -> dict[str, Any]:
        """
        check if a statement is valid
        :param statement: [openvex statement](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        :return: statement with only chainguard products
        """
        # map package type to chainguard purl fragment
        d = {
            "pypi": "+cgr.",
        }
        new_products = []
        for product in statement.get("products", []):
            pid = self._get_purl(product)
            if not pid:
                self.logger.info(f"skipping invalid product {product}")
                continue
            purl = PackageURL.from_string(pid)
            # keep product if valid type and matches chainguard fragment for type
            if purl.type in d and purl.version and d[purl.type] in purl.version:
                new_products.append(product)
        statement["products"] = new_products
        return statement

    @staticmethod
    def _get_purl(product: dict[str, Any]) -> str | None:
        """
        Extract purl from product dict
        """
        if pid := product.get("identifiers", {}).get("purl", ""):
            return pid
        # TODO: remove @id fallback when all openvex files are fixed
        if pid := product.get("@id", ""):
            return pid
        return None

    @property
    def target_url(self) -> str:
        return self.url

    def get(self) -> Generator[tuple[str, dict[str, dict[str, Any]]], None, None]:
        """
        Download, load and normalize wolfi sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the openvex index data
        self._download(self._index_filename)

        # iterate over index file to load remaining files
        with open(self._get_index_path()) as f:
            # expected format "entries": [{"filename": "<path>", "modified": "<RFC3339>"}...]
            index_dict = orjson.loads(f.read())
            for entry in index_dict["entries"]:
                self._download(entry["id"])

        # load the data
        for ecosystem, openvex_doc_dict in self._load():
            # normalize the loaded data
            yield ecosystem, self._normalize(openvex_doc_dict)
