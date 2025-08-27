from __future__ import annotations

import copy
import logging
import os
from urllib.parse import urlparse, urljoin
from typing import TYPE_CHECKING
from vunnel.providers.wolfi.parser import CGParser
from packageurl import PackageURL

import orjson

from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

class OpenVEXParser(CGParser):
    _release_ = "rolling"
    _openvex_dir_ = "openvex"
    _security_reference_url_ = "https://images.chainguard.dev/security"
    _openvex_url_ = "https://packages.cgr.dev/chainguard/vex/all.json"

    def __init__(  # noqa: PLR0913
        self,
        workspace,
        url: str,
        namespace: str,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
    ):
        '''
       :param str url: The url of the openvex all.json file
       :param str namespace:
       :param int download_timeout: 
       :param logging.Logger logger: 
       :type string security_reference_url: location for security information
        '''
        self.download_timeout = download_timeout
        self.namespace = namespace
        # where to store feed files
        self.output_path = os.path.join(workspace.input_path, self._openvex_dir_)
        # openvex feed and security info urls
        self.url = url.strip("/") if url else OpenVEXParser._openvex_url_
        self.security_reference_url = security_reference_url.strip("/") if security_reference_url else OpenVEXParser._security_reference_url_
        # results in stripping `all.json` from feed url
        self._base_url = urljoin(self.url, '.')
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
        urls.extend(vulnerability.build_reference_links(vulnerability_id))
        return urls

    def _download(self, filename: str):
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

    def _load(self) -> Generator[str, dict]:
        """
        Loads all openvex json files and yields them
        :yields:
            str: release name
            dict: [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        """
        for dir, _, files in os.walk(self.output_path):
            for file in files:
                # skip the index file, usually all.json
                if os.path.basename(file) == self._index_filename:
                    continue
                try:
                    path = os.path.join(dir, file)
                    self.logger.info(f"reading {path}")
                    with open(path, 'rb') as f:
                        # yield [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
                        openvex_doc_dict = orjson.loads(f.read())
                        yield self._release_, openvex_doc_dict
                except Exception:
                    self.logger.exception(f"failed to load {self.namespace} openvex data: {path}")
                    raise

    def _normalize(self, _, doc: dict) -> dict[str, dict]:
        """
        Normalize all the openvex entries into an array of openvex statements
        :param release:
        :param data: [openvex document](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        :return: Tuple[str, dict] where dict is an openvex statement
        """
        # ignore invalid docs
        if not 'statements' in doc:
            return {}
        # format as vuln_id -> statement for provider
        return {
            # https://github.com/openvex/spec?tab=readme-ov-file#what-does-an-openvex-document-look-like
            name: self._clean_statements(statement)
            for statement in doc['statements']
            if (name := statement.get('vulnerability', {}).get('name', None))
        }

    def _clean_statements(self, statement: dict) -> dict:
        """
        check if a statement is valid
        :param statement: [openvex statement](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        :return: statement with only chainguard products
        """
        # map package type to chainguard purl fragment
        d = {
            "pypi": "+cgr."
        }
        new_products = []
        for product in statement.get('products', []):
            id = self._get_purl(product)
            if not id:
                self.logger.info(f'skipping invalid product {product}')
                continue
            purl = PackageURL.from_string(id)
            # keep product if valid type and matches chainguard fragment for type
            if purl.type in d and d[purl.type] in id:
                new_products.append(product)
        statement['products'] = new_products
        return statement
    
    @staticmethod
    def _get_purl(product: dict) -> str:
        '''
        Extract purl from product dict
        '''
        if id := product.get('identifiers', {}).get('purl', ''):
            return id
        # TODO: remove @id fallback when all openvex files are fixed
        if id := product.get('@id', ''):
            return id
        return None
    
    @property
    def target_url(self):
        return self.url

    def get(self) -> Generator[str, dict]:
        """
        Download, load and normalize wolfi sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the openvex index data
        self._download(self._index_filename)

        # iterate over index file to load remaining files
        with open(self._get_index_path(), 'r') as f:
            # expected format "entries": [{"filename": "<path>", "modified": "<RFC3339>"}...]
            index_dict = orjson.loads(f.read())
            for entry in index_dict["entries"]:
                # TODO does this handle subpaths? (IE pypi/foo.openvex.json)
                # expected [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
                self._download(entry["file"])

        # load the data
        for release, openvex_doc_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, openvex_doc_dict)
