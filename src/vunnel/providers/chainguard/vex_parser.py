from __future__ import annotations

import copy
import logging
import os
from urllib.parse import urlparse, urljoin
from typing import TYPE_CHECKING

import orjson

from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator

class VexParser:
    _release_ = "rolling"
    _vex_dir_ = "vex"
    _security_reference_url_ = "https://images.chainguard.dev/security"
    _vex_url_ = "https://packages.cgr.dev/chainguard/vex/all.json"

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
       :param str url: The url of the vex all.json file
       :param str namespace:
       :param int download_timeout: 
       :param logging.Logger logger: 
       :type string security_reference_url: location for security information
        '''
        self.download_timeout = download_timeout
        self.namespace = namespace
        # where to store feed files
        self.output_path = os.path.join(workspace.input_path, self._vex_dir_)
        # various urls
        self.url = url.strip("/") if url else VexParser._vex_url_
        self.security_reference_url = security_reference_url.strip("/") if security_reference_url else VexParser._security_reference_url_
        self._base_url = urljoin(self.url, '..')
        # typically all.json
        self._index_filename = self._extract_filename_from_url(self.url)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

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
        Downloads chainguard vex file from <self._base_url> and saves in <self.output_dir>
        :return:
        """
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path, exist_ok=True)
        try:
            uri_path = urljoin(self._base_url, filename)
            self.logger.info(f"downloading {self.namespace} vex {uri_path}")
            r = http.get(uri_path, self.logger, stream=True, timeout=self.download_timeout)
            filepath = os.path.join(self.output_path, filename)
            with open(filepath, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self) -> Generator[str, dict]:
        """
        Loads all vex json and yields it
        :yields:
            str: release name
            dict: [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
        """
        for root, _, files in os.walk(self.output_path):
            for file in files:
                # skip the index file, usually all.json
                if os.path.basename(file) == self._index_filename:
                    continue
                try:
                    path = os.path.join(self.output_path, os.path.basename(file))
                    with open(path) as fh:
                        # yield [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
                        vex_data_dict = orjson.loads(fh.read())
                        yield self._release_, vex_data_dict
                except Exception:
                    self.logger.exception(f"failed to load {self.namespace} vex data: {path}")
                    raise

    def _normalize(self, _, doc: dict) -> dict[str, dict]:
        """
        Normalize all the vex entries into an array of vex statements
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
            name: statement
            for statement in doc['statements']
            if (name := statement.get("vulnerability", {}).get("name", None))
        }

    def get(self) -> Generator[str, dict]:
        """
        Download, load and normalize wolfi sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the vex index data
        self._download(self._index_filename)

        # iterate over index file to load remaining files
        with open(self._get_index_path()) as f:
            # expected format "entries": [{"filename": "<path>", "modified": "<RFC3339>"}...]
            index_dict = orjson.loads(f.read())
            for entry in index_dict["entries"]:
                # TODO does this handle subpaths? (IE pypi/foo.openvex.json)
                # expected [openvex data](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
                self._download(entry["filename"])

        # load the data
        for release, vex_doc_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, vex_doc_dict)
