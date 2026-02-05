from __future__ import annotations

import logging
import os

import orjson
import requests

from vunnel import utils, workspace

# NOTE, CHANGE ME!: this namespace should be unique to your provider and match expectations from
# grype to know what to search for in the DB.
NAMESPACE = "GRYPEOSNAMESPACETHATYOUCHOOSE"


class Parser:
    # NOTE, CHANGE ME!: remove / add / change these attributes as needed to download and parse your provider
    _json_url_ = "https://services.nvd.nist.gov/made-up-location"
    _json_file_ = "vulnerability_data.json"

    def __init__(self, ws: workspace.Workspace, download_timeout: int = 125, logger: logging.Logger | None = None):
        self.workspace = ws
        self.download_timeout = download_timeout
        self.json_file_path = os.path.join(ws.input_path, self._json_file_)

        # NOTE, CHANGE ME!: you should always record any URLs accessed in this list, either
        # statically or dynamically within _download()
        self.urls = [self._json_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self):
        self._download()
        yield from self._normalize()

    @utils.retry_with_backoff()
    def _download(self):
        self.logger.info(f"downloading vulnerability data from {self._json_url_}")

        r = requests.get(self._json_url_, timeout=self.download_timeout)
        r.raise_for_status()

        with open(self.json_file_path, "w", encoding="utf-8") as f:
            f.write(r.text)

    def _normalize(self):

        with open(self.json_file_path, encoding="utf-8") as f:

            for input_record in orjson.loads(f.read()):

                vuln_id = input_record["name"]

                # NOTE: this is in the data shape described by the OS vulnerability schema
                yield vuln_id, {
                    "Vulnerability": {
                        "Name": vuln_id,
                        "NamespaceName": NAMESPACE,
                        "Link": f"https://someplace.com/{vuln_id}",
                        "Severity": input_record["severity"],
                        "Description": input_record["description"],
                        "FixedIn": [
                            {
                                "Name": p,
                                "VersionFormat": "apk",
                                "NamespaceName": NAMESPACE,
                                "Version": input_record["fixed"] or "None",
                            }
                            for p in input_record["packages"]
                        ],
                    },
                }
