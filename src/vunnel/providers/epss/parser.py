from __future__ import annotations

import datetime
import gzip

# import json
import logging
import os
from io import BytesIO
from typing import TYPE_CHECKING

import requests

from vunnel import utils, workspace

if TYPE_CHECKING:
    from collections.abc import Generator


NAMESPACE = "epss"


class Parser:
    # _json_url_ = "https://api.first.org/data/v1/epss"
    # _json_file_ = "epss_data.jsonl"
    _csv_url_ = "https://epss.cyentia.com/epss_scores-{}.csv.gz"
    _csv_file_ = "epss_data.csv"

    def __init__(self, ws: workspace.Workspace, download_timeout: int = 125, logger: logging.Logger | None = None):
        self.workspace = ws
        self.download_timeout = download_timeout
        # self.json_file_path = os.path.join(ws.input_path, self._json_file_)
        self.csv_file_path = os.path.join(ws.input_path, self._csv_file_)
        year = datetime.datetime.now(tz=datetime.timezone.utc).year
        month = datetime.datetime.now(tz=datetime.timezone.utc).month
        day = datetime.datetime.now(tz=datetime.timezone.utc).day
        self.datestring = f"{year}-{month:02}-{day:02}"
        self._csv_url_ = self._csv_url_.format(self.datestring)

        # self.urls = [self._json_url_]
        self.urls = [self._csv_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self) -> Generator[tuple[str | None, dict[str, str]], None, None]:
        """
        Download, load and normalize EPSS data
        :return:
        """
        self._download()
        yield from self._normalize()

    @utils.retry_with_backoff()
    def _download(self) -> None:
        self.logger.info(f"downloading vulnerability data from {self._csv_url_}")

        # NOTE: consider backing off to 'try yesterday' if the 'now'
        # CSV doesn't exist (yet), if this is run on day boundries

        # NOTE: consider skipping the whole execution if the 'now' CSV
        # has already been processed soas not to waste time - the EPSS
        # CSV bundle is only updated daily

        r = requests.get(self._csv_url_, timeout=self.download_timeout)
        r.raise_for_status()

        gzbuf = BytesIO(r.content)
        with gzip.GzipFile(fileobj=gzbuf, mode="rb") as GZFH, open(self.csv_file_path, "wb") as FH:
            FH.write(GZFH.read())

    def _normalize(self) -> Generator[tuple[str | None, dict[str, str]], None, None]:
        with open(self.csv_file_path, encoding="utf-8") as FH:
            for csv_line in FH.readlines():
                if not csv_line.startswith("CVE"):
                    continue
                try:
                    # {"cve": "CVE-2024-6775", "epss": "0.000430000", "percentile": "0.092910000", "date": "2024-07-17"}
                    toks = csv_line.split(",")
                    input_record = {
                        "cve": toks[0],
                        "epss": toks[1],
                        "percentile": toks[2],
                        "date": self.datestring,
                    }
                except Exception as err:
                    self.logger.warning(f"couldn't parse CSV line from input - {csv_line}: {err}")
                    input_record = None
                if not input_record:
                    continue
                yield input_record.get("cve"), input_record

    # NOTE: these next two implementations (ending with _json()) are
    # not used, leaving here as alternative method for getting the
    # same data but from the EPSS API as opposed to the simpler csv
    # bundle.  related member variables (json things) would need to be
    # uncommented as well to use this implementation

    # @utils.retry_with_backoff()
    # def _download_api_json(self):
    #    self.logger.info(f"downloading vulnerability data from {self._json_url_}")
    #    total = 1000
    #    limit = 10000
    #    offset = 0
    #    current = 0
    #    r = requests.get(self._json_url_, params={"limit": limit, "offset": offset}, timeout=self.download_timeout)
    #    r.raise_for_status()

    #    with open(self.json_file_path, "w", encoding="utf-8") as f:
    #        done = False
    #        while not done:
    #            for record in r.json().get("data", []):
    #                f.write(json.dumps(record) + "\n")
    #            current = current + limit
    #            total = r.json().get("total", 0)
    #            if current >= total:
    #                done = True
    #            else:
    #                offset = offset + limit
    #                r = requests.get(self._json_url_, params={"limit": limit, "offset": offset}, timeout=self.download_timeout)
    #                r.raise_for_status()

    # def _normalize_api_json(self):
    #    with open(self.json_file_path, encoding="utf-8") as f:
    #        for json_line in f.readlines():
    #            try:
    #                input_record = json.loads(json_line)
    #            except:
    #                logger.warning(f"couldn't parse (json loads) line from input: {json_line}")
    #                input_record = None
    #            if not input_record:
    #                continue
    #            yield input_record.get("cve"), input_record
