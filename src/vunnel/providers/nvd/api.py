from __future__ import annotations

import datetime
import logging
import urllib.parse
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.utils import http

if TYPE_CHECKING:
    from collections.abc import Generator

    import requests


class NvdAPI:
    _cve_api_url_: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _cve_history_api_url_: str = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
    _max_results_per_page_: int = 2000
    max_date_range_days: int = 120

    def __init__(self, api_key: str | None = None, logger: logging.Logger | None = None, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def cve_history(
        self,
        cve_id: str | None = None,
        results_per_page: int
        | None = None,  # from api docs: "it is recommended that users of the CVE API use the default resultsPerPage value"
        change_start_date: str
        | datetime.datetime
        | None = None,  # note: if you specify a changeStartDate, you must also specify a changeEndDate
        change_end_date: str | datetime.datetime | None = None,  # note: maximum date range is 120 days
    ) -> Generator[dict[str, Any], Any, None]:
        parameters = {}

        if cve_id:
            parameters["cveId"] = cve_id

        if results_per_page:
            if results_per_page < 1 or results_per_page > self._max_results_per_page_:
                raise RuntimeError(f"'resultsPerPage' must be > 1 and < {self._max_results_per_page_}")
            parameters["resultsPerPage"] = str(results_per_page)

        if change_start_date:
            parameters["changeStartDate"] = clean_date(change_start_date)

        if change_end_date:
            parameters["changeEndDate"] = clean_date(change_end_date)

        return self._request_all_pages(
            self._cve_history_api_url_,
            parameters,
            message="fetching CVE history",
        )

    def cve(  # noqa: PLR0913
        self,
        cve_id: str | None = None,
        results_per_page: int
        | None = None,  # from api docs: "it is recommended that users of the CVE API use the default resultsPerPage value"
        last_mod_start_date: str | datetime.datetime | None = None,
        last_mod_end_date: str | datetime.datetime | None = None,
        pub_start_date: str
        | datetime.datetime
        | None = None,  # note: if you specify a pubStartDate, you must also specify a pubEndDate
        pub_end_date: str | datetime.datetime | None = None,  # note: maximum date range is 120 days
    ) -> Generator[dict[str, Any], Any, None]:
        parameters = {}

        if cve_id:
            parameters["cveId"] = cve_id

        if results_per_page:
            if results_per_page < 1 or results_per_page > self._max_results_per_page_:
                raise RuntimeError(f"'resultsPerPage' must be > 1 and < {self._max_results_per_page_}")
            parameters["resultsPerPage"] = str(results_per_page)

        if last_mod_start_date:
            parameters["lastModStartDate"] = clean_date(last_mod_start_date)

        if last_mod_end_date:
            parameters["lastModEndDate"] = clean_date(last_mod_end_date)

        if pub_start_date:
            parameters["pubStartDate"] = clean_date(pub_start_date)

        if pub_end_date:
            parameters["pubEndDate"] = clean_date(pub_end_date)

        yield from self._request_all_pages(
            self._cve_api_url_,
            parameters,
            message="fetching CVE results",
        )

    def _request_all_pages(
        self,
        url: str,
        parameters: dict[str, str],
        message: str = "fetching results",
    ) -> Generator[dict[str, Any], Any, None]:
        headers = {
            "content-type": "application/json",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        self.logger.debug(f"{message}")

        response = self._request(url, parameters, headers)

        payload = orjson.loads(response.text)
        if "message" in payload:
            raise RuntimeError(f"API error: {payload['message']}")

        yield payload

        total_results = payload["totalResults"]
        results_per_page = payload["resultsPerPage"]

        if not total_results or not results_per_page:
            return

        pages = total_results // results_per_page
        index = results_per_page

        for page in range(pages):
            self.logger.debug(f"{message} (page {page+2} of {pages})")

            parameters["resultsPerPage"] = str(results_per_page)
            parameters["startIndex"] = str(index)

            response = self._request(self._cve_api_url_, parameters, headers)

            yield orjson.loads(response.text)

            index += results_per_page

    def _request(self, url: str, parameters: dict[str, str], headers: dict[str, str]) -> requests.Response:
        # this is to prevent from encoding the ':' in any timestamps passed
        # (e.g. prevent pubStartDate=2002-01-01T00%3A00%3A00 , want pubStartDate=2002-01-01T00:00:00)
        payload_str = urllib.parse.urlencode(parameters, safe=":")

        # NVD rate-limiting is detailed at https://nvd.nist.gov/developers/start-here and currently resets on a 30 second
        # rolling window, so setting retry to start trying again after 30 seconds.
        response = http.get(url, self.logger, backoff_in_seconds=30, params=payload_str, headers=headers, timeout=self.timeout)
        response.encoding = "utf-8"

        return response


def clean_date(dt: datetime.datetime | str) -> str:
    if isinstance(dt, datetime.datetime):
        return dt.isoformat()
    return datetime.datetime.strptime(dt, "%Y-%m-%d %H:%M").isoformat()  # noqa: DTZ007
