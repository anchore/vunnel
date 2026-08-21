"""ENISA EUVD provider manager.

Fetches vulnerability records from the public EUVD search API and normalizes
them into the EUVD vunnel schema. The upstream payload uses locale-formatted
timestamps and `\\n`-delimited string lists for ``aliases`` and ``references``;
this module converts those into ISO-8601 timestamps and proper string arrays
so downstream consumers (e.g. grype) can rely on a stable shape.

The EUVD API (https://euvd.enisa.europa.eu/apidoc) is paginated through
``page`` and ``size`` query parameters and exposes a ``fromUpdatedDate``
filter we use for incremental syncs after the first full fetch.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from collections.abc import Generator
from typing import Any
from urllib.parse import urlencode

from vunnel import workspace
from vunnel.utils import http_wrapper as http

# Public EUVD search endpoint. Documented at https://euvd.enisa.europa.eu/apidoc.
DEFAULT_URL = "https://euvdservices.enisa.europa.eu/api/search"
# Maximum page size accepted by the upstream API at the time of writing.
PAGE_SIZE = 100
# Conservative cap so a misbehaving server can never push us into an infinite
# pagination loop. ENISA published roughly 350k records in May 2026; the cap
# leaves room for several years of growth before it needs to move.
MAX_PAGES = 20000

# Locale-format timestamps used by the upstream API, e.g.
#   "May 4, 2026, 1:00:23 AM"
_UPSTREAM_TS_FORMAT = "%b %d, %Y, %I:%M:%S %p"


class Manager:
    """Download + transform handler for the EUVD provider."""

    def __init__(
        self,
        url: str,
        workspace: workspace.Workspace,
        download_timeout: int = 125,
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES,
        logger: logging.Logger | None = None,
    ):
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.page_size = page_size
        self.max_pages = max_pages
        self._url = url

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @property
    def urls(self) -> list[str]:
        return [self._url]

    def get(self, last_updated: datetime.datetime | None = None) -> Generator[tuple[str, dict[str, Any]], None, None]:
        """Yield ``(EUVD-id, normalized-record)`` tuples.

        When ``last_updated`` is provided, only entries updated on or after
        that timestamp are returned (incremental sync). Otherwise the full
        catalogue is paged through.
        """
        for raw in self._download_all(last_updated):
            normalized = _normalize_record(raw)
            if normalized is None:
                continue
            yield normalized["id"], normalized

    def _download_all(self, last_updated: datetime.datetime | None) -> Generator[dict[str, Any], None, None]:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        params: dict[str, str] = {"size": str(self.page_size)}
        if last_updated is not None:
            params["fromUpdatedDate"] = last_updated.strftime("%Y-%m-%d")

        seen = 0
        for page in range(self.max_pages):
            params["page"] = str(page)
            url = f"{self._url}?{urlencode(params)}"
            response = http.get(url, self.logger, timeout=self.download_timeout)
            payload = response.json()

            items = payload.get("items") or []
            if not items:
                # Empty page means we've drained all matches.
                return

            # Persist each page on disk so the workspace tarball is reproducible.
            page_path = os.path.join(self.workspace.input_path, f"euvd-page-{page:05d}.json")
            with open(page_path, "w") as f:
                json.dump(payload, f)

            for raw in items:
                yield raw
                seen += 1

            # Stop early when we've drained the dataset.
            total = payload.get("total")
            if isinstance(total, int) and seen >= total:
                return

            if len(items) < self.page_size:
                return

        self.logger.warning(
            "stopped EUVD pagination after %d pages of %d items; the dataset may have outgrown MAX_PAGES",
            self.max_pages,
            self.page_size,
        )


def _normalize_record(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one upstream EUVD record into the vunnel EUVD schema.

    Returns ``None`` when the record is missing the mandatory ``id`` /
    ``description`` fields so the caller can skip it cleanly.
    """
    if not isinstance(raw, dict):
        return None
    euvd_id = raw.get("id")
    description = raw.get("description")
    if not euvd_id or not description:
        return None

    return {
        "id": euvd_id,
        "enisaUuid": raw.get("enisaUuid"),
        "description": description,
        "datePublished": _normalize_timestamp(raw.get("datePublished")),
        "dateUpdated": _normalize_timestamp(raw.get("dateUpdated")),
        "baseScore": raw.get("baseScore"),
        "baseScoreVersion": raw.get("baseScoreVersion"),
        "baseScoreVector": raw.get("baseScoreVector"),
        "epss": raw.get("epss"),
        "assigner": raw.get("assigner"),
        "aliases": _split_newline_list(raw.get("aliases")),
        "references": _split_newline_list(raw.get("references")),
        "products": _normalize_products(raw.get("enisaIdProduct"), raw.get("enisaIdVendor")),
    }


def _normalize_timestamp(raw: Any) -> str | None:
    """Convert the upstream locale timestamp to an ISO-8601 string.

    The upstream API serializes dates as ``"May 4, 2026, 1:00:23 AM"``. When
    the format does not match (or the field is missing), ``None`` is returned
    so consumers can rely on a clean ``string | null``.
    """
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.datetime.strptime(raw, _UPSTREAM_TS_FORMAT).replace(tzinfo=datetime.timezone.utc).isoformat()
    except ValueError:
        return None


def _split_newline_list(raw: Any) -> list[str]:
    """Split ``"foo\\nbar\\n"`` style strings into ``["foo", "bar"]``.

    Upstream returns these fields as newline-delimited strings rather than
    JSON arrays. Empty / missing values become an empty list.
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [line.strip() for line in str(raw).splitlines() if line.strip()]


def _normalize_products(
    products: Any,
    vendors: Any,
) -> list[dict[str, str | None]]:
    """Pair ``enisaIdProduct`` and ``enisaIdVendor`` arrays into vendor/product/version triples.

    The upstream payload reports vendors and products as parallel arrays.
    They share the same logical record but different ENISA ids, so we zip
    them by index; any missing slot is filled with ``None`` so consumers
    don't trip over uneven lengths.
    """
    product_list: list[dict[str, Any]] = list(products) if isinstance(products, list) else []
    vendor_list: list[dict[str, Any]] = list(vendors) if isinstance(vendors, list) else []

    pairs: list[dict[str, str | None]] = []
    for idx in range(max(len(product_list), len(vendor_list))):
        product_entry = product_list[idx] if idx < len(product_list) else None
        vendor_entry = vendor_list[idx] if idx < len(vendor_list) else None

        product_name = None
        product_version = None
        if isinstance(product_entry, dict):
            inner = product_entry.get("product") or {}
            if isinstance(inner, dict):
                product_name = inner.get("name")
            product_version = product_entry.get("product_version") or None

        vendor_name = None
        if isinstance(vendor_entry, dict):
            inner = vendor_entry.get("vendor") or {}
            if isinstance(inner, dict):
                vendor_name = inner.get("name")

        pairs.append(
            {
                "vendor": vendor_name,
                "product": product_name,
                "version": product_version,
            },
        )
    return pairs
