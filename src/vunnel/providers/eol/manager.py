from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

    from vunnel.workspace import Workspace


import requests


class Manager:
    """Manager for handling EOL data from endoflife.date."""

    def __init__(
        self,
        url: str,
        workspace: Workspace,
        download_timeout: int,
        logger: logging.Logger,
    ):
        self.url = url
        self.workspace = workspace
        self.download_timeout = download_timeout
        self.logger = logger
        self.urls: list[str] = []

    def get(self) -> Generator[tuple[str, str, dict[str, Any]], None, None]:
        """Get EOL data for all products and cycles."""
        self.logger.info(f"downloading EOL data from {self.url}")
        self.urls.append(self.url)

        try:
            response = requests.get(self.url, timeout=self.download_timeout)
            response.raise_for_status()
            data = response.json()
            products = data.get("result", [])
        except requests.RequestException as e:
            self.logger.error(f"failed to download EOL data: {e}")
            return

        for product in products:
            product_name = product["name"]
            self.logger.debug(f"processing product: {product_name}")

            for release in product.get("releases", []):
                cycle_name = release["name"]
                self.logger.debug(f"processing cycle: {cycle_name}")

                # Convert date strings to datetime objects
                cycle_data = {
                    "cycle": cycle_name,
                    "codename": release.get("codename"),
                    "label": release.get("label"),
                    "release_date": release.get("releaseDate"),
                    "is_lts": release.get("isLts", False),
                    "lts_from": release.get("ltsFrom"),
                    "is_eoas": release.get("isEoas", False),
                    "eoas_from": release.get("eoasFrom"),
                    "is_eol": release.get("isEol", False),
                    "eol_from": release.get("eolFrom"),
                    "is_maintained": release.get("isMaintained", False),
                }

                # Convert date strings to datetime objects
                for field in [
                    "release_date",
                    "lts_from",
                    "eoas_from",
                    "eol_from",
                ]:
                    if cycle_data.get(field):
                        try:
                            cycle_data[field] = datetime.fromisoformat(cycle_data[field].replace("Z", "+00:00"))
                        except ValueError:
                            self.logger.warning(
                                f"failed to parse date for {product_name} {cycle_name} {field}: {cycle_data[field]}",
                            )
                            cycle_data[field] = None

                yield product_name, cycle_name, cycle_data
