from __future__ import annotations

from datetime import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator
    from vunnel.workspace import Workspace

import requests
from urllib.parse import urljoin


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
            products = response.json()
        except requests.RequestException as e:
            self.logger.error(f"failed to download EOL data: {e}")
            return

        for product in products:
            product_name = product["product"]
            self.logger.debug(f"processing product: {product_name}")

            # Get cycles for this product
            cycles_url = urljoin(self.url, f"{product_name}.json")
            self.urls.append(cycles_url)

            try:
                response = requests.get(cycles_url, timeout=self.download_timeout)
                response.raise_for_status()
                cycles = response.json()
            except requests.RequestException as e:
                self.logger.error(f"failed to download cycles for {product_name}: {e}")
                continue

            for cycle in cycles:
                cycle_name = cycle["cycle"]
                self.logger.debug(f"processing cycle: {cycle_name}")

                # Convert date strings to datetime objects
                for field in [
                    "eol",
                    "latest_release_date",
                    "release_date",
                    "support",
                    "discontinued",
                    "extended_support",
                ]:
                    if cycle.get(field):
                        try:
                            cycle[field] = datetime.fromisoformat(cycle[field].replace("Z", "+00:00"))
                        except ValueError:
                            self.logger.warning(
                                f"failed to parse date for {product_name} {cycle_name} {field}: {cycle[field]}",
                            )
                            cycle[field] = None

                yield product_name, cycle_name, cycle
