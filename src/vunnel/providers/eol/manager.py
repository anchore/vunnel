from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging
    from collections.abc import Generator

    from vunnel.workspace import Workspace


from vunnel.utils import http_wrapper as http


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

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        """Get EOL data for all products and cycles."""
        self.logger.info(f"downloading EOL data from {self.url}")

        response = http.get(self.url, self.logger, timeout=self.download_timeout)

        self.urls.append(self.url)

        data = response.json()
        products = data.get("result", [])

        for product in products:
            product_name = product["name"]

            for release in product.get("releases", []):
                cycle_name = release["name"]

                # Pass through API data with product name added
                cycle_data = {
                    "product": product_name,
                    **release,
                    "identifiers": product.get("identifiers", []),
                }

                yield product_name, cycle_name, cycle_data
