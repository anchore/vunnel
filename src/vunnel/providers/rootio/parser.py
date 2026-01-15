from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


namespace = "rootio"


class Parser:
    _api_base_url_ = "https://api.root.io/external/osv"

    def __init__(
        self,
        ws: Workspace,
        api_base_url: str | None = None,
        download_timeout: int = 125,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.api_base_url = api_base_url or self._api_base_url_
        self.download_timeout = download_timeout
        self.urls = [self.api_base_url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _fetch_osv_ids(self) -> list[str]:
        """Fetch the list of OSV record IDs from the Root IO API."""
        self.logger.info("fetching list of OSV IDs from Root IO")
        url = f"{self.api_base_url}/all.json"
        response = http.get(url, self.logger, timeout=self.download_timeout)

        # Parse the response - it's an array of objects with "id" and "modified" fields
        id_objects = response.json()

        # Extract just the ID strings from each object
        id_list = [obj["id"] for obj in id_objects]

        # Save the full response to workspace for debugging/reproducibility
        os.makedirs(self.workspace.input_path, exist_ok=True)
        ids_file = os.path.join(self.workspace.input_path, "osv_ids.json")
        with open(ids_file, "wb") as f:
            f.write(orjson.dumps(id_objects))

        self.logger.info(f"found {len(id_list)} OSV records")
        return id_list

    def _fetch_osv_record(self, osv_id: str) -> dict[str, Any]:
        """Fetch an individual OSV record from the Root IO API."""
        self.logger.debug(f"fetching OSV record: {osv_id}")
        url = f"{self.api_base_url}/{osv_id}.json"
        response = http.get(url, self.logger, timeout=self.download_timeout)

        record = response.json()

        # Save the record to workspace for reproducibility
        record_dir = os.path.join(self.workspace.input_path, "osv")
        os.makedirs(record_dir, exist_ok=True)
        record_file = os.path.join(record_dir, f"{osv_id}.json")
        with open(record_file, "wb") as f:
            f.write(orjson.dumps(record))

        return record

    def _normalize(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        """Normalize a vulnerability entry into the expected tuple format."""
        self.logger.trace("normalizing vulnerability data")  # type: ignore[attr-defined]

        # Extract the OSV record as-is (using OSV schema)
        # Transformation to Grype-specific schema happens in grype-db
        vuln_id = vuln_entry["id"]
        vuln_schema = vuln_entry["schema_version"]

        # Transform ecosystem format: Root IO API returns "Root:Alpine:3.18" format,
        # but grype-db expects "Alpine:3.18" (without "Root:" prefix)
        for affected in vuln_entry.get("affected", []):
            package = affected.get("package", {})
            ecosystem = package.get("ecosystem", "")
            if ecosystem.startswith("Root:"):
                package["ecosystem"] = ecosystem[5:]  # Strip "Root:" prefix
                self.logger.debug(f"normalized ecosystem: {ecosystem} -> {package['ecosystem']}")

        # Set database_specific metadata to mark as advisory for grype-db
        # This is critical for grype-db to emit unaffectedPackageHandles for the NAK pattern
        if "database_specific" not in vuln_entry:
            vuln_entry["database_specific"] = {}
        if "anchore" not in vuln_entry["database_specific"]:
            vuln_entry["database_specific"]["anchore"] = {}
        vuln_entry["database_specific"]["anchore"]["record_type"] = "advisory"

        return vuln_id, vuln_schema, vuln_entry

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        """
        Fetch and yield OSV records from Root IO API.

        Yields:
            Tuples of (vulnerability_id, schema_version, record_dict)
        """
        # Fetch the list of OSV IDs
        osv_ids = self._fetch_osv_ids()

        # Download fixdate information if needed
        # TEMPORARILY DISABLED: self.fixdater.download()
        # Fix date patching is optional and requires authentication

        # Fetch and process each OSV record
        for osv_id in osv_ids:
            try:
                vuln_entry = self._fetch_osv_record(osv_id)

                # Apply fix date patching for published/modified dates
                # TEMPORARILY DISABLED: osv.patch_fix_date(vuln_entry, self.fixdater)
                # Fix date patching is optional and requires authentication

                # Normalize and yield the record
                yield self._normalize(vuln_entry)
            except Exception as e:
                self.logger.error(f"failed to process OSV record {osv_id}: {e}")
                continue
