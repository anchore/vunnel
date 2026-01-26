from __future__ import annotations

import concurrent.futures
import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


namespace = "rootio"


class Parser:
    _api_base_url_ = "https://api.root.io/external/osv"

    def __init__(  # noqa: PLR0913
        self,
        ws: Workspace,
        api_base_url: str | None = None,
        download_timeout: int = 125,
        parallelism: int = 10,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.api_base_url = api_base_url or self._api_base_url_
        self.download_timeout = download_timeout
        self.parallelism = parallelism
        self.urls = [self.api_base_url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _is_valid_osv_id(self, osv_id: str) -> bool:
        """
        Validate OSV ID format.

        Valid IDs should not be empty or end with a trailing dash.
        Examples of invalid IDs: "ROOT-APP-NPM-", "", " "
        """
        if not osv_id or not osv_id.strip():
            return False
        return not osv_id.endswith("-")

    def _fetch_osv_ids(self) -> list[str]:
        """Fetch the list of OSV record IDs from the Root IO API."""
        self.logger.info("fetching list of OSV IDs from Root IO")
        url = f"{self.api_base_url}/all.json"
        response = http.get(url, self.logger, timeout=self.download_timeout)

        # Parse the response - it's an array of objects with "id" and "modified" fields
        id_objects = response.json()

        # Extract and validate ID strings from each object
        all_ids = [obj["id"] for obj in id_objects]
        valid_ids = [osv_id for osv_id in all_ids if self._is_valid_osv_id(osv_id)]

        invalid_count = len(all_ids) - len(valid_ids)
        if invalid_count > 0:
            self.logger.warning(f"skipping {invalid_count} invalid OSV IDs")

        # Save the full response to workspace for debugging/reproducibility
        os.makedirs(self.workspace.input_path, exist_ok=True)
        ids_file = os.path.join(self.workspace.input_path, "osv_ids.json")
        with open(ids_file, "wb") as f:
            f.write(orjson.dumps(id_objects))

        self.logger.info(f"found {len(valid_ids)} valid OSV records")
        return valid_ids

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

        Downloads records concurrently for performance, then processes them sequentially.

        Yields:
            Tuples of (vulnerability_id, schema_version, record_dict)
        """
        # Fetch the list of OSV IDs
        osv_ids = self._fetch_osv_ids()

        # TEMPORARILY DISABLED: Download fixdate information for precise fix dates
        # Note: Requires ghcr.io/anchore/grype-db-observed-fix-date/rootio to exist
        # FIXME: Enable once Anchore creates the fixdate database for rootio
        # self.fixdater.download()

        # Download all OSV records concurrently
        self.logger.info(f"downloading {len(osv_ids)} OSV records with parallelism={self.parallelism}")
        records = {}
        failed_ids = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallelism) as executor:
            # Submit all download tasks
            future_to_id = {executor.submit(self._fetch_osv_record, osv_id): osv_id for osv_id in osv_ids}

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_id):
                osv_id = future_to_id[future]
                try:
                    record = future.result()
                    records[osv_id] = record
                except Exception as e:
                    self.logger.error(f"failed to download OSV record {osv_id}: {e}")
                    failed_ids.append(osv_id)

        if failed_ids:
            self.logger.warning(f"failed to download {len(failed_ids)} records")

        self.logger.info(f"successfully downloaded {len(records)} OSV records")

        # Process downloaded records sequentially
        for osv_id in osv_ids:
            if osv_id not in records:
                continue  # Skip failed downloads

            try:
                vuln_entry = records[osv_id]

                # TEMPORARILY DISABLED: Apply fix date patching to add precise fix dates to ranges
                # FIXME: Enable once Anchore creates the fixdate database for rootio
                # osv.patch_fix_date(vuln_entry, self.fixdater)

                # Normalize and yield the record
                yield self._normalize(vuln_entry)
            except Exception as e:
                self.logger.error(f"failed to process OSV record {osv_id}: {e}")
                continue
