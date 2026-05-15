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
        # populated in _fetch_osv_ids() before any per-record fetches start.
        self._osv_dir: str = ""
        self._ids_file: str = ""

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _is_valid_osv_id(self, osv_id: str) -> bool:
        """
        Validate OSV ID format and drop Root IO's synthetic smoke-test records.

        Rejects:
          - empty / whitespace-only IDs
          - IDs ending in a trailing dash (e.g. "ROOT-APP-NPM-")
          - IDs ending in "-CVE-0000-0000" — Root IO publishes one of these
            per supported Ubuntu release as a health-check (currently
            ROOT-OS-UBUNTU-2510-CVE-0000-0000 and
            ROOT-OS-UBUNTU-plucky-CVE-0000-0000). They have no security
            relevance and shouldn't enter the DB.
        """
        if not osv_id or not osv_id.strip():
            return False
        if osv_id.endswith("-"):
            return False
        return not osv_id.endswith("-CVE-0000-0000")

    def _read_cached_modified_map(self) -> dict[str, str]:
        """Return {osv_id: modified} from the previous run's osv_ids.json.

        The vunnel runtime is configured with InputStatePolicy=KEEP for this
        provider (see provider.disallow_existing_input_policy in __init__),
        so the input cache persists across runs. A missing or unreadable
        file is treated as an empty cache — every record will be fetched.
        """
        if not self._ids_file or not os.path.exists(self._ids_file):
            return {}
        try:
            with open(self._ids_file, "rb") as f:
                cached = orjson.loads(f.read())
        except (orjson.JSONDecodeError, OSError) as e:
            self.logger.warning(f"failed to read cached osv_ids.json ({e}); will re-fetch all records")
            return {}
        return {obj["id"]: obj.get("modified", "") for obj in cached if isinstance(obj, dict) and "id" in obj}

    def _fetch_osv_ids(self) -> list[dict[str, str]]:
        """Fetch the {id, modified} listing from the Root IO API and stage workspace dirs."""
        self.logger.info("fetching list of OSV IDs from Root IO")
        url = f"{self.api_base_url}/all.json"
        response = http.get(url, self.logger, timeout=self.download_timeout)

        # Parse the response - it's an array of objects with "id" and "modified" fields
        id_objects = response.json()

        # Filter out malformed entries
        valid_objects = []
        for obj in id_objects:
            if not isinstance(obj, dict):
                continue
            osv_id = obj.get("id", "").strip()
            if not self._is_valid_osv_id(osv_id):
                continue
            obj["id"] = osv_id
            valid_objects.append(obj)

        invalid_count = len(id_objects) - len(valid_objects)
        if invalid_count > 0:
            self.logger.warning(f"skipping {invalid_count} invalid OSV IDs")

        # Prepare workspace dirs once so the concurrent fetchers don't all
        # race on os.makedirs.
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._osv_dir = os.path.join(self.workspace.input_path, "osv")
        os.makedirs(self._osv_dir, exist_ok=True)
        self._ids_file = os.path.join(self.workspace.input_path, "osv_ids.json")

        self.logger.info(f"found {len(valid_objects)} valid OSV records")
        return valid_objects

    def _select_records_to_fetch(
        self,
        listing: list[dict[str, str]],
        cached_modified: dict[str, str],
    ) -> tuple[list[str], list[str]]:
        """Split the listing into IDs that need a fresh HTTP fetch vs IDs whose
        cached copy is still good.

        A record is fetched when:
          - it's new (id not in cached_modified), or
          - its `modified` timestamp has advanced since the cached run, or
          - the on-disk JSON is missing (cache eviction / partial prior run).
        """
        to_fetch: list[str] = []
        to_reuse: list[str] = []
        for obj in listing:
            osv_id = obj["id"]
            current_modified = obj.get("modified", "")
            cached = cached_modified.get(osv_id)
            if cached is None or current_modified != cached:
                to_fetch.append(osv_id)
                continue
            if not os.path.exists(os.path.join(self._osv_dir, f"{osv_id}.json")):
                to_fetch.append(osv_id)
                continue
            to_reuse.append(osv_id)
        return to_fetch, to_reuse

    def _fetch_osv_record(self, osv_id: str) -> dict[str, Any]:
        """Fetch an individual OSV record from the Root IO API."""
        self.logger.debug(f"fetching OSV record: {osv_id}")
        url = f"{self.api_base_url}/{osv_id}.json"
        response = http.get(url, self.logger, timeout=self.download_timeout)

        record = response.json()

        # Save the raw record to workspace for reproducibility. Normalization
        # happens later, so the on-disk copy is the verbatim API response.
        record_file = os.path.join(self._osv_dir, f"{osv_id}.json")
        with open(record_file, "wb") as f:
            f.write(orjson.dumps(record))

        return record

    def _load_cached_record(self, osv_id: str) -> dict[str, Any]:
        """Read a previously-fetched record from the workspace cache."""
        record_file = os.path.join(self._osv_dir, f"{osv_id}.json")
        with open(record_file, "rb") as f:
            return orjson.loads(f.read())

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

        # Map the Root IO-specific "upstream" field to the standard OSV "aliases" field.
        # Root IO's API uses "upstream" to list the upstream CVE IDs that a rootio patch
        # fixes; OSV 1.6.x (and grype-db) only knows "aliases". Without this mapping,
        # grype-db can't link rootio NAK records to their upstream CVE IDs. We also drop
        # the `upstream` key after copying — it isn't part of the OSV 1.6.x schema we
        # declare, and leaving it in trips the schema validator on records that carry
        # both fields (the common case in production data).
        upstream = vuln_entry.pop("upstream", None)
        if upstream and not vuln_entry.get("aliases"):
            vuln_entry["aliases"] = upstream

        # Set database_specific metadata to mark as advisory for grype-db
        # This is critical for grype-db to emit unaffectedPackageHandles for the NAK pattern
        if "database_specific" not in vuln_entry:
            vuln_entry["database_specific"] = {}
        if "anchore" not in vuln_entry["database_specific"]:
            vuln_entry["database_specific"]["anchore"] = {}
        vuln_entry["database_specific"]["anchore"]["record_type"] = "advisory"

        return vuln_id, vuln_schema, vuln_entry

    def _download_records_parallel(
        self,
        to_fetch: list[str],
    ) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Fetch each ID concurrently. Returns (records, failed_ids)."""
        records: dict[str, dict[str, Any]] = {}
        failed_ids: list[str] = []
        if not to_fetch:
            return records, failed_ids
        self.logger.info(f"downloading {len(to_fetch)} OSV records with parallelism={self.parallelism}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallelism) as executor:
            future_to_id = {executor.submit(self._fetch_osv_record, osv_id): osv_id for osv_id in to_fetch}
            for future in concurrent.futures.as_completed(future_to_id):
                osv_id = future_to_id[future]
                try:
                    records[osv_id] = future.result()
                except Exception as e:
                    self.logger.error(f"failed to download OSV record {osv_id}: {e}")
                    failed_ids.append(osv_id)
        return records, failed_ids

    def _load_cached_records(
        self,
        to_reuse: list[str],
    ) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Load each ID from the on-disk cache. On corruption, fall back to a
        fresh fetch for that single record. Returns (records, failed_ids)."""
        records: dict[str, dict[str, Any]] = {}
        failed_ids: list[str] = []
        for osv_id in to_reuse:
            try:
                records[osv_id] = self._load_cached_record(osv_id)
            except (orjson.JSONDecodeError, OSError) as e:
                self.logger.warning(f"cached record for {osv_id} unreadable ({e}); re-fetching")
                try:
                    records[osv_id] = self._fetch_osv_record(osv_id)
                except Exception as fetch_err:
                    self.logger.error(f"failed to re-fetch {osv_id} after cache miss: {fetch_err}")
                    failed_ids.append(osv_id)
        return records, failed_ids

    def _process_record(self, vuln_entry: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        """Stamp fix-date metadata and normalize a single record for yielding.

        Stamping `database_specific.anchore.fixes` lets grype-db's OSV
        transformer (extractFixAvailability) surface the fix-available date
        on the unaffected handle. patch_fix_date marks the advisory
        `published` candidate as accurate=False so consumers know this is a
        fallback estimate.
        """
        osv.patch_fix_date(vuln_entry, self.fixdater)
        return self._normalize(vuln_entry)

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        """
        Yield OSV records from the Root IO API, using a modified-timestamp
        cache so subsequent runs only re-fetch records whose `modified`
        advanced.

        Cold-start runs still fetch every record (~14k); steady-state runs
        on a kept input cache fetch only the records that changed (usually
        a few dozen per day). Per-record downloads run concurrently in a
        thread pool, but records are then iterated in listing order so the
        yield order is deterministic across runs.

        Yields:
            Tuples of (vulnerability_id, schema_version, record_dict)
        """
        listing = self._fetch_osv_ids()
        cached_modified = self._read_cached_modified_map()
        to_fetch, to_reuse = self._select_records_to_fetch(listing, cached_modified)
        self.logger.info(
            f"records: {len(listing)} total, {len(to_fetch)} to fetch, {len(to_reuse)} reused from cache",
        )

        # Download observed-fix-date data (if a remote artifact exists for this
        # provider). Missing artifacts are tolerated — patch_fix_date will fall
        # back to the advisory's `published` date as a low-quality candidate.
        self.fixdater.download()

        fresh_records, fresh_failures = self._download_records_parallel(to_fetch)
        cached_records, cached_failures = self._load_cached_records(to_reuse)
        records = {**fresh_records, **cached_records}
        failed_ids = fresh_failures + cached_failures

        if failed_ids:
            self.logger.warning(f"failed to obtain {len(failed_ids)} records")
        self.logger.info(
            f"loaded {len(records)} OSV records ({len(fresh_records)} from API, {len(cached_records)} from cache)",
        )

        # Persist the new listing only after we've successfully obtained every
        # record we tried to fetch. If a record fetch failed, we leave the
        # cached osv_ids.json untouched so the next run still treats that
        # record as "needs fetch" — otherwise we'd silently drop the failed
        # ID's stale cache entry and never retry it.
        if not failed_ids:
            with open(self._ids_file, "wb") as f:
                f.write(orjson.dumps(listing))

        # Process records in listing order for deterministic yield ordering.
        for obj in listing:
            osv_id = obj["id"]
            if osv_id not in records:
                continue  # Skip failed downloads
            try:
                yield self._process_record(records[osv_id])
            except Exception as e:
                self.logger.error(f"failed to process OSV record {osv_id}: {e}")
                continue
