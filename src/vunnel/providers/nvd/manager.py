from __future__ import annotations

import datetime
import logging
import os
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import orjson
import sqlalchemy as db

from .analysis import Analysis
from .api import NvdAPI
from .cvelist import CVEList
from .normalization import cpes_from_vendor_and_product, parse_cpe_5_version_info

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel.workspace import Workspace


class Manager:
    def __init__(
        self,
        workspace: Workspace,
        logger: logging.Logger | None = None,
        download_timeout: int = 125,
        api_key: str | None = None,
    ) -> None:
        self.workspace = workspace

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        self.api = NvdAPI(api_key=api_key, logger=logger, timeout=download_timeout)
        self.cvelist = CVEList(logger=logger, destination=workspace.input_path, timeout=download_timeout)
        self.analysis = Analysis(destination=workspace.input_path, logger=logger, timeout=download_timeout)
        self.urls = [*self.api.urls(), *self.cvelist.urls(), *self.analysis.urls()]

    def get(
        self,
        db_conn: db.engine.Connection,
        result_table: db.Table,
        last_updated: datetime.datetime | None,
        skip_if_exists: bool = False,
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        # download and persist all CVElist records
        self.cvelist.download()

        # download the latest NVD analysis data
        self.analysis.download()

        # download and process NVD records in realtime (not persisted to the DB)
        # TODO: instead yield from input db
        # if skip_if_exists and self._can_update_incrementally(last_updated):
        #     yield from self._download_updates(last_updated)  # type: ignore  # noqa: PGH003
        # else:
        #     yield from self._download_all()

        # these are the records that are suspect to reprocess.
        cves_reprocessed = set()
        for cve_id, nvd_record in self._nvd_records_to_reprocess(conn=db_conn, result_table=result_table):
            cves_reprocessed.add(cve_id)
            r_id, r = self._reconcile_cve_record(cve_id=cve_id, cve_list_record=self.cvelist.get(cve_id), nvd_record=nvd_record)
            if r:
                yield r_id, r

        # any CVEs that are in CVElist and not NVD should be processed
        for cve_id, cve_list_record in self._unique_cvelist_records_to_process(
            conn=db_conn,
            result_table=result_table,
            skip_cves=cves_reprocessed,
        ):
            r_id, r = self._reconcile_cve_record(cve_id=cve_id, cve_list_record=cve_list_record, nvd_record=None)
            if r:
                yield r_id, r

    def download_nvd_input(self, last_updated: datetime.datetime | None,
                           skip_if_exists: bool = False
                           )-> Generator[tuple[str, dict[str, Any]], Any, None]:
        if skip_if_exists and self._can_update_incrementally(last_updated):
            yield from self._download_updates(last_updated)  # type: ignore  # noqa: PGH003
        else:
            yield from self._download_all()

    def _nvd_records_to_reprocess(
        self,
        conn: db.engine.Connection,
        result_table: db.Table,
    ) -> Generator[tuple[str, str], Any, None]:
        # select id from results where id like "202%" and record like "%Awaiting Analysis%"
        reprocess_rows = result_table.select().where(
            db.and_(
                result_table.c.id.like(b"202%"),
                db.or_(
                    result_table.c.record.like(b"%Awaiting Analysis%"),
                    result_table.c.record.like(b'%"vulnStatus": "Received"%'),
                ),
            ),
        )

        reprocess_items = conn.execute(reprocess_rows).fetchall()

        if len(reprocess_items) > 0:
            self.logger.debug(f"found {len(reprocess_items)} NVD records to reprocess")
        else:
            self.logger.debug("no NVD records to reprocess")

        for row in reprocess_items:
            cve_id = id_to_cve(row.id)
            self.logger.trace(f"reprocessing NVD entry {cve_id!r}")

            yield cve_id, orjson.loads(row.record)["item"]

    def _unique_cvelist_records_to_process(
        self,
        conn: db.engine.Connection,
        result_table: db.Table,
        skip_cves: set[str],
    ) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        # find CVE ids that are in the CVElist but not in the NVD
        cvelist_cves = self.cvelist.cves()

        nvd_cves = set()
        for row in conn.execute(result_table.select()):
            nvd_cves.add(id_to_cve(row.id).lower())

        unique_cvelist_cves = (cvelist_cves - nvd_cves) - skip_cves
        if len(unique_cvelist_cves) > 0:
            self.logger.debug(f"found {len(unique_cvelist_cves)} unique CVEs in the CVElist")
        else:
            self.logger.debug("no unique CVEs in the CVElist")

        for cve_id in unique_cvelist_cves:
            self.logger.trace(f"processing unique CVE list entry {cve_id!r}")
            yield cve_id, self.cvelist.get(cve_id)

    def _can_update_incrementally(self, last_updated: datetime.datetime | None) -> bool:
        if not last_updated:
            return False

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        days_since_last_sync = (now - last_updated).days

        if days_since_last_sync >= NvdAPI.max_date_range_days:
            self.logger.info(
                f"last sync was {days_since_last_sync} days ago (more than {NvdAPI.max_date_range_days} days, the max range value of the NVD API), downloading all data",  # noqa: E501
            )
            return False

        return True

    def _download_all(self) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        self.logger.info("downloading all CVEs")

        # TODO: should we delete all existing state in this case first?

        for response in self.api.cve():
            yield from self._unwrap_records(response)

    def _download_updates(self, last_updated: datetime.datetime) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        self.logger.debug(f"downloading CVEs changed since {last_updated.isoformat()}")

        # get the list of CVEs that have been updated since the last sync
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for idx, response in enumerate(self.api.cve(last_mod_start_date=last_updated, last_mod_end_date=now)):
            if idx == 0:
                total_results = response.get("totalResults", None)
                if total_results:
                    self.logger.debug(f"discovered {total_results} updated CVEs")

            yield from self._unwrap_records(response)

    def _unwrap_records(self, response: dict[str, Any]) -> Generator[tuple[str, dict[str, Any]], Any, None]:
        for vuln in response["vulnerabilities"]:
            cve_id = vuln["cve"]["id"]

            yield self._reconcile_cve_record(
                cve_id,
                self.cvelist.get(cve=cve_id),
                vuln,
            )

    def _reconcile_cve_record(
        self,
        cve_id: str,
        cve_list_record: dict[str, Any],
        nvd_record: dict[str, Any] | None,
    ) -> tuple[str, dict[str, Any]]:
        self.logger.trace(f"Reconciling CVE and NVD records for {cve_id!r}")
        nvd_override = self.analysis.get_nvd_override(cve_id=cve_id)
        if nvd_override:
            configs = nvd_override.get("cve", {}).get("configurations")

            if configs:
                self.logger.debug(f"Overriding NVD record {cve_id!r} with curated CPE configurations")
                nvd_record["cve"]["configurations"] = configs
                return cve_to_id(cve_id), nvd_record

        # TODO: insert magic here...
        # Iterate through affected entries in CVE list record
        # Extract collectionURL, packageName, vendor, and product (defaulting to None if not found)
        # and pass to self.analysis.cpe_lookup.lookup to (hopefully) get a list of CPE patterns.
        # If none are found then attempt to generate some (need to create a function for this)
        # from the attributes that exist.
        # If we fail to generate any CPEs, warn and bail
        # If we do have CPEs, iterate through the CVE5 version and attempt to create a CPE version config
        # Still need a function for that
        cna_node = cve_list_record.get("containers", {}).get("cna", {})

        if not nvd_record or "cve" not in nvd_record:
            nvd_record = {
                "cve": {},
            }

        if "descriptions" not in nvd_record["cve"]:
            descriptions = cna_node.get("descriptions")
            if descriptions:
                nvd_record["cve"]["descriptions"] = descriptions

        # TODO: add published and modified dates if missing
        # TODO: Add references if missing and provided by CVE record
        # TODO: Add CNA CVSS scores (Secondary) if missing and provided by CVE record

        #if nvd_record["cve"].get("configurations"):
        #    return cve_to_id(cve_id), nvd_record

        configs = []
        for affected in cna_node.get("affected", []):
            collection_url = affected.get("collectionURL")
            package_name = affected.get("packageName")
            vendor = affected.get("vendor")
            product = affected.get("product")
            cpes = set()

            for cpe in affected.get("cpes", []):
                if cpe.startswith("cpe:2.3") and len(cpe.split(":")) == 12:
                    cpes.add(cpe)
                    self.logger.trace(f"Using CPES {cpes!r} provided by the CNA on the CVE record for {cve_id!r}")

            lookup_cpes = self.analysis.cpe_lookup.lookup(collection_url=collection_url, package_name=package_name, vendor=vendor, product=product)
            if lookup_cpes:
                self.logger.trace(f"Discovered CPES {lookup_cpes!r} via lookups for {cve_id!r}")
                cpes.update(lookup_cpes)

            if not cpes:
                cpes = cpes_from_vendor_and_product(vendor=vendor, product=product)
                self.logger.trace(f"Generated CPES {cpes!r} from vendor={vendor!r}, product={product!r} for {cve_id!r}")
                if not cpes:
                    # TODO: create some sort of generator if the values aren't all equivalent to empty
                    # for now just bail
                    self.logger.trace(f"No CPEs discovered or generated for affected entry: {affected!r} on {cve_id!r}")
                    continue

            # Possible status values are `affected`, `unaffected`, and `unknown`, should be considered `unknown`
            # if not specified
            default_status = affected.get("defaultStatus", "unknown").lower()
            versions = affected.get("versions", [])
            node = {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [],
            }

            for v in versions:
                status = v.get("status", default_status).lower()
                version, less_than, less_than_or_equal, version_type = parse_cpe_5_version_info(v)

                if version_type == "git":
                    self.logger.debug(f"Skipping git version type for {cve_id!r}")
                    continue

                for cpe in cpes:
                    m = {}
                    m["criteria"] = cpe
                    m["matchCriteriaId"] = str(uuid4()).upper()
                    if less_than and less_than != "*":
                        m["versionEndExcluding"] = less_than
                        if version and version != "*":
                            m["versionStartIncluding"] = version
                    elif less_than_or_equal and less_than_or_equal != "*":
                        m["versionEndIncluding"] = less_than_or_equal
                        if version and version != "*":
                            m["versionStartIncluding"] = version
                    elif version:
                        components = cpe.split(":")
                        components[5] = version
                        m["criteria"] = ":".join(components)
                    else:
                        self.logger.trace(f"no useable version information extracted for affected entry: {affected!r}, version: {v!r} on {cve_id!r}")
                        break

                    if status in {"affected", "unknown"}:
                        m["vulnerable"] = True
                    elif status in {"unaffected"}:
                        m["vulnerable"] = False

                    node["cpeMatch"].append(m)

            if not node["cpeMatch"]:
                continue

            configs.append(
                {
                    "nodes": [node],
                },
            )

        if configs:
            self.logger.debug(f"patching NVD record for {cve_id!r} with CPE configurations: {configs!r}")
            nvd_record["cve"]["configurations"] = configs

        return cve_to_id(cve_id), nvd_record


def cve_to_id(cve: str) -> str:
    year = cve.split("-")[1]
    return os.path.join(year, cve).lower()


def id_to_cve(cve_id: str) -> str:
    return cve_id.split("/")[1]
