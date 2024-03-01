from __future__ import annotations

import datetime
import logging
import os
from typing import TYPE_CHECKING, Any

import orjson
import sqlalchemy as db

from .analysis import Analysis
from .api import NvdAPI
from .cvelist import CVEList

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
        if skip_if_exists and self._can_update_incrementally(last_updated):
            yield from self._download_updates(last_updated)  # type: ignore  # noqa: PGH003
        else:
            yield from self._download_all()

        # these are the records that are suspect to reprocess.
        cves_reprocessed = set()
        for cve_id, nvd_record in self._nvd_records_to_reprocess(conn=db_conn, result_table=result_table):
            cves_reprocessed.add(cve_id)
            yield self._reconsile_cve_record(cve_id=cve_id, cve_list_record=self.cvelist.get(cve_id), nvd_record=nvd_record)

        # any CVEs that are in CVElist and not NVD should be processed
        for cve_id, cve_list_record in self._unique_cvelist_records_to_process(
            conn=db_conn,
            result_table=result_table,
            skip_cves=cves_reprocessed,
        ):
            yield self._reconsile_cve_record(cve_id=cve_id, cve_list_record=cve_list_record, nvd_record=None)

    def _nvd_records_to_reprocess(
        self,
        conn: db.engine.Connection,
        result_table: db.Table,
    ) -> Generator[tuple[str, str], Any, None]:
        # select id from results where id like "202%" and record like "%Awaiting Analysis%"
        reprocess_rows = result_table.select().where(
            db.and_(
                result_table.c.id.like(b"202%"),
                result_table.c.record.like(b"%Awaiting Analysis%"),
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

            yield cve_to_id(cve_id), self._reconsile_cve_record(
                cve_id,
                self.cvelist.get(cve=cve_id),
                vuln,
            )

    def _reconsile_cve_record(
        self,
        cve_id: str,
        cve_list_record: dict[str, Any],
        nvd_record: dict[str, Any] | None,
    ) -> tuple[str, dict[str, Any]]:
        # TODO: insert magic here...

        return cve_to_id(cve_id), nvd_record


def cve_to_id(cve: str) -> str:
    year = cve.split("-")[1]
    return os.path.join(year, cve).lower()


def id_to_cve(cve_id: str) -> str:
    return cve_id.split("/")[1]
