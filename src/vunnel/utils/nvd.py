# pylint: skip-file

import zlib
from collections import namedtuple

import requests
from anchore_engine.db import session_scope
from anchore_engine.subsys import logger
from anchore_enterprise.db.entities.feeds import DataRecord

CPETuple = namedtuple("CPETuple", ["cpe22_uri", "cpe23_fs", "cpe_obj"])


def get_severity(cve, session=None):
    """
    Looks up the nvdv2 database record for input cve and returns the severity
    """
    if not session:
        with session_scope() as session:
            payload = db_lookup(cve, session)
    else:
        payload = db_lookup(cve, session)

    return _get_payload_severity(payload)


def _get_payload_severity(payload):
    """
    Returns the severity from input nvdv2 payload. If severity is not available, falls back to CVSS v3 and CVSS v2 severity in that order
    """
    severity = None

    if not payload or not isinstance(payload, dict):
        return severity

    severity = payload.get("severity")
    if not severity:
        severity = _get_cvss_v3_severity(payload)
        if not severity:
            severity = _get_cvss_v2_severity(payload)

    return severity


def _get_cvss_v3_severity(payload):
    severity = None

    if not payload or not isinstance(payload, dict):
        return severity

    cvss_v3 = payload.get("cvss_v3")
    if cvss_v3:
        severity = cvss_v3.get("base_metrics", {}).get("base_severity")

    return severity


def _get_cvss_v2_severity(payload):
    severity = None

    if not payload or not isinstance(payload, dict):
        return severity

    cvss_v2 = payload.get("cvss_v2")
    if cvss_v2:
        severity = cvss_v2.get("severity")

    return severity


def db_lookup(cve, session, feed_id="nvdv2", group_id="nvdv2:cves"):
    payload = None
    try:
        nvd_record = (
            session.query(DataRecord)
            .filter(DataRecord.feed_id == feed_id)
            .filter(DataRecord.group_id == group_id)
            .filter(DataRecord.record_id == cve)
            .one_or_none()
        )

        payload = nvd_record.payload if nvd_record else None
    except:
        logger.exception("Database error looking up nvdv2 record for {}".format(cve))

    return payload
