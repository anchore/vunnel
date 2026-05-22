from __future__ import annotations

import abc
import copy
import logging
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import cvss
import orjson

from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import vulnerability

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType


class Parser(abc.ABC):
    """Generic implementation of a feed parser for Chainguard and Wolfi, which both secdb and osv build on"""
    _release_ = "rolling"
    _input_dir_: str = ""
    _security_reference_url_ = "https://images.chainguard.dev/security"

    def __init__(  # noqa: PLR0913
        self,
        workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.download_timeout = download_timeout
        self.input_dir_path = os.path.join(workspace.input_path, self._input_dir_)
        self.metadata_url = url.strip("/") if url else ""
        self.url = url
        self.namespace = namespace
        self.security_reference_url = (
            security_reference_url.strip("/") if security_reference_url else self._security_reference_url_
        )

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    @staticmethod
    def _extract_filename_from_url(url):
        return os.path.basename(urlparse(url).path)

    def build_reference_links(self, vulnerability_id: str) -> list[str]:
        urls = []
        urls.append(f"{self.security_reference_url}/{vulnerability_id}")
        urls.extend(vulnerability.build_reference_links(vulnerability_id))
        return urls

    @abc.abstractmethod
    def _download(self) -> None: ...

    @abc.abstractmethod
    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]: ...

    @abc.abstractmethod
    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]: ...

    @property
    def target_url(self) -> str:
        return self.url

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """
        Download, load and normalize feed data into vulnerability records.

        Output conforms to the vunnel OS vulnerability schema (schema.OSSchema, default v1.1.0):
        https://github.com/anchore/vunnel/blob/main/schema/vulnerability/os/schema-1.1.0.json
        """
        self._download()
        for release, data in self._load():
            yield release, self._normalize(release, data)


class SecDBParser(Parser):
    _input_dir_ = "secdb"

    def __init__(# noqa: PLR0913
        self,
        workspace,
        url: str,
        namespace: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        security_reference_url: str | None = None,
    ):
        self._db_filename = self._extract_filename_from_url(url)
        super().__init__(workspace, url, namespace, fixdater, download_timeout, logger, security_reference_url)

    def _download(self) -> None:
        if not os.path.exists(self.input_dir_path):
            os.makedirs(self.input_dir_path, exist_ok=True)

        self.fixdater.download()

        try:
            self.logger.info(f"downloading {self.namespace} secdb {self.url}")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = os.path.join(self.input_dir_path, self._db_filename)
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        try:
            with open(f"{self.input_dir_path}/{self._db_filename}") as fh:
                dbtype_data_dict = orjson.loads(fh.read())
                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} sec db data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        vuln_dict: dict[str, Any] = {}

        self.logger.debug("normalizing vulnerability data")

        for el in data["packages"]:
            pkg_el = el["pkg"]

            pkg = pkg_el["name"]
            for fix_version in pkg_el["secfixes"]:
                vids = []
                if pkg_el["secfixes"][fix_version]:
                    for rawvid in pkg_el["secfixes"][fix_version]:
                        tmp = rawvid.split()
                        for newvid in tmp:
                            if newvid not in vids:
                                vids.append(newvid)

                for vid in vids:
                    if vid not in vuln_dict:
                        vuln_dict[vid] = copy.deepcopy(vulnerability.vulnerability_element)
                        vuln_record = vuln_dict[vid]
                        reference_links = self.build_reference_links(vid)

                        vuln_record["Vulnerability"]["Name"] = str(vid)
                        vuln_record["Vulnerability"]["NamespaceName"] = self.namespace + ":" + str(release)

                        if reference_links:
                            # TODO: Support multiple links
                            vuln_record["Vulnerability"]["Link"] = reference_links[0]

                        vuln_record["Vulnerability"]["Severity"] = "Unknown"
                    else:
                        vuln_record = vuln_dict[vid]

                    ecosystem = self.namespace + ":" + str(release)
                    fixed_el = {
                        "Name": pkg,
                        "Version": fix_version,
                        "VersionFormat": "apk",
                        "NamespaceName": ecosystem,
                    }

                    result = self.fixdater.best(
                        vuln_id=str(vid),
                        cpe_or_package=pkg,
                        fix_version=fix_version,
                        ecosystem=ecosystem,
                        # as of today, there isn't any good candidate for a fix date. In the future
                        # we might be able to use the date on the aports commit that added the fix.
                        # candidates=[],
                    )
                    if result:
                        fixed_el["Available"] = {
                            "Date": result.date.isoformat(),
                            "Kind": result.kind,
                        }

                    vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

        return vuln_dict


class OSVParser(Parser):
    _input_dir_ = "osv"

    def _download(self) -> None:
        if not os.path.exists(self.input_dir_path):
            os.makedirs(self.input_dir_path, exist_ok=True)
        
        self.fixdater.download()

        try:
            self.logger.info(f"downloading {self.namespace} osv index {self.url}")
            # self.url should point to the top level all.json file, e.g.
            # https://packages.cgr.dev/chainguard/v2/osv/all.json
            r = http.get(self.url, self.logger, timeout=self.download_timeout)
            index = orjson.loads(r.content)

            base_url = self.url.rsplit("/", 1)[0]
            for entry in index:
                # for each entry pointed to by the index, pull down the full JSON file
                filename = f"{entry['id']}.json"
                entry_url = f"{base_url}/{filename}"
                r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
                file_path = os.path.join(self.input_dir_path, filename)
                with open(file_path, "wb") as fp:
                    for chunk in r.iter_content():
                        fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing osv for {self.url}")

    def _load(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        try:
            # for each file we have downloaded, which should be every json file in the index, load it
            # and yield the data for normalization
            for filename in os.listdir(self.input_dir_path):
                if not filename.endswith(".json"):
                    continue
                with open(os.path.join(self.input_dir_path, filename)) as fh:
                    data = orjson.loads(fh.read())
                    yield self._release_, data
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} osv data")
            raise

    def _normalize(self, release: str, data: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        """
        Normalize one OSV record into a single-entry {vuln_id: payload} dict.

        Output conforms to the vunnel OS vulnerability schema (schema.OSSchema, default v1.1.0):
        https://github.com/anchore/vunnel/blob/main/schema/vulnerability/os/schema-1.1.0.json

        Input shape reference (Chainguard OSV):
        https://packages.cgr.dev/chainguard/v2/osv/CGA-2255-2h2p-73q2.json
        """
        vid = data["id"]
        ecosystem = f"{self.namespace}:{release}"
        cvss_scores = [
            _parse_cvss(entry["score"])
            for entry in data["severity"]
        ]

        return {
            "Vulnerability": {
                "CVSS": cvss_scores,
                "Description": "",
                "FixedIn": [
                    {
                        "Name": affected["package"]["name"],
                        "NamespaceName": ecosystem,
                        "VendorAdvisory": {
                            "NoAdvisory": False,
                            "AdvisorySummary": [
                                {
                                    # TODO should we only include fixed events
                                    "ID": component["advisory_id"],
                                    "Link": f"{self.security_reference_url}/{component['advisory_id']}",
                                    # TODO can we use the rest of these fields
                                    "Architecture": component["architecture"],
                                    "ComponentName": component["component_name"],
                                    "ComponentVersion": component["component_version"],
                                    "ComponentType": component["component_type"],
                                    "ComponentLocation": component["component_location"],
                                    "ComponentPurl": component["component_purl"],
                                    "LatestEventStatus": component["latest_event_status"],
                                    "LatestEventTimestamp": component["latest_event_timestamp"],
                                }
                                for component in affected["ecosystem_specific"]["components"]
                            ]
                        },
                        "Version": _version_from_ranges(affected["ranges"]),
                        "VersionFormat": "apk",
                        # TODO should we try to pull timestamp from components
                        # "Availability": {
                        #     "Date": ,
                        #     "Kind": "advisory",
                        # },
                        "VulnerableRange": _vulnerable_range(affected["ranges"]),
                        "Module": None,
                    }
                    for affected in data["affected"]
                ],
                "Link": f"https://images.chainguard.dev/security/{vid}",
                "Metadata": {
                    "Issued": data["published"],
                    "Updated": data["modified"],
                    "Withdrawn": None,
                    "RefId": None, # TODO what is this
                    "CVE": [
                        {"Name": parent}
                        for parent in data["upstream"]
                    ]
                },
                "Name": vid,
                "NamespaceName": ecosystem,
                "Severity": _severity_from_score(max((s["base_metrics"]["base_score"] for s in cvss_scores), default=0.0)),
            }
        }


def _parse_cvss(vector: str) -> dict[str, Any] | None:
    """Parse a CVSS vector into the structured form expected by the OS schema, or None on failure."""
    parsers: list[tuple[type, str]] = [(cvss.CVSS3, "3.0"), (cvss.CVSS2, "2.0")]
    for cls, default_version in parsers:
        try:
            c = cls(vector)
        except Exception:  # noqa: BLE001 — try the next CVSS version on any parse failure
            continue
        return {
            "version": default_version,
            "vector_string": vector,
            "base_metrics": {
                "base_score": float(c.base_score),
                # cvss.CVSS3 exposes sub-scores as c.isc / c.esc (raw, unrounded);
                # cvss.CVSS2 doesn't expose them, so fall back to 0.0.
                "exploitability_score": round(float(getattr(c, "esc", 0.0)), 1),
                "impact_score": round(float(getattr(c, "isc", 0.0)), 1),
                "base_severity": str(c.severities()[0]),
            },
            "status": "N/A",
        }
    return None


def _severity_from_score(base_score: float) -> str:
    """Map a CVSS v3 base score to its qualitative rating (None/Low/Medium/High/Critical)."""
    if base_score <= 0.0:
        return "None"
    if base_score < 4.0:
        return "Low"
    if base_score < 7.0:
        return "Medium"
    if base_score < 9.0:
        return "High"
    return "Critical"


def _vulnerable_range(ranges: list[dict[str, Any]] | None) -> str:
    """Build a VulnerableRange string (e.g. '>= 1.0, < 2.0') from an OSV affected.ranges array.

    OSV events become comparators: ``introduced`` -> ``>=`` (omitted when ``"0"``),
    ``fixed`` -> ``<``, ``last_affected`` -> ``<=``. Comparators are joined with ", ".
    """
    parts: list[str] = []
    for r in ranges or []:
        for event in r.get("events") or []:
            if "introduced" in event:
                v = event["introduced"]
                if v and v != "0":
                    parts.append(f">= {v}")
            elif "fixed" in event:
                parts.append(f"< {event['fixed']}")
            elif "last_affected" in event:
                parts.append(f"<= {event['last_affected']}")
    return ", ".join(parts)


def _version_from_ranges(ranges: list[dict[str, Any]] | None) -> str | None:
    """Pull a Version from an OSV affected.ranges array.

    Returns the first ``fixed`` event encountered (priority); otherwise the first
    ``introduced`` event; otherwise ``None`` when neither is present.
    """
    introduced: str | None = None
    for r in ranges or []:
        for event in r.get("events") or []:
            if "fixed" in event:
                return event["fixed"]
            if introduced is None and "introduced" in event:
                introduced = event["introduced"]
    return introduced
