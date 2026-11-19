"""
This driver requires a specific Github Personal Access Token (PAT). Generate
one with the necessary scope with:

    https://github.com/settings/tokens/new

The authentication is done over HTTP headers for a PAT. If OAuth apps are
needed, then the authentication header needs to be modified from:

     headers = {"Authorization": "token XYZ123TOKENTOKENTOKEN"}

To:

     headers = {"Authorization": "Bearer XYZ123TOKENTOKENTOKEN"}

"""

from __future__ import annotations

import datetime
import logging
import os
import re
import time
from dataclasses import dataclass
from decimal import Decimal, DecimalException
from typing import TYPE_CHECKING

import requests
from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSS3MalformedError, CVSS4MalformedError

from vunnel import utils
from vunnel.tool import fixdate
from vunnel.utils import fdb as db
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics

if TYPE_CHECKING:
    from types import TracebackType

    from vunnel.workspace import Workspace

# this is the ecosystem in GHSA to a syft package type
ecosystem_map = {
    "COMPOSER": "composer",
    "ERLANG": "erlang",
    "GO": "go",
    "MAVEN": "java",
    "NPM": "npm",
    "NUGET": "nuget",
    "PIP": "python",
    "PUB": "dart",
    "RUBYGEMS": "gem",
    "RUST": "rust",
    "SWIFT": "swift",
    "ACTIONS": "github-action",
}

GITHUB_RATE_LIMIT_REMAINING_HEADER = "x-ratelimit-remaining"
GITHUB_RATE_LIMIT_RESET_HEADER = "x-ratelimit-reset"


@dataclass
class RepoAdvisorySource:
    """
    A GitHub repository whose repository-scoped security advisories should be
    fetched in addition to the global GitHub Advisory Database.

    Repository advisories that are never reviewed into the global database
    (common for projects that are not themselves a package in a GHSA ecosystem,
    such as language runtimes) carry a free-form or empty ecosystem, so the
    ecosystem (a syft package type) must be given explicitly. When package is
    set, it replaces the package name on every affected entry.
    """

    repo: str = ""
    ecosystem: str = ""
    package: str | None = None


class Parser:
    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        token: str,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        api_url: str = "https://api.github.com/graphql",
        logger: logging.Logger | None = None,
        repos: list[RepoAdvisorySource] | None = None,
        rest_api_url: str = "https://api.github.com",
    ):
        self.repos = repos or []
        self.rest_api_url = rest_api_url.rstrip("/")
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.db = db.connection(workspace.input_path, serializer="json")
        self.download_timeout = download_timeout
        self.api_url = api_url
        self.token = token
        self.timestamp = None
        self.cursor = None
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download(self, vuln_cursor=None):
        """
        Download the advisories from Github via the GraphQL API, using a cursor
        if it was defined in the class. Advisories stay in memory until
        persisted later in the process.
        """
        if not self.token:
            raise ValueError("Github token must be defined")

        query = graphql_advisories(timestamp=self.timestamp, cursor=self.cursor, vuln_cursor=vuln_cursor)

        return get_query(self.token, query, self.download_timeout, self.api_url)

    def _parse(self, data):
        """
        Load JSON from `self.json_file`, extract values from interesting fields.
        Sample output from GraphQL request:

            {
              "data": {
                "securityAdvisories": {
                  "nodes": [
                    {
                      "ghsaId": "GHSA-73m2-3pwg-5fgc",
                      "summary": "Critical severity vulnerability that affects waitress",
                      "severity": "CRITICAL",
                      "publishedAt": "2020-02-04T03:07:31Z",
                      "identifiers": [
                        {
                          "type": "GHSA",
                          "value": "GHSA-73m2-3pwg-5fgc"
                        },
                        {
                          "type": "CVE",
                          "value": "CVE-2020-5236"
                        }
                      ],
                      "references": [
                        {
                          "url": "https://github.com/Pylons/waitress/security/advisories/GHSA-73m2-3pwg-5fgc"
                        },
                        {
                          "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-5236"
                        }
                      ],
                      "vulnerabilities": {
                        "pageInfo": {
                          "endCursor": "MQ",
                          "hasNextPage": False
                        },
                        "nodes": [
                          {
                            "package": {
                              "ecosystem": "PIP",
                              "name": "waitress"
                            },
                            "firstPatchedVersion": {
                              "identifier": "1.4.3"
                            }
                          }
                        ]
                      },
                      "description": "### Impact\r\n\r\nWhen waitress[...]"
                    }
                  ]
                }
              }
            }
        """
        advisories = []
        advisory_nodes = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        for node_data in advisory_nodes:
            subquery_cursor = needs_subquery(node_data)
            # An unlikely situation where more than one hundred vulnerabilities
            # are associated with an advisory, and requests need to be done to
            # fetch all the missing ones
            if subquery_cursor:
                ghsaId = node_data["ghsaId"]
                self.logger.info(f"found node that requires a subquery: {ghsaId}")

                extra_vulnerabilities = get_vulnerabilities(
                    self.token,
                    ghsaId,
                    self.timestamp,
                    subquery_cursor,
                    parent_cursor=self.cursor,
                )
                current_vulnerabilities = node_data.get("vulnerabilities", {}).get("nodes", [])
                current_vulnerabilities.extend(extra_vulnerabilities)

            parsed = NodeParser(node_data, self.fixdater, logger=self.logger).parse()
            advisories.append(parsed)

        return advisories

    def get(self):
        self.fixdater.download()

        # determine if a run was completed by looking for a timestamp
        metadata = self.db.get_metadata()

        # why rstrip(Z)? Previous code had been incorrectly adding a Z to the end of the timestamp manually
        # instead of using the isoformat() method. This lead to a parsing problem with the github API (naturally).
        # in the future this rstrip() should be removed when all cached data in CI is updated.
        self.timestamp = metadata.data.get("timestamp")
        if self.timestamp:
            self.timestamp = self.timestamp.rstrip("Z")

        current_timestamp = datetime.datetime.now(tz=datetime.UTC).isoformat()
        has_cursor = True
        global_ids: set[str] = set()

        # Process everything that was persisted first
        for node_data in self.db.get_all():
            parsed = NodeParser(node_data.load(), self.fixdater, logger=self.logger).parse()
            global_ids.add(parsed.data.get("ghsaId", ""))
            yield parsed

        while has_cursor:
            # download graphql data as json, if the timestamp is present, then the
            # download will retrieve advisories that have been updated from that
            # point in time, if a cursor is present, it will be used as well
            data = self._download()

            if "errors" in data:
                raise RuntimeError(f"Error downloading advisories: {data['errors']}")

            page_info = data["data"]["securityAdvisories"]["pageInfo"]
            if page_info["hasNextPage"]:
                self.cursor = has_cursor = page_info.get("endCursor")
            else:
                has_cursor = False

            advisories = self._parse(data)
            for advisory in advisories:
                record = self.db.create(advisory.data["ghsaId"])
                record.commit(advisory.data)
                global_ids.add(advisory.data["ghsaId"])
                yield advisory

        # Repository advisories are refetched in full every run and never persisted to the incremental
        # store, so edits and withdrawals upstream take effect on the next run. Once GitHub reviews one
        # into the global database (same GHSA ID), the global record wins and the repository copy is skipped.
        yield from self._get_repo_advisories(global_ids)

        # No more work to do. Persist the timestamp and return
        metadata.data["timestamp"] = current_timestamp
        metadata.commit()

    def _get_repo_advisories(self, global_ids: set[str]):
        for source in self.repos:
            advisories = get_repo_advisories(source.repo, self.token, self.download_timeout, self.rest_api_url)
            self.logger.info(f"fetched {len(advisories)} repository advisories from {source.repo}")
            for rest_advisory in advisories:
                ghsa_id = rest_advisory.get("ghsa_id")
                if not ghsa_id:
                    continue
                if ghsa_id in global_ids:
                    self.logger.debug(f"skipping repository advisory {ghsa_id} from {source.repo}: present in global database")
                    continue
                node = repo_advisory_to_node(rest_advisory, source, logger=self.logger)
                if not node["vulnerabilities"]["nodes"]:
                    self.logger.warning(f"skipping repository advisory {ghsa_id} from {source.repo}: no usable affected packages")
                    continue
                yield NodeParser(
                    node,
                    self.fixdater,
                    logger=self.logger,
                    ecosystem_override=source.ecosystem,
                    advisory_url=rest_advisory.get("html_url"),
                ).parse()


@utils.retry_with_backoff()
def get_query(token, query, timeout=125, api_url="https://api.github.com/graphql"):
    logger = logging.getLogger("get-query")

    headers = {"Authorization": f"token {token}"}
    logger.info(f"downloading github advisories from {api_url}")

    response = requests.post(api_url, json={"query": query}, timeout=timeout, headers=headers)
    if GITHUB_RATE_LIMIT_REMAINING_HEADER in response.headers and GITHUB_RATE_LIMIT_RESET_HEADER in response.headers:
        remaining = int(response.headers[GITHUB_RATE_LIMIT_REMAINING_HEADER])
        # reset time is the time in UNIX Epoch Seconds at which
        # the rate limit will reset.
        reset_time = int(response.headers[GITHUB_RATE_LIMIT_RESET_HEADER])
        logger.debug(f"github rate limit has {remaining} requests left {reset_time}")
        if remaining < 10:
            current_time = int(time.time())
            sleep_time = reset_time - current_time
            # note that the rate limit resets 1x / hour, so this could be a long time
            if sleep_time > 1 and sleep_time < 3600:  # never sleep for more than 1 hour
                logger.info(f"sleeping for {sleep_time} seconds to allow GitHub rate limit to reset")
                time.sleep(sleep_time)
            elif sleep_time > 3600:
                raise Exception(
                    f"github rate limit exhaused and not expected to reset for {sleep_time} seconds. Try again later.",
                )
    response.raise_for_status()
    if response.status_code == 200:
        return response.json()
    raise Exception(f"Unable to retrieve Github Advisories. HTTP Code: {response.status_code}")


@utils.retry_with_backoff()
def _get_rest_page(url: str, token: str, timeout: int) -> requests.Response:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response


def get_repo_advisories(repo: str, token: str, timeout: int = 125, rest_api_url: str = "https://api.github.com") -> list[dict]:
    """
    Fetch all published repository-scoped security advisories for an "owner/name" repository
    via the REST API, following pagination.
    """
    logger = logging.getLogger("get-repo-advisories")
    url: str | None = f"{rest_api_url}/repos/{repo}/security-advisories?state=published&per_page=100"
    advisories: list[dict] = []
    while url:
        logger.info(f"downloading github repository advisories from {url}")
        response = _get_rest_page(url, token, timeout)
        page = response.json()
        if not isinstance(page, list):
            raise RuntimeError(f"unexpected response fetching repository advisories for {repo}: {page}")
        advisories.extend(page)
        url = response.links.get("next", {}).get("url")
    return advisories


_REST_SEVERITY_MAP = {
    "low": "LOW",
    "medium": "MODERATE",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def _version_key(version: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", version)
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def select_fix_version(version_range: str, patched_versions: str) -> str | None:
    """
    Repository advisories carry a free-form, comma separated "patched_versions" string per affected range,
    e.g. range ">= 3.4.0, <= 3.4.11" with patched versions "3.4.12, 4.0.0". Pick the lowest patched
    version that lies above the range's upper bound, which is the fix for that range. Fall back to the
    first listed version when the range has no usable upper bound.
    """
    candidates = [v.strip() for v in (patched_versions or "").split(",") if v.strip()]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    upper = re.search(r"(<=?)\s*([^\s,]+)", version_range or "")
    upper_key = _version_key(upper.group(2)) if upper else None
    if not upper or upper_key is None:
        return candidates[0]
    inclusive = upper.group(1) == "<="

    eligible = []
    for c in candidates:
        key = _version_key(c)
        if key is None:
            continue
        if key > upper_key or (not inclusive and key == upper_key):
            eligible.append((key, c))
    if not eligible:
        return candidates[0]
    return min(eligible)[1]


def repo_advisory_to_node(rest: dict, source: RepoAdvisorySource, logger: logging.Logger | None = None) -> dict:
    """
    Convert a REST repository advisory into the GraphQL securityAdvisories node shape that NodeParser consumes.
    """
    if not logger:
        logger = logging.getLogger("repo-advisory-to-node")

    vulnerabilities = []
    for v in rest.get("vulnerabilities") or []:
        version_range = (v.get("vulnerable_version_range") or "").strip()
        if not version_range:
            logger.warning(f"dropping affected entry without a version range from {rest.get('ghsa_id')} ({source.repo})")
            continue
        package = v.get("package") or {}
        fix_version = select_fix_version(version_range, v.get("patched_versions") or "")
        vulnerabilities.append(
            {
                "package": {
                    "ecosystem": package.get("ecosystem") or "",
                    "name": source.package or package.get("name"),
                },
                "firstPatchedVersion": {"identifier": fix_version} if fix_version else None,
                "vulnerableVersionRange": version_range,
            },
        )

    cvss_severities = {}
    for rest_key, gql_key in (("cvss_v3", "cvssV3"), ("cvss_v4", "cvssV4")):
        entry = (rest.get("cvss_severities") or {}).get(rest_key) or {}
        if entry.get("vector_string"):
            cvss_severities[gql_key] = {"score": entry.get("score"), "vectorString": entry["vector_string"]}

    identifiers = list(rest.get("identifiers") or [])
    if rest.get("cve_id") and not any(i.get("value") == rest["cve_id"] for i in identifiers):
        identifiers.append({"type": "CVE", "value": rest["cve_id"]})

    references = [{"url": rest["html_url"]}] if rest.get("html_url") else []

    return {
        "ghsaId": rest.get("ghsa_id"),
        "classification": "GENERAL",
        "summary": rest.get("summary"),
        "severity": _REST_SEVERITY_MAP.get((rest.get("severity") or "").lower()),
        "cvssSeverities": cvss_severities or None,
        "identifiers": identifiers,
        "references": references,
        "vulnerabilities": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": vulnerabilities},
        "publishedAt": rest.get("published_at"),
        "updatedAt": rest.get("updated_at"),
        "withdrawnAt": rest.get("withdrawn_at"),
    }


def get_advisory(ghsaId, data):
    """
    Given a list of advisories, find the one associated with the ghsaId. The
    data is expected as the raw JSON response from the GraphQL, so processing
    needs to traverse into the nodes
    """
    try:
        nodes = data["data"]["securityAdvisories"]["nodes"]
    except KeyError:
        return {}
    for node in nodes:
        if node.get("ghsaId", "") == ghsaId:
            return node
    return {}


def get_vulnerabilities(token, ghsaId, timestamp, vuln_cursor, parent_cursor):
    """
    In the improbable case that an Advisory is associated with more than 100
    (Github's GraphQL limit) these will need to get fetched until the cursor is
    exhausted.
    This function is only executed if it has been determined that pagination is
    present from the securityAdvisories JSON response::

      {
        ...
            "vulnerabilities": {
              "pageInfo": {
                "hasNextPage": false,
                "endCursor": "Mg"
              },
              "nodes": [
                {
                  "package": {
                    "ecosystem": "NPM",
                    "name": "event-stream"
                  },
                  "firstPatchedVersion": {
                    "identifier": "4.0.0"
                  }
                }
              ]
            }
        ...
      }


    """
    logger = logging.getLogger("get-vulnerabilities")

    nodes = []
    while vuln_cursor is not None:
        logger.info(f"fetching extra vulnerability from {ghsaId}, page count: {len(nodes) + 1}")

        query = graphql_advisories(parent_cursor, timestamp, vuln_cursor)
        data = get_query(token, query)
        advisory = get_advisory(ghsaId, data)

        # data will retrieve the 100 advisories that the parent cursor
        # initially got, we must find the specific advisory needed for
        # pagination using the ghsaId
        vulnerabilities = advisory.get("vulnerabilities", {})
        page_info = vulnerabilities.get("pageInfo", {})
        vuln_cursor = page_info.get("endCursor") if page_info.get("hasNextPage") else None

        for vulnerability in vulnerabilities.get("nodes", []):
            nodes.append(vulnerability)

    return nodes


def needs_subquery(data):
    """
    This will probably never require a subquery, but still check if it
    needs to, set the boolean.

    Checks for `"hasNextPage"` within the vulnerabilities::

      "vulnerabilities": {
        "pageInfo": {
          "endCursor": "MQ",
          "hasNextPage": true
        },
        "nodes": [
          {
            "package": {
              "ecosystem": "NPM",
              "name": "event-stream"
            },
            "firstPatchedVersion": {
              "identifier": "4.0.0"
            }
          }
        ]
      }

    This function is not part of the parser because it does not alter or
    extract any useful information needed for processing, preventing double
    parsing.
    """
    pageInfo = data.get("vulnerabilities", {}).get("pageInfo", {})
    if pageInfo.get("hasNextPage", True):
        return pageInfo.get("endCursor")
    return False


def graphql_advisories(cursor=None, timestamp=None, vuln_cursor=None):
    """
    The cursor needs to be the `endCursor` for the last successful query. The
    feed will go fetch from the beginning of all the feeds available, in
    chunks of 100 which is the limit per request. For the roughly 1700
    advisories this would mean less than 20 requests.

    There are four distinct GraphQL requests:

    * No cursor, and no timestamp: the first request ever to the advisory database
    * A cursor, but no timestamp: The first batch of requests ever after the
      initial request to the database
    * No cursor with a timestamp: A first batch was completed, and this is the
      first request for a new iteration. Timestamp is used to retrieve any
      updates since the last batch was finished
    * A cursor with timestamp: A first batch was completed, and this follows
      after the first request is done which provides the cursor.

    Example GraphQL query (use: https://developer.github.com/v4/explorer/) ::

        {
          securityAdvisories(
            classifications: [GENERAL, MALWARE]
            orderBy: {field: PUBLISHED_AT, direction: ASC}
            first: 10
          ) {
            nodes {
              ghsaId
              classification
              summary
              severity
              cvssSeverities {
                cvssV3 {
                    score
                    vectorString
                }
                cvssV4 {
                    score
                    vectorString
                }
              }
              identifiers {
                type
                value
              }
              references {
                url
              }
              vulnerabilities(
                classifications: [GENERAL, MALWARE]
                first: 100
                orderBy: {field: UPDATED_AT, direction: ASC}
              ) {
                pageInfo {
                  endCursor
                  hasNextPage
                }
                nodes {
                  package {
                    ecosystem
                    name
                  }
                  firstPatchedVersion {
                    identifier
                  }
                  vulnerableVersionRange
                }
              }
              publishedAt
              updatedAt
              withdrawnAt
            }
            pageInfo {
              endCursor
              hasNextPage
              hasPreviousPage
              startCursor
            }
          }
        }

    If trying to get a single GHSA, the `securityAdvisories` field needs to be updated
    with and identifier, to::

      securityAdvisories(
        classifications: [GENERAL, MALWARE]
        orderBy: {field: PUBLISHED_AT
        direction: ASC}, first: 10
        identifier: {type: GHSA, value: "GHSA-pp7h-53gx-mx7r"}
      ) {
    """
    query_func = "securityAdvisories(orderBy: {field: %s, direction: ASC}, "
    updatedSince = ""
    after = ""
    vuln_after = ""
    if timestamp:
        query_func = query_func % "UPDATED_AT"
        updatedSince = f'updatedSince: "{timestamp}", '
    else:
        query_func = query_func % "PUBLISHED_AT"

    if cursor:
        after = f'after: "{cursor}", '

    caller = f"{query_func}{after}{updatedSince}classifications: [GENERAL, MALWARE], first: 100)"

    if vuln_cursor:
        vuln_after = f'after: "{vuln_cursor}", '
    vulnerabilities = f"{vuln_after}classifications: [GENERAL, MALWARE], first: 100, orderBy: {{field: UPDATED_AT, direction: ASC}}"

    return f"""
    {{
      {caller} {{
        nodes {{
          ghsaId
          classification
          summary
          severity
          cvssSeverities {{
            cvssV3 {{
              score
              vectorString
            }}
            cvssV4 {{
              score
              vectorString
            }}
          }}
          identifiers {{
            type
            value
          }}
          references {{
            url
          }}
          vulnerabilities({vulnerabilities}) {{
            pageInfo {{
              endCursor
              hasNextPage
            }}
            nodes {{
              package {{
                ecosystem
                name
              }}
              firstPatchedVersion {{
                identifier
              }}
              vulnerableVersionRange
            }}
          }}
          publishedAt
          updatedAt
          withdrawnAt
        }}
        pageInfo {{
          endCursor
          hasNextPage
          hasPreviousPage
          startCursor
        }}
      }}
    }}
    """


class NodeParser(dict):
    __parsers__ = (
        "_classification",
        "_severity",
        "_cvss_severities",
        "_fixedin",
        "_summary",
        "_url",
        "_cves",
        "_published",
        "_updated",
        "_withdrawn",
        "_references",
    )

    def __init__(
        self,
        data: dict,
        fixdater: fixdate.Finder,
        logger: logging.Logger | None = None,
        ecosystem_override: str | None = None,
        advisory_url: str | None = None,
    ):
        self.fixdater = fixdater
        # repository advisories have no usable GHSA ecosystem, so the syft package type is configured explicitly
        self.ecosystem_override = ecosystem_override
        self.advisory_url = advisory_url
        self.description = None
        self.identifier = None
        self.summary = None
        self.cves = []
        self.data = data
        self.ecosystems = set()
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def parse(self):
        for parser in self.__parsers__:
            getattr(self, parser)()
        return self

    def __getattr__(self, attr):
        if attr in self:
            return self[attr]
        raise AttributeError(f"No such attribute: {attr}")

    def _classification(self):
        classification = self.data.get("classification", "GENERAL")
        self["Classification"] = classification

    def _severity(self):
        """
        Severity is extracted and expected to be upper-case:

            "severity": "CRITICAL",

        This is transformed to meet the schema on the consumer to:

            "Critical"

        All severities from Github are::

            'CRITICAL'
            'HIGH'
            'LOW'
            'MODERATE'


        """
        severity_map = {
            "LOW": "Low",
            "MODERATE": "Medium",
            "HIGH": "High",
            "CRITICAL": "Critical",
        }
        severity = self.data.get("severity")
        self["Severity"] = severity_map.get(severity, "Unknown")

    def _make_legacy_cvss(self, cvss_vector: str, vulnerability_id: str) -> CVSS | None:
        try:
            cvss_vector = cvss_vector.removesuffix("/")
            cvss3_obj = CVSS3(cvss_vector)

            cvss_object = CVSS(
                version=f"3.{cvss3_obj.minor_version}",
                vector_string=cvss_vector,
                base_metrics=CVSSBaseMetrics(
                    base_score=float(cvss3_obj.base_score.quantize(Decimal("0.1"))),
                    exploitability_score=float(cvss3_obj.esc.quantize(Decimal("0.1"))),
                    impact_score=float(cvss3_obj.isc.quantize(Decimal("0.1"))),
                    base_severity=cvss3_obj.severities()[0],
                ),
                status="N/A",
            )
        except (CVSS3MalformedError, DecimalException, AttributeError):
            self.logger.exception(
                "error transforming CVSS v3 vector %s, skipping it for %s",
                cvss_vector,
                vulnerability_id,
            )
            cvss_object = None

        return cvss_object

    def _make_cvss_v3(self, cvss_vector: str, vulnerability_id: str) -> dict | None:
        try:
            cvss_vector = cvss_vector.removesuffix("/")
            cvss3_obj = CVSS3(cvss_vector)
            cvss_object = {
                "version": f"3.{cvss3_obj.minor_version}",
                "vector": cvss_vector,
            }
        except (CVSS3MalformedError, DecimalException, AttributeError):
            self.logger.exception(
                "error transforming CVSS v3 vector %s, skipping it for %s",
                cvss_vector,
                vulnerability_id,
            )
            cvss_object = None

        return cvss_object

    def _make_cvss_v4(self, cvss_vector: str, vulnerability_id: str) -> dict | None:
        try:
            cvss_vector = cvss_vector.removesuffix("/")
            v4 = CVSS4(cvss_vector)
            version = v4.clean_vector().split("/")[0].split(":")[1]
            cvss_object = {
                "version": version,
                "vector": cvss_vector,
            }
        except (CVSS4MalformedError, DecimalException, AttributeError):
            self.logger.exception(
                "error transforming CVSS v4 vector %s, skipping it for %s",
                cvss_vector,
                vulnerability_id,
            )
            cvss_object = None

        return cvss_object

    def _make_cvss_severities(self, cvss_severities: dict, vulnerability_id: str) -> list:
        result: list = []
        v3 = cvss_severities.get("cvssV3")
        if v3:
            vector = v3.get("vectorString")
            if vector:
                # legacy CVSS needs to stick around until v5 schema db updates stop
                self["CVSS"] = self._make_legacy_cvss(vector, vulnerability_id)
                cvss_v3 = self._make_cvss_v3(vector, vulnerability_id)
                if cvss_v3:
                    result.append(cvss_v3)

        v4 = cvss_severities.get("cvssV4")
        if v4:
            vector = v4.get("vectorString")
            if vector:
                cvss_v4 = self._make_cvss_v4(vector, vulnerability_id)
                if cvss_v4:
                    result.append(cvss_v4)

        return result

    def _cvss_severities(self):
        cvss_severities = self.data.get("cvssSeverities")

        if cvss_severities:
            self["cvss_severities"] = self._make_cvss_severities(cvss_severities, self.data.get("ghsaId"))

    def _fixedin(self):
        """
        Extracts `identifier` key from `firstPatchedVersion':

            "vulnerabilities": {
              "nodes": [
                {
                  "package": {
                    "ecosystem": "PIP",
                    "name": "waitress"
                  },
                  "firstPatchedVersion": {
                    "identifier": "1.4.3"
                  },
                  "vulnerableVersionRange": ">= 1.2.0, < 1.4.3",
                }
              ]
            }
        """
        self["FixedIn"] = []
        vulnerabilities = self.data.get("vulnerabilities", {}).get("nodes", [])
        for item in vulnerabilities:
            # identify the type of package, if this is a DEB or RPM or
            # something we haven't seen before, ignore it
            github_ecosystem = item.get("package", {}).get("ecosystem")
            ecosystem = self.ecosystem_override or ecosystem_map.get(github_ecosystem)
            if ecosystem:
                self.ecosystems.add(ecosystem)

                try:
                    fix_version = item.get("firstPatchedVersion", {}).get("identifier", None)
                except AttributeError:
                    fix_version = None

                package_name = item.get("package", {}).get("name")
                version_range = item.get("vulnerableVersionRange", "").replace(",", "")

                record = {
                    "name": package_name,
                    "identifier": fix_version or "None",
                    "ecosystem": ecosystem,
                    "namespace": f"github:{ecosystem}",
                    "range": version_range,
                }

                vid = self.data.get("ghsaId")
                result = self.fixdater.best(
                    vuln_id=vid,
                    cpe_or_package=package_name,
                    fix_version=fix_version,
                    ecosystem=ecosystem,
                )
                if result:
                    record["available"] = {
                        "date": result.date.isoformat(),
                        "kind": result.kind,
                    }

                self["FixedIn"].append(record)
            else:
                # Log vuln skipped for unknown ecosystem
                self.logger.debug("dropping github vuln from unmapped ecosystem: %s", github_ecosystem)

    def _summary(self):
        self["Summary"] = self.data.get("summary")

    def _published(self):
        self["published"] = self.data.get("publishedAt")

    def _updated(self):
        self["updated"] = self.data.get("updatedAt")

    def _withdrawn(self):
        self["withdrawn"] = self.data.get("withdrawnAt")

    def _references(self):
        self["references"] = self.data.get("references", [])

    def _url(self):
        """
        This creates the advisory URL which doesn't exist as part of the API,
        using the ID.
        """
        if self.advisory_url:
            self["url"] = self.advisory_url
            return
        self["url"] = os.path.join("https://github.com/advisories/", self.data.get("ghsaId"))

    def _cves(self):
        cves = []
        for identifier in self.data.get("identifiers", []):
            value = identifier["value"]
            if value.startswith("GHSA"):
                continue
            cves.append(value)
        self["CVE"] = cves
        self["Metadata"] = {"CVE": cves}
        self["ghsaId"] = self.data.get("ghsaId")
