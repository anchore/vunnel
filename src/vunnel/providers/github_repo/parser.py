"""
Fetch published repository security advisories via the GitHub REST API and
convert them into the same records the ``github`` provider produces.

Repository advisories are visible on a repository's Security tab as soon as a
maintainer publishes them, but only appear in the global GitHub Advisory
Database (which the ``github`` provider consumes) after GitHub has reviewed
them, which can take weeks. This parser only yields advisories that have *not*
yet been merged into the global database; once merged, the ``github`` provider
becomes the source of truth.

Each REST advisory is adapted into the GraphQL node shape used by the
``github`` provider and run through its :class:`NodeParser`, so the output is
identical in shape to the ``github`` provider's.
"""

from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Any

import orjson
import requests

from vunnel import utils
from vunnel.providers.github.parser import NodeParser, get_query, respect_rate_limit
from vunnel.tool import fixdate
from vunnel.utils import fdb as db

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

DEFAULT_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"

# number of advisories checked against the global database per GraphQL request
MERGE_CHECK_BATCH_SIZE = 100

# REST severity -> GraphQL severity (as understood by NodeParser)
SEVERITY_MAP = {
    "low": "LOW",
    "medium": "MODERATE",
    "moderate": "MODERATE",
    "high": "HIGH",
    "critical": "CRITICAL",
}

_REPO_PATTERN = re.compile(
    r"^(?:https?://(?:www\.)?github\.com/)?(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$",
)

_GHSA_PATTERN = re.compile(r"^GHSA(?:-[0-9a-z]{4}){3}$", re.IGNORECASE)


def graphql_merge_check(ghsa_ids: list[str]) -> str:
    """
    Build a single GraphQL query that looks up each advisory by alias (``a0``, ``a1``, ...).
    IDs must already be validated against ``_GHSA_PATTERN`` since they are interpolated.
    """
    lookups = "\n".join(f'  a{idx}: securityAdvisory(ghsaId: "{ghsa_id}") {{ ghsaId }}' for idx, ghsa_id in enumerate(ghsa_ids))
    return f"{{\n{lookups}\n}}"


def normalize_repo(value: str) -> str:
    """
    Normalize a repository reference to ``owner/repo``.

    Accepts ``owner/repo`` or a GitHub URL such as ``https://github.com/owner/repo``
    (optionally with a ``.git`` suffix or trailing slash). Raises ``ValueError``
    for anything else.
    """
    match = _REPO_PATTERN.match(value.strip()) if isinstance(value, str) else None
    if not match or match.group("repo") in {".", ".."}:
        raise ValueError(f"invalid GitHub repository {value!r}: expected 'owner/repo' or 'https://github.com/owner/repo'")
    return f"{match.group('owner')}/{match.group('repo')}"


def _first_patched_version(patched_versions: str | None) -> dict[str, str] | None:
    if not patched_versions:
        return None
    first = patched_versions.split(",")[0].strip()
    return {"identifier": first} if first else None


def to_graphql_node(advisory: dict[str, Any]) -> dict[str, Any]:
    """
    Adapt a REST repository advisory into the GraphQL ``securityAdvisories`` node
    shape consumed by :class:`vunnel.providers.github.parser.NodeParser`.
    """
    ghsa_id = advisory.get("ghsa_id")

    identifiers = [{"type": str(i.get("type", "")).upper(), "value": i.get("value")} for i in advisory.get("identifiers") or [] if i.get("value")]
    cve_id = advisory.get("cve_id")
    if cve_id and not any(i["value"] == cve_id for i in identifiers):
        identifiers.append({"type": "CVE", "value": cve_id})

    cvss_severities: dict[str, Any] = {}
    for rest_key, gql_key in (("cvss_v3", "cvssV3"), ("cvss_v4", "cvssV4")):
        entry = (advisory.get("cvss_severities") or {}).get(rest_key) or {}
        cvss_severities[gql_key] = {"score": entry.get("score"), "vectorString": entry.get("vector_string")}

    vulnerabilities = []
    for vuln in advisory.get("vulnerabilities") or []:
        package = vuln.get("package") or {}
        node = {
            "package": {"ecosystem": str(package.get("ecosystem") or "").upper(), "name": package.get("name")},
            "firstPatchedVersion": _first_patched_version(vuln.get("patched_versions")),
            "vulnerableVersionRange": vuln.get("vulnerable_version_range") or "",
        }
        # maintainers sometimes list the same package/range more than once
        if node not in vulnerabilities:
            vulnerabilities.append(node)

    references = [{"url": advisory["html_url"]}] if advisory.get("html_url") else []

    return {
        "ghsaId": ghsa_id,
        "classification": "GENERAL",
        "summary": advisory.get("summary"),
        "description": advisory.get("description"),
        "severity": SEVERITY_MAP.get(str(advisory.get("severity") or "").lower()),
        "cvssSeverities": cvss_severities,
        "identifiers": identifiers,
        "references": references,
        "vulnerabilities": {"nodes": vulnerabilities},
        "publishedAt": advisory.get("published_at"),
        "updatedAt": advisory.get("updated_at"),
        "withdrawnAt": advisory.get("withdrawn_at"),
    }


class Parser:
    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        token: str,
        repos: list[str],
        api_url: str = DEFAULT_API_URL,
        download_timeout: int = 125,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(workspace)
        self.fixdater = fixdater
        self.workspace = workspace
        self.token = token
        self.repos = repos
        self.api_url = api_url.rstrip("/")
        self.graphql_url = f"{self.api_url}/graphql"
        self.download_timeout = download_timeout
        self.db = db.connection(workspace.input_path, serializer="json")
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    @property
    def urls(self) -> list[str]:
        return [self._advisories_url(repo) for repo in self.repos]

    def _advisories_url(self, repo: str) -> str:
        return f"{self.api_url}/repos/{repo}/security-advisories"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": GITHUB_API_VERSION}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @utils.retry_with_backoff()
    def _get(self, url: str, params: dict[str, Any] | None = None) -> requests.Response:
        """
        GET a GitHub API URL, honouring rate limits. A 404 is returned to the caller
        (it is an expected answer, not an error); other HTTP errors raise and are retried.
        """
        response = requests.get(url, params=params, headers=self._headers(), timeout=self.download_timeout)
        respect_rate_limit(response, self.logger)
        if response.status_code == 404:
            return response
        response.raise_for_status()
        return response

    def _repo_advisories(self, repo: str) -> list[dict[str, Any]]:
        """Return all published advisories for a repository, following pagination."""
        url: str | None = self._advisories_url(repo)
        params: dict[str, Any] | None = {"state": "published", "per_page": 100}
        advisories: list[dict[str, Any]] = []

        while url:
            self.logger.info(f"downloading published security advisories from {url}")
            response = self._get(url, params=params)
            if response.status_code == 404:
                self.logger.warning(f"repository {repo!r} not found or has no accessible security advisories, skipping")
                return []
            advisories.extend(response.json())
            # the next link already carries the query parameters (including the cursor)
            url = response.links.get("next", {}).get("url")
            params = None

        self._save_input(repo, advisories)
        return advisories

    def _save_input(self, repo: str, advisories: list[dict[str, Any]]) -> None:
        path = os.path.join(self.workspace.input_path, "repos", f"{repo.replace('/', '_')}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(orjson.dumps(advisories))

    def _merged_ids(self, ghsa_ids: list[str], merged: set[str]) -> set[str]:
        """
        Return the subset of `ghsa_ids` that are in the global GitHub Advisory Database
        (and are therefore produced by the `github` provider).

        Lookups are batched into GraphQL requests of up to `MERGE_CHECK_BATCH_SIZE`
        aliased `securityAdvisory` queries; this is the same API the `github` provider
        reads, so "found" means exactly "emitted by the github provider". Unknown
        advisories resolve to null with a NOT_FOUND error, which is the expected answer.
        Merging is one-way, so positive answers are added to the `merged` cache and
        never re-queried.
        """
        to_check = sorted({i for i in ghsa_ids if i not in merged})
        for start in range(0, len(to_check), MERGE_CHECK_BATCH_SIZE):
            batch = to_check[start : start + MERGE_CHECK_BATCH_SIZE]
            self.logger.info(f"checking {len(batch)} advisories against the GitHub Advisory Database")
            response = get_query(self.token, graphql_merge_check(batch), self.download_timeout, self.graphql_url)

            unexpected = [e for e in response.get("errors") or [] if e.get("type") != "NOT_FOUND"]
            if unexpected:
                raise RuntimeError(f"error checking advisories against the GitHub Advisory Database: {unexpected}")

            data = response.get("data") or {}
            for idx, ghsa_id in enumerate(batch):
                if data.get(f"a{idx}"):
                    merged.add(ghsa_id)

        return {i for i in ghsa_ids if i in merged}

    def get(self) -> Generator[NodeParser]:
        """Yield parsed advisories that are published on a repository but not yet in the global database."""
        if not self.token:
            raise ValueError("a GitHub token is required (the merge check uses the GitHub GraphQL API)")

        self.fixdater.download()

        published: list[dict[str, Any]] = []
        for repo in self.repos:
            for advisory in self._repo_advisories(repo):
                ghsa_id = advisory.get("ghsa_id")
                if advisory.get("state") != "published" or not isinstance(ghsa_id, str):
                    continue
                if not _GHSA_PATTERN.match(ghsa_id):
                    self.logger.warning(f"skipping advisory with unexpected identifier {ghsa_id!r} from {repo}")
                    continue
                published.append(advisory)

        metadata = self.db.get_metadata()
        merged = set(metadata.data.get("merged", []))
        try:
            already_merged = self._merged_ids([a["ghsa_id"] for a in published], merged)
        finally:
            metadata.data["merged"] = sorted(merged)
            metadata.commit()

        for advisory in published:
            ghsa_id = advisory["ghsa_id"]
            if ghsa_id in already_merged:
                self.logger.debug(f"skipping {ghsa_id}: already in the GitHub Advisory Database")
                continue

            parsed = NodeParser(to_graphql_node(advisory), self.fixdater, logger=self.logger).parse()
            # the global advisory URL does not resolve until the advisory is merged
            if advisory.get("html_url"):
                parsed["url"] = advisory["html_url"]
            yield parsed
