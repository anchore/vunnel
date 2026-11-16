from __future__ import annotations

import json
import os
import time
from unittest.mock import Mock, patch

import pytest
import requests

from vunnel import result, workspace
from vunnel.providers.github_repo import Config, Provider, parser

API = "https://api.github.com"
REPO_URL = f"{API}/repos/netty/netty/security-advisories"
PAGE_2_URL = f"{API}/repositories/1064563/security-advisories?state=published&per_page=100&after=abc"
MERGED_ID = "GHSA-xxxx-yyyy-zzzz"


def load_fixture(name: str) -> list[dict]:
    with open(os.path.join(os.path.dirname(__file__), "test-fixtures", name)) as fh:
        return json.load(fh)


def make_response(status_code: int = 200, body=None, next_url: str | None = None, headers: dict | None = None) -> Mock:
    response = Mock()
    response.status_code = status_code
    response.headers = headers or {}
    response.json = Mock(return_value=body)
    response.links = {"next": {"url": next_url, "rel": "next"}} if next_url else {}
    if status_code >= 400:
        response.raise_for_status = Mock(side_effect=requests.HTTPError(f"{status_code}"))
    else:
        response.raise_for_status = Mock()
    return response


@pytest.fixture()
def fake_github(monkeypatch):
    """
    Route requests.get calls to canned responses. `routes` maps URL -> response (or list of
    responses consumed in order). Unknown global advisory lookups return 404 (not merged).
    """

    def apply(routes: dict | None = None):
        if routes is None:
            routes = {
                REPO_URL: make_response(body=load_fixture("advisories-page-1.json"), next_url=PAGE_2_URL),
                PAGE_2_URL: make_response(body=load_fixture("advisories-page-2.json")),
                f"{API}/advisories/{MERGED_ID}": make_response(body={"ghsa_id": MERGED_ID, "type": "reviewed"}),
            }
        calls: list[str] = []

        def get(url, params=None, headers=None, timeout=None):
            calls.append(url)
            route = routes.get(url)
            if isinstance(route, list):
                return route.pop(0)
            if route is not None:
                return route
            if url.startswith(f"{API}/advisories/"):
                return make_response(404, body={"message": "Not Found"})
            raise AssertionError(f"unexpected request to {url}")

        monkeypatch.setattr(parser.requests, "get", get)
        return calls

    return apply


def new_parser(helpers, repos=("netty/netty",), token="secret"):
    ws = helpers.provider_workspace_helper(name=Provider.name())
    return parser.Parser(
        workspace=workspace.Workspace(root=ws.root, name=Provider.name(), create=True),
        token=token,
        repos=list(repos),
        api_url=API,
    )


class TestNormalizeRepo:
    @pytest.mark.parametrize(
        "value",
        [
            "netty/netty",
            "https://github.com/netty/netty",
            "https://github.com/netty/netty/",
            "https://github.com/netty/netty.git",
            "http://www.github.com/netty/netty",
            "  netty/netty  ",
        ],
    )
    def test_valid(self, value):
        assert parser.normalize_repo(value) == "netty/netty"

    def test_keeps_dots_in_repo_name(self):
        assert parser.normalize_repo("FasterXML/jackson.core") == "FasterXML/jackson.core"

    @pytest.mark.parametrize(
        "value",
        ["", "netty", "netty/netty/issues", "https://gitlab.com/netty/netty", "-bad/netty", "owner/..", None],
    )
    def test_invalid(self, value):
        with pytest.raises(ValueError, match="invalid GitHub repository"):
            parser.normalize_repo(value)


class TestConfig:
    def test_token_from_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "from-env")
        assert Config().token == "from-env"

    def test_token_redacted(self):
        assert "s3cr3t-token" not in str(Config(token="s3cr3t-token"))

    def test_repos_normalized_and_deduplicated(self):
        c = Config(token="t", repos=["https://github.com/netty/netty", "netty/netty", "FasterXML/jackson-databind"])
        assert c.repos == ["netty/netty", "FasterXML/jackson-databind"]

    def test_invalid_repo_fails_fast(self):
        with pytest.raises(ValueError):
            Config(token="t", repos=["not-a-repo"])

    def test_defaults(self):
        c = Config(token="t")
        assert c.repos == []
        assert c.api_url == "https://api.github.com"


class TestToGraphqlNode:
    def advisory(self, **overrides):
        adv = load_fixture("advisories-page-2.json")[0]
        adv.update(overrides)
        return adv

    @pytest.mark.parametrize(
        ("rest", "graphql"),
        [("low", "LOW"), ("medium", "MODERATE"), ("high", "HIGH"), ("critical", "CRITICAL"), ("unknown", None), (None, None)],
    )
    def test_severity(self, rest, graphql):
        assert parser.to_graphql_node(self.advisory(severity=rest))["severity"] == graphql

    def test_cve_added_to_identifiers(self):
        node = parser.to_graphql_node(self.advisory())
        assert {"type": "CVE", "value": "CVE-2026-54321"} in node["identifiers"]
        assert {"type": "GHSA", "value": "GHSA-abcd-efgh-ijkl"} in node["identifiers"]

    def test_cve_not_duplicated(self):
        adv = load_fixture("advisories-page-1.json")[1]
        node = parser.to_graphql_node(adv)
        assert [i["value"] for i in node["identifiers"]].count("CVE-2026-12345") == 1

    def test_vulnerabilities(self):
        nodes = parser.to_graphql_node(self.advisory())["vulnerabilities"]["nodes"]
        assert nodes[0] == {
            "package": {"ecosystem": "MAVEN", "name": "io.netty:netty-codec-http2"},
            "firstPatchedVersion": {"identifier": "4.2.18.Final"},
            "vulnerableVersionRange": ">= 4.2.0.Final, < 4.2.18.Final",
        }
        assert nodes[1]["firstPatchedVersion"] is None
        assert nodes[2]["package"]["ecosystem"] == "OTHER"

    def test_duplicate_vulnerabilities_removed(self):
        adv = load_fixture("advisories-page-1.json")[0]
        assert len(adv["vulnerabilities"]) == 3
        assert len(parser.to_graphql_node(adv)["vulnerabilities"]["nodes"]) == 2

    def test_cvss(self):
        node = parser.to_graphql_node(self.advisory())
        assert node["cvssSeverities"]["cvssV3"]["vectorString"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert node["cvssSeverities"]["cvssV4"]["score"] == 9.3

    def test_references_and_dates(self):
        node = parser.to_graphql_node(self.advisory())
        assert node["references"] == [{"url": "https://github.com/netty/netty/security/advisories/GHSA-abcd-efgh-ijkl"}]
        assert node["publishedAt"] == "2026-09-11T00:00:00Z"
        assert node["updatedAt"] == "2026-09-12T00:00:00Z"
        assert node["withdrawnAt"] is None

    def test_minimal_advisory(self):
        node = parser.to_graphql_node({"ghsa_id": "GHSA-1111-2222-3333"})
        assert node["vulnerabilities"]["nodes"] == []
        assert node["references"] == []
        assert node["identifiers"] == []


class TestParser:
    def test_follows_pagination_and_skips_merged(self, helpers, fake_github, auto_fake_fixdate_finder):
        calls = fake_github()
        p = new_parser(helpers)
        ids = [a["ghsaId"] for a in p.get()]

        assert ids == ["GHSA-rmcw-9fcq-wjq7", "GHSA-abcd-efgh-ijkl"]
        assert PAGE_2_URL in calls

    def test_parsed_output(self, helpers, fake_github, auto_fake_fixdate_finder):
        fake_github()
        p = new_parser(helpers)
        advisory = {a["ghsaId"]: a for a in p.get()}["GHSA-abcd-efgh-ijkl"]

        assert advisory["Severity"] == "Critical"
        assert advisory["CVE"] == ["CVE-2026-54321"]
        assert advisory["url"] == "https://github.com/netty/netty/security/advisories/GHSA-abcd-efgh-ijkl"
        assert advisory.ecosystems == {"java", "npm"}
        assert {f["namespace"] for f in advisory["FixedIn"]} == {"github:java", "github:npm"}
        assert {f["identifier"] for f in advisory["FixedIn"]} == {"4.2.18.Final", "None"}
        assert len(advisory["cvss_severities"]) == 2

    def test_merged_cache_avoids_repeat_lookup(self, helpers, fake_github, auto_fake_fixdate_finder):
        calls = fake_github()
        p = new_parser(helpers)
        list(p.get())
        assert calls.count(f"{API}/advisories/{MERGED_ID}") == 1
        assert p.db.get_metadata().data["merged"] == [MERGED_ID]

        calls.clear()
        list(p.get())
        assert f"{API}/advisories/{MERGED_ID}" not in calls
        # unmerged advisories are re-checked every run
        assert f"{API}/advisories/GHSA-rmcw-9fcq-wjq7" in calls

    def test_unreviewed_global_advisory_is_not_merged(self, helpers, fake_github, auto_fake_fixdate_finder):
        fake_github(
            {
                REPO_URL: make_response(body=load_fixture("advisories-page-1.json")),
                f"{API}/advisories/{MERGED_ID}": make_response(body={"ghsa_id": MERGED_ID, "type": "unreviewed"}),
            },
        )
        p = new_parser(helpers)
        ids = [a["ghsaId"] for a in p.get()]
        assert MERGED_ID in ids
        assert p.db.get_metadata().data["merged"] == []

    def test_non_published_advisories_skipped(self, helpers, fake_github, auto_fake_fixdate_finder):
        advisories = load_fixture("advisories-page-2.json")
        advisories[0]["state"] = "withdrawn"
        fake_github({REPO_URL: make_response(body=advisories)})
        assert list(new_parser(helpers).get()) == []

    def test_missing_repo_is_skipped(self, helpers, fake_github, auto_fake_fixdate_finder):
        other = f"{API}/repos/netty/gone/security-advisories"
        fake_github(
            {
                other: make_response(404, body={"message": "Not Found"}),
                REPO_URL: make_response(body=load_fixture("advisories-page-2.json")),
            },
        )
        ids = [a["ghsaId"] for a in new_parser(helpers, repos=("netty/gone", "netty/netty")).get()]
        assert ids == ["GHSA-abcd-efgh-ijkl"]

    def test_repo_with_no_advisories(self, helpers, fake_github, auto_fake_fixdate_finder):
        fake_github({REPO_URL: make_response(body=[])})
        assert list(new_parser(helpers).get()) == []

    @patch("time.sleep")
    def test_server_errors_are_retried(self, mock_sleep, helpers, fake_github, auto_fake_fixdate_finder):
        fake_github({REPO_URL: [make_response(502), make_response(body=load_fixture("advisories-page-2.json"))]})
        assert [a["ghsaId"] for a in new_parser(helpers).get()] == ["GHSA-abcd-efgh-ijkl"]

    def test_raw_input_saved(self, helpers, fake_github, auto_fake_fixdate_finder):
        fake_github()
        p = new_parser(helpers)
        list(p.get())
        with open(os.path.join(p.workspace.input_path, "repos", "netty_netty.json")) as fh:
            assert len(json.load(fh)) == 3

    def test_auth_header_only_with_token(self, helpers, auto_fake_fixdate_finder):
        p = new_parser(helpers, token="")
        assert "Authorization" not in p._headers()
        p.token = "abc"
        assert p._headers()["Authorization"] == "Bearer abc"

    @patch("time.sleep")
    def test_respects_rate_limit(self, mock_sleep, helpers, fake_github, auto_fake_fixdate_finder):
        headers = {"x-ratelimit-remaining": "5", "x-ratelimit-reset": str(int(time.time()) + 5)}
        fake_github({REPO_URL: make_response(body=[], headers=headers)})
        list(new_parser(helpers).get())
        mock_sleep.assert_called_once()


def run_provider(helpers, repos=("netty/netty",)):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    c = Config(token="secret", api_url=API, repos=list(repos))
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=c)
    urls, count = provider.update(None)
    return workspace, urls, count


def test_provider_schema(helpers, fake_github, auto_fake_fixdate_finder):
    fake_github()
    workspace, urls, count = run_provider(helpers)

    # GHSA-rmcw (java) + GHSA-abcd (java, npm); the merged advisory is excluded
    assert count == 3
    assert urls == [REPO_URL]
    assert workspace.result_schemas_valid(require_entries=True)


def test_provider_no_repos(helpers, fake_github, auto_fake_fixdate_finder):
    calls = fake_github({})
    _, urls, count = run_provider(helpers, repos=())
    assert count == 0
    assert urls == []
    assert calls == []


def test_provider_via_snapshot(helpers, fake_github, auto_fake_fixdate_finder):
    fake_github()
    workspace, _, _ = run_provider(helpers)
    workspace.assert_result_snapshots()
