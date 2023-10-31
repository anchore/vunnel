from __future__ import annotations

import pytest
import time
from unittest.mock import patch, Mock
from vunnel import result, workspace
from vunnel.providers.github import Config, Provider, parser
from vunnel.utils import fdb as db
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics


@pytest.fixture()
def advisory():
    def apply(has_next_page=False):
        return {
            "data": {
                "securityAdvisory": {
                    "vulnerabilities": {
                        "pageInfo": {"hasNextPage": has_next_page, "endCursor": "Mg"},
                        "nodes": [
                            {
                                "package": {"ecosystem": "NPM", "name": "event-flow"},
                                "firstPatchedVersion": None,
                                "vulnerableVersionRange": "< 4.0.0",
                            },
                            {
                                "package": {"ecosystem": "NPM", "name": "event-stream"},
                                "firstPatchedVersion": {"identifier": "4.0.0"},
                                "vulnerableVersionRange": ">= 1.2.0, < 4.0.0",
                            },
                        ],
                    },
                },
            },
        }

    return apply


@pytest.fixture()
def advisories():
    def apply(has_next_page=False, vuln_has_next_page=False):
        return {
            "data": {
                "securityAdvisories": {
                    "nodes": [
                        {
                            "ghsaId": "GHSA-mh6f-8j2x-4483",
                            "summary": "Critical severity vulnerability that affects flatmap-stream and event-stream",
                            "severity": "CRITICAL",
                            "cvss": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                            "identifiers": [{"type": "GHSA", "value": "GHSA-mh6f-8j2x-4483"}],
                            "references": [{"url": "https://github.com/dominictarr/event-stream/issues/116"}],
                            "vulnerabilities": {
                                "pageInfo": {
                                    "endCursor": "Mg",
                                    "hasNextPage": vuln_has_next_page,
                                },
                                "nodes": [
                                    {
                                        "package": {
                                            "ecosystem": "NPM",
                                            "name": "flatmap-stream",
                                        },
                                        "firstPatchedVersion": None,
                                        "advisory": {"ghsaId": "GHSA-mh6f-8j2x-4483"},
                                    },
                                    {
                                        "package": {
                                            "ecosystem": "NPM",
                                            "name": "event-stream",
                                        },
                                        "firstPatchedVersion": {"identifier": "4.0.0"},
                                        "advisory": {"ghsaId": "GHSA-mh6f-8j2x-4483"},
                                    },
                                    {
                                        "package": {
                                            "ecosystem": "MAVEN",
                                            "name": "org.webjars.npm:jquery",
                                        },
                                        "firstPatchedVersion": {"identifier": "1.9.0"},
                                        "vulnerableVersionRange": ">= 1.7.1, <= 1.8.3",
                                    },
                                ],
                            },
                            "publishedAt": "2018-11-26T23:58:21Z",
                            "updatedAt": "2023-01-12T05:08:40Z",
                            "withdrawnAt": None,
                        },
                    ],
                    "pageInfo": {
                        "endCursor": "Y3Vyc29yOnYyOpK5MjAxOS0wMi0yMFQyMjoyOToxNi0wODowMM0D7w==",
                        "hasNextPage": has_next_page,
                        "hasPreviousPage": False,
                        "startCursor": "Y3Vyc29yOnYyOpK5MjAxOS0wMi0yMFQyMjoyOToxNi0wODowMM0D7w==",
                    },
                },
            },
        }

    return apply


@pytest.fixture()
def empty_response():
    return {
        "data": {
            "securityAdvisories": {
                "nodes": [],
                "pageInfo": {
                    "endCursor": None,
                    "hasNextPage": False,
                    "hasPreviousPage": False,
                    "startCursor": None,
                },
            },
        },
    }


@pytest.fixture()
def node():
    return {
        "ghsaId": "GHSA-73m2-3pwg-5fgc",
        "classification": "GENERAL",
        "summary": "Critical severity vulnerability that affects waitress",
        "severity": "CRITICAL",
        "cvss": {
            "score": 9.8,
            "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "publishedAt": "2020-02-04T03:07:31Z",
        "updatedAt": "2020-02-04T03:07:32Z",
        "withdrawnAt": "2020-02-04T03:07:33Z",
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-73m2-3pwg-5fgc"},
            {"type": "CVE", "value": "CVE-2020-5236"},
        ],
        "references": [
            {"url": "https://github.com/Pylons/waitress/security/advisories/GHSA-73m2-3pwg-5fgc"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-5236"},
        ],
        "vulnerabilities": {
            "pageInfo": {"endCursor": "MQ", "hasNextPage": False},
            "nodes": [
                {
                    "package": {"ecosystem": "PIP", "name": "waitress"},
                    "firstPatchedVersion": {"identifier": "1.4.3"},
                    "vulnerableVersionRange": ">= 1.2.0, < 1.4.2",
                },
                {
                    "package": {"ecosystem": "GO", "name": "waitress"},
                    "firstPatchedVersion": None,
                    "vulnerableVersionRange": "< 1.4.2",
                },
                # RPM ecosystem is unknown, which will cause this vuln to be skipped
                {
                    "package": {"ecosystem": "RPM", "name": "waitress"},
                    "firstPatchedVersion": None,
                    "vulnerableVersionRange": "< 1.4.2",
                },
            ],
        },
    }


@pytest.fixture()
def fake_get_query(monkeypatch):
    def apply(return_values):
        responses = Capture(return_values=return_values)
        monkeypatch.setattr(parser, "get_query", responses)
        return responses

    return apply


class TestNodeParser:
    def test_no_such_attribute(self, node):
        result = parser.NodeParser(node).parse()
        with pytest.raises(AttributeError):
            result.foo

    def test_gets_classification(self, node):
        result = parser.NodeParser(node).parse()
        assert result["Classification"] == "GENERAL"
        assert result.Classification == "GENERAL"

    def test_gets_severity(self, node):
        result = parser.NodeParser(node).parse()
        assert result["Severity"] == "Critical"
        assert result.Severity == "Critical"

    def test_gets_cvss(self, node):
        result = parser.NodeParser(node).parse()
        expected = CVSS(
            version="3.0",
            vector_string="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_metrics=CVSSBaseMetrics(base_score=9.8, exploitability_score=3.9, impact_score=5.9, base_severity="Critical"),
            status="N/A",
        )

        assert result["CVSS"] == expected
        assert result.CVSS == expected

    def test_trailing_slash_cvss(self, node):
        node["cvss"]["vectorString"] = node["cvss"]["vectorString"] + "/"
        result = parser.NodeParser(node).parse()
        expected = CVSS(
            version="3.0",
            vector_string="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_metrics=CVSSBaseMetrics(base_score=9.8, exploitability_score=3.9, impact_score=5.9, base_severity="Critical"),
            status="N/A",
        )

        assert result["CVSS"] == expected
        assert result.CVSS == expected

    def test_gets_published(self, node):
        result = parser.NodeParser(node).parse()
        result["published"] = "2020-02-04T03:07:31Z"
        result.published = "2020-02-04T03:07:31Z"

    def test_gets_updated(self, node):
        result = parser.NodeParser(node).parse()
        result["updated"] = "2020-02-04T03:07:32Z"
        result.updated = "2020-02-04T03:07:32Z"

    def test_gets_withdrawn(self, node):
        result = parser.NodeParser(node).parse()
        result["withdrawn"] = "2020-02-04T03:07:33Z"
        result.withdrawn = "2020-02-04T03:07:33Z"

    def test_gets_fixedin(self, node):
        result = parser.NodeParser(node).parse()
        assert len(result["FixedIn"]) == 2

    def test_gets_multiple_fixedin(self, node):
        result = parser.NodeParser(node).parse()
        name = sorted([x["name"] for x in result["FixedIn"]])
        identifier = sorted([x["identifier"] for x in result["FixedIn"]])
        ecosystem = sorted([x["ecosystem"] for x in result["FixedIn"]])
        namespace = sorted([x["namespace"] for x in result["FixedIn"]])
        assert name == sorted(["waitress", "waitress"])
        assert identifier == sorted(["1.4.3", "None"])
        assert ecosystem == sorted(["go", "python"])
        assert namespace == sorted(["github:python", "github:go"])

    def test_fixedin_metadata(self, node):
        result = parser.NodeParser(node).parse()
        ranges = sorted([x["range"] for x in result["FixedIn"]])
        assert ranges == sorted([">= 1.2.0 < 1.4.2", "< 1.4.2"])

    def test_gets_summary(self, node):
        result = parser.NodeParser(node).parse()
        assert result.Summary == "Critical severity vulnerability that affects waitress"
        assert result["Summary"] == "Critical severity vulnerability that affects waitress"

    def test_gets_link(self, node):
        result = parser.NodeParser(node).parse()
        assert result.url == "https://github.com/advisories/GHSA-73m2-3pwg-5fgc"
        assert result["url"] == "https://github.com/advisories/GHSA-73m2-3pwg-5fgc"

    def test_gets_cve_only(self, node):
        result = parser.NodeParser(node).parse()
        assert set(result["Metadata"]["CVE"]) == {"CVE-2020-5236"}
        assert set(result.Metadata["CVE"]) == {"CVE-2020-5236"}

    def test_cves_arent_present(self, node):
        sans_cve_data = node.copy()
        sans_cve_data["identifiers"] = []
        result = parser.NodeParser(sans_cve_data).parse()
        assert result.Metadata == {"CVE": []}

    def test_ecosystems_not_repeated(self, node):
        repeated = {"package": {"ecosystem": "PIP", "name": "waitress"}}
        node["vulnerabilities"]["nodes"].append(repeated)
        result = parser.NodeParser(node).parse()
        assert result.ecosystems == {"go", "python"}


class TestCreateGraphQLQuery:
    def test_no_cursor_no_timestamp(self):
        # a.k.a. first query ever
        result = parser.graphql_advisories()
        line = result.split("\n")[2].strip()
        assert (
            line
            == "securityAdvisories(orderBy: {field: PUBLISHED_AT, direction: ASC}, classifications: [GENERAL, MALWARE], first: 100) {"
        )

    def test_no_cursor_with_timestamp_changes_field(self):
        # first run after a successful run
        result = parser.graphql_advisories(timestamp="2019-02-06T20:44:12.371565")
        line = result.split("\n")[2].strip()
        assert line.startswith("securityAdvisories(orderBy: {field: UPDATED_AT, direction: ASC}")

    def test_no_cursor_with_timestamp_adds_updatedsince(self):
        result = parser.graphql_advisories(timestamp="2019-02-06T20:44:12.371565")
        line = result.split("\n")[2].strip().split("}")[-1]
        assert line == ', updatedSince: "2019-02-06T20:44:12.371565", classifications: [GENERAL, MALWARE], first: 100) {'

    def test_cursor_no_timestamp(self):
        # subsequent request in the first run ever: no timestamp has been recorded
        # because this is the first run that hasn't completed
        result = parser.graphql_advisories(cursor="FXXF==")
        line = result.split("\n")[2].strip()
        assert (
            line
            == 'securityAdvisories(orderBy: {field: PUBLISHED_AT, direction: ASC}, after: "FXXF==", classifications: [GENERAL, MALWARE], first: 100) {'
        )

    def test_cursor_with_timestamp(self):
        # subsequent request after a successful run(s) because a timestamp has
        # been recorded
        result = parser.graphql_advisories(cursor="FXXF==", timestamp="2019-02-06T20:44:12.371565")
        line = result.split("\n")[2].strip()
        line = line.split("}")[-1]
        assert (
            line
            == ', after: "FXXF==", updatedSince: "2019-02-06T20:44:12.371565", classifications: [GENERAL, MALWARE], first: 100) {'
        )

    def test_cursor_with_timestamp_changes_field(self):
        # subsequent request after a successful run(s) because a timestamp has
        # been recorded
        result = parser.graphql_advisories(cursor="FXXF==", timestamp="2019-02-06T20:44:12.371565")
        line = result.split("\n")[2].strip()
        line = line.split("}")[0]
        assert line == "securityAdvisories(orderBy: {field: UPDATED_AT, direction: ASC"


class TestNeedsSubquery:
    def test_has_cursor(self, node):
        node["vulnerabilities"]["pageInfo"]["hasNextPage"] = True
        assert parser.needs_subquery(node) == "MQ"

    def test_has_no_cursor(self, node):
        assert parser.needs_subquery(node) is False


# TODO: move this out to a conftest.py file, it is going to be useful in other tests


class Capture:
    def __init__(self, *a, **kw):
        self.a = a
        self.kw = kw
        self.calls = []
        self.return_values = kw.get("return_values", False)
        self.always_returns = kw.get("always_returns", False)

    def __call__(self, *a, **kw):
        self.calls.append({"args": a, "kwargs": kw})
        if self.always_returns:
            return self.always_returns
        if self.return_values:
            return self.return_values.pop()
        return None


class TestGetNestedVulnerabilities:
    def test_paginates_with_cursor(self, empty_response, advisories, fake_get_query):
        # first and second responses have 2 vulns and indicates there is a next page. The
        # third response has 2 more vulns and no more pages
        responses = [advisories(), advisories(False, True)]
        fake_get_query(return_values=responses)
        result = parser.get_vulnerabilities("secret", "GHSA-mh6f-8j2x-4483", "2019", "vulncursor", "CurSor")
        # should retrieve 2 vulnerabilities on each request, total of 6
        assert len(result) == 6

    def test_paginates_vulncursor_does_not_match(self, advisories, fake_get_query):
        # request goes out, comes back but the ghsaId doesn't match, no new
        # vulnerabilities are added
        responses = [advisories(False, True)]
        fake_get_query(return_values=responses)
        result = parser.get_vulnerabilities("secret", "ghsa-aaaa", "2019", "vulncursor", "CurSor")
        assert len(result) == 0

    def test_paginates_with_cursor_empty(self, advisories, fake_get_query):
        responses = [advisories(False, False)]
        fake_get_query(return_values=responses)
        result = parser.get_vulnerabilities("secret", "GHSA-mh6f-8j2x-4483", "2019", "vulncursor", "CurSor")
        # should retrieve 1 response with 3 vulnerabilities from the first
        # request even though there isn't another cursor
        assert len(result) == 3

    def test_no_vulns_no_cursor(self, advisory, fake_get_query):
        advisory = advisory(False)
        advisory["data"]["securityAdvisory"]["vulnerabilities"]["nodes"] = []
        responses = [advisory]
        fake_get_query(return_values=responses)
        result = parser.get_vulnerabilities("secret", "GHSA-mh6f-8j2x-4483", "2019", "vulncursor", "CurSor")
        assert len(result) == 0


class TestParser:
    def test_get_with_no_cursor_no_timestamp(self, fake_get_query, tmpdir, empty_response):
        fake_get_query([empty_response])
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret")
        result = list(p.get())
        assert result == []

    def test_get_commits_timestamp(self, fake_get_query, tmpdir, empty_response):
        fake_get_query([empty_response])
        ws = workspace.Workspace(root=tmpdir.strpath, name="test", create=True)
        p = parser.Parser(ws, "secret")
        for _i in p.get():
            pass
        database = db.connection(ws.input_path)
        metadata = database.get_metadata()
        timestamp = metadata.data["timestamp"]
        assert isinstance(timestamp, str)
        assert timestamp.endswith("Z") or timestamp.endswith("+00:00")

    def test_get_commits_timestamp_with_cursors(self, advisories, fake_get_query, tmpdir, empty_response):
        fake_get_query([empty_response, advisories(has_next_page=True)])
        ws = workspace.Workspace(root=tmpdir.strpath, name="test", create=True)
        p = parser.Parser(ws, "secret")
        for _i in p.get():
            pass
        database = db.connection(ws.input_path)
        metadata = database.get_metadata()
        timestamp = metadata.data["timestamp"]
        assert isinstance(timestamp, str)
        assert timestamp.endswith("Z") or timestamp.endswith("+00:00")

    def test_has_next_page(self, advisories, fake_get_query, tmpdir, empty_response):
        fake_get_query([empty_response, advisories(has_next_page=True)])
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret")
        result = list(p.get())
        assert len(result) == 1

    def test_has_next_page_with_advisories(self, advisories, fake_get_query, tmpdir):
        fake_get_query([advisories(), advisories(has_next_page=True)])
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret")
        result = list(p.get())
        assert len(result) == 2


def test_provider_schema(helpers, fake_get_query, advisories):
    fake_get_query([advisories(), advisories(has_next_page=True)])
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(token="secret", api_url="https://localhost")
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=c)
    provider.update(None)

    assert workspace.result_schemas_valid(require_entries=True)


@patch("time.sleep")
@patch("requests.post")
def test_provider_respects_github_rate_limit(mock_post, mock_sleep):
    response = Mock()
    in_five_seconds = int(time.time()) + 5
    response.headers = {"x-ratelimit-remaining": 9, "x-ratelimit-reset": in_five_seconds}
    response.status_code = 200
    mock_post.return_value = response

    def mock_json():
        return "{}"

    def mock_raise_for_status():
        pass

    response.json = mock_json
    response.raise_for_status = mock_raise_for_status
    parser.get_query("some-token", "some-query")
    mock_sleep.assert_called_once()


@patch("time.sleep")
@patch("requests.post")
def test_provider_respects_github_rate_limit(mock_post, mock_sleep):
    response = Mock()
    in_five_seconds = int(time.time()) + 5
    response.headers = {"x-ratelimit-remaining": 11, "x-ratelimit-reset": in_five_seconds}
    response.status_code = 200
    mock_post.return_value = response

    def mock_json():
        return "{}"

    def mock_raise_for_status():
        pass

    response.json = mock_json
    response.raise_for_status = mock_raise_for_status
    parser.get_query("some-token", "some-query")
    mock_sleep.assert_not_called()


def test_provider_via_snapshot(helpers, fake_get_query, advisories):
    fake_get_query([advisories(), advisories(has_next_page=True)])
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(token="secret", api_url="https://localhost")
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=c)
    provider.update(None)

    workspace.assert_result_snapshots()
