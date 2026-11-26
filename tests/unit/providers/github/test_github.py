from __future__ import annotations

import json
import os

import pytest
import time
from unittest.mock import patch, Mock
from vunnel import result, workspace
from vunnel.providers.github import Config, Provider, parser
from vunnel.utils import fdb as db
from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics
from vunnel.tool import fixdate


@pytest.fixture(autouse=True)
def no_repo_advisory_downloads(monkeypatch):
    """the default config fetches repository advisories (e.g. ruby/ruby); never hit the network in tests"""
    monkeypatch.setattr(parser, "get_repo_advisories", lambda *a, **kw: [])


@pytest.fixture()
def ruby_repo_advisories():
    path = os.path.join(os.path.dirname(__file__), "test-fixtures", "ruby-repo-advisories.json")
    with open(path) as f:
        return json.load(f)


@pytest.fixture()
def fake_repo_advisories(monkeypatch):
    def apply(by_repo: dict[str, list[dict]]):
        calls = []

        def fake(repo, *a, **kw):
            calls.append(repo)
            return by_repo.get(repo, [])

        monkeypatch.setattr(parser, "get_repo_advisories", fake)
        return calls

    return apply


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
                            "cvssSeverities": {
                                "cvssV3": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                                "cvssV4": {
                                    "score": 9.8,
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
                                }
                            },
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
        "cvssSeverities": {
            "cvssV3": {
                "score": 9.8,
                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "cvssV4": {
                "score": 9.8,
                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
            }
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
    def test_no_such_attribute(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        with pytest.raises(AttributeError):
            result.foo

    def test_gets_classification(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        assert result["Classification"] == "GENERAL"
        assert result.Classification == "GENERAL"

    def test_gets_severity(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        assert result["Severity"] == "Critical"
        assert result.Severity == "Critical"

    def test_gets_cvss(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        expected = CVSS(
            version="3.0",
            vector_string="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_metrics=CVSSBaseMetrics(base_score=9.8, exploitability_score=3.9, impact_score=5.9, base_severity="Critical"),
            status="N/A",
        )

        assert result["CVSS"] == expected
        assert result.CVSS == expected

    def test_trailing_slash_cvss(self, node, helpers, auto_fake_fixdate_finder):
        node["cvssSeverities"]["cvssV3"]["vectorString"] = node["cvssSeverities"]["cvssV3"]["vectorString"] + "/"
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        expected = CVSS(
            version="3.0",
            vector_string="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_metrics=CVSSBaseMetrics(base_score=9.8, exploitability_score=3.9, impact_score=5.9, base_severity="Critical"),
            status="N/A",
        )

        assert result["CVSS"] == expected
        assert result.CVSS == expected

    def test_cvss_severities_contains_both_v3_and_v4(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()

        assert len(result["cvss_severities"]) == 2
        assert result["cvss_severities"][0] == {
            "version": "3.0",
            "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        assert result["cvss_severities"][1] == {
            "version": "4.0",
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
        }

    @pytest.mark.parametrize(
        ("cvss_input", "expected_count", "expected_version", "expect_legacy_cvss"),
        [
            pytest.param(
                {"cvssV3": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "cvssV4": None},
                1,
                "3.1",
                True,
                id="v3_only",
            ),
            pytest.param(
                {"cvssV3": None, "cvssV4": {"score": 7.1, "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}},
                1,
                "4.0",
                False,
                id="v4_only",
            ),
        ],
    )
    def test_cvss_severities_partial_data(self, node, helpers, auto_fake_fixdate_finder, cvss_input, expected_count, expected_version, expect_legacy_cvss):
        node["cvssSeverities"] = cvss_input
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()

        assert len(result["cvss_severities"]) == expected_count
        assert result["cvss_severities"][0]["version"] == expected_version
        assert ("CVSS" in result) == expect_legacy_cvss

    @pytest.mark.parametrize(
        ("vector", "expected_version", "expected_vector"),
        [
            pytest.param(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
                "4.0",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
                id="valid_v4",
            ),
            pytest.param(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/",
                "4.0",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
                id="trailing_slash",
            ),
        ],
    )
    def test_make_cvss_v4_valid(self, node, helpers, auto_fake_fixdate_finder, vector, expected_version, expected_vector):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        node_parser = parser.NodeParser(node, fixdater=fixdate.default_finder(ws))

        result = node_parser._make_cvss_v4(vector, "GHSA-test-1234")

        assert result == {"version": expected_version, "vector": expected_vector}

    @pytest.mark.parametrize(
        "vector",
        [
            pytest.param("invalid-vector", id="malformed"),
            pytest.param("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="wrong_version"),
        ],
    )
    def test_make_cvss_v4_invalid(self, node, helpers, auto_fake_fixdate_finder, vector):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        node_parser = parser.NodeParser(node, fixdater=fixdate.default_finder(ws))

        assert node_parser._make_cvss_v4(vector, "GHSA-test-1234") is None

    def test_references_captured(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()

        assert result["references"] == [
            {"url": "https://github.com/Pylons/waitress/security/advisories/GHSA-73m2-3pwg-5fgc"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-5236"},
        ]

    def test_references_defaults_to_empty_list(self, node, helpers, auto_fake_fixdate_finder):
        del node["references"]
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()

        assert result["references"] == []

    def test_gets_published(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        result["published"] = "2020-02-04T03:07:31Z"
        result.published = "2020-02-04T03:07:31Z"

    def test_gets_updated(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        result["updated"] = "2020-02-04T03:07:32Z"
        result.updated = "2020-02-04T03:07:32Z"

    def test_gets_withdrawn(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        result["withdrawn"] = "2020-02-04T03:07:33Z"
        result.withdrawn = "2020-02-04T03:07:33Z"

    def test_gets_fixedin(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        assert len(result["FixedIn"]) == 2

    def test_gets_multiple_fixedin(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        name = sorted([x["name"] for x in result["FixedIn"]])
        identifier = sorted([x["identifier"] for x in result["FixedIn"]])
        ecosystem = sorted([x["ecosystem"] for x in result["FixedIn"]])
        namespace = sorted([x["namespace"] for x in result["FixedIn"]])
        assert name == sorted(["waitress", "waitress"])
        assert identifier == sorted(["1.4.3", "None"])
        assert ecosystem == sorted(["go", "python"])
        assert namespace == sorted(["github:python", "github:go"])

    def test_fixedin_metadata(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        ranges = sorted([x["range"] for x in result["FixedIn"]])
        assert ranges == sorted([">= 1.2.0 < 1.4.2", "< 1.4.2"])

    def test_gets_summary(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        assert result.Summary == "Critical severity vulnerability that affects waitress"
        assert result["Summary"] == "Critical severity vulnerability that affects waitress"

    def test_gets_link(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        assert result.url == "https://github.com/advisories/GHSA-73m2-3pwg-5fgc"
        assert result["url"] == "https://github.com/advisories/GHSA-73m2-3pwg-5fgc"

    def test_gets_cve_only(self, node, helpers, auto_fake_fixdate_finder):
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
        assert set(result["Metadata"]["CVE"]) == {"CVE-2020-5236"}
        assert set(result.Metadata["CVE"]) == {"CVE-2020-5236"}

    def test_cves_arent_present(self, node, helpers, auto_fake_fixdate_finder):
        sans_cve_data = node.copy()
        sans_cve_data["identifiers"] = []
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(sans_cve_data, fixdater=fixdate.default_finder(ws)).parse()
        assert result.Metadata == {"CVE": []}

    def test_ecosystems_not_repeated(self, node, helpers, auto_fake_fixdate_finder):
        repeated = {"package": {"ecosystem": "PIP", "name": "waitress"}}
        node["vulnerabilities"]["nodes"].append(repeated)
        ws = helpers.provider_workspace_helper(name=Provider.name())
        result = parser.NodeParser(node, fixdater=fixdate.default_finder(ws)).parse()
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
    def test_get_with_no_cursor_no_timestamp(self, fake_get_query, tmpdir, empty_response, auto_fake_fixdate_finder):
        fake_get_query([empty_response])
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret")
        result = list(p.get())
        assert result == []

    def test_get_commits_timestamp(self, fake_get_query, tmpdir, empty_response, auto_fake_fixdate_finder):
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

    def test_get_commits_timestamp_with_cursors(self, advisories, fake_get_query, tmpdir, empty_response, auto_fake_fixdate_finder):
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

    def test_has_next_page(self, advisories, fake_get_query, tmpdir, empty_response, auto_fake_fixdate_finder):
        fake_get_query([empty_response, advisories(has_next_page=True)])
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret")
        result = list(p.get())
        assert len(result) == 1

    def test_has_next_page_with_advisories(self, advisories, fake_get_query, tmpdir, auto_fake_fixdate_finder):
        fake_get_query([advisories(), advisories(has_next_page=True)])
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret")
        result = list(p.get())
        assert len(result) == 2


def test_provider_schema(helpers, fake_get_query, advisories, auto_fake_fixdate_finder):
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


def test_provider_via_snapshot(helpers, fake_get_query, advisories, auto_fake_fixdate_finder):
    fake_get_query([advisories(), advisories(has_next_page=True)])
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(token="secret", api_url="https://localhost")
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=c)
    provider.update(None)

    workspace.assert_result_snapshots()


RUBY_SOURCE = parser.RepoAdvisorySource(repo="ruby/ruby", ecosystem="binary", package="ruby")


class TestSelectFixVersion:
    @pytest.mark.parametrize(
        ("version_range", "patched", "expected"),
        [
            ("<= 3.3.12", "3.3.13", "3.3.13"),
            # one patched-versions string covering two release lines: pick the one that fixes this range
            (">= 3.4.0, <= 3.4.11", "3.4.12, 4.0.0", "3.4.12"),
            (">= 3.4.0, <= 3.4.11", "4.0.0, 3.4.12", "3.4.12"),
            (">= 3.4.0, < 3.4.12", "3.4.12, 4.0.0", "3.4.12"),
            ("<= 3.3.12", "3.3.13, 3.4.12", "3.3.13"),
            # no usable upper bound: fall back to the first listed version
            (">= 1.0", "1.2, 2.0", "1.2"),
            ("All", "1.2, 2.0", "1.2"),
            ("<= 1.0", "", None),
            ("<= 1.0", None, None),
        ],
    )
    def test_select_fix_version(self, version_range, patched, expected):
        assert parser.select_fix_version(version_range, patched) == expected


class TestRepoAdvisoryToNode:
    def test_converts_ruby_advisory(self, ruby_repo_advisories, auto_fake_fixdate_finder):
        rest = next(a for a in ruby_repo_advisories if a["ghsa_id"] == "GHSA-gfj3-8wj9-qx8p")
        node = parser.repo_advisory_to_node(rest, RUBY_SOURCE)
        parsed = parser.NodeParser(
            node,
            fixdate.default_finder(None),
            ecosystem_override=RUBY_SOURCE.ecosystem,
            advisory_url=rest["html_url"],
        ).parse()

        assert parsed["ghsaId"] == "GHSA-gfj3-8wj9-qx8p"
        assert parsed["Severity"] == "Critical"
        assert parsed["Classification"] == "GENERAL"
        assert parsed["url"] == "https://github.com/ruby/ruby/security/advisories/GHSA-gfj3-8wj9-qx8p"
        assert parsed["references"] == [{"url": "https://github.com/ruby/ruby/security/advisories/GHSA-gfj3-8wj9-qx8p"}]
        assert parsed["CVE"] == []
        assert parsed.ecosystems == {"binary"}
        assert [(f["name"], f["ecosystem"], f["namespace"], f["range"], f["identifier"]) for f in parsed["FixedIn"]] == [
            ("ruby", "binary", "github:binary", "<= 3.3.12", "3.3.13"),
            ("ruby", "binary", "github:binary", ">= 3.4.0 <= 3.4.11", "3.4.12"),
        ]
        # null CVSS vectors from the REST API are dropped rather than emitted
        assert "cvss_severities" not in parsed

    def test_rest_fields(self):
        rest = {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "cve_id": "CVE-2026-0001",
            "html_url": "https://github.com/o/r/security/advisories/GHSA-xxxx-xxxx-xxxx",
            "summary": "s",
            "severity": "medium",
            "identifiers": [{"type": "GHSA", "value": "GHSA-xxxx-xxxx-xxxx"}],
            "published_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "withdrawn_at": None,
            "cvss_severities": {
                "cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
                "cvss_v4": {"vector_string": None, "score": None},
            },
            "vulnerabilities": [
                {"package": {"ecosystem": "", "name": "thing"}, "vulnerable_version_range": "< 2.0", "patched_versions": "2.0"},
                {"package": {"ecosystem": "", "name": "thing"}, "vulnerable_version_range": "", "patched_versions": "3.0"},
            ],
        }
        node = parser.repo_advisory_to_node(rest, parser.RepoAdvisorySource(repo="o/r", ecosystem="binary"))
        assert node["severity"] == "MODERATE"
        assert node["identifiers"][-1] == {"type": "CVE", "value": "CVE-2026-0001"}
        assert node["cvssSeverities"] == {
            "cvssV3": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        # entries without a range are dropped; the package name is kept when no override is configured
        assert node["vulnerabilities"]["nodes"] == [
            {
                "package": {"ecosystem": "", "name": "thing"},
                "firstPatchedVersion": {"identifier": "2.0"},
                "vulnerableVersionRange": "< 2.0",
            },
        ]

    def test_infers_ecosystem_per_entry_without_override(self, auto_fake_fixdate_finder):
        # the REST API reports GHSA ecosystems in lowercase; one advisory may span several ecosystems
        rest = {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "html_url": "https://github.com/o/r/security/advisories/GHSA-xxxx-xxxx-xxxx",
            "severity": "high",
            "vulnerabilities": [
                {"package": {"ecosystem": "maven", "name": "io.netty:netty-codec-http"}, "vulnerable_version_range": "<= 4.1.124.Final", "patched_versions": "4.1.125.Final"},
                {"package": {"ecosystem": "npm", "name": "thing"}, "vulnerable_version_range": "< 2.0", "patched_versions": "2.0"},
                {"package": {"ecosystem": "other", "name": "ignored"}, "vulnerable_version_range": "< 1.0", "patched_versions": "1.0"},
            ],
        }
        source = parser.RepoAdvisorySource(repo="o/r")
        node = parser.repo_advisory_to_node(rest, source)
        parsed = parser.NodeParser(node, fixdate.default_finder(None), ecosystem_override=source.syft_ecosystem).parse()

        assert parsed.ecosystems == {"java", "npm"}
        assert [(f["name"], f["namespace"], f["identifier"]) for f in parsed["FixedIn"]] == [
            ("io.netty:netty-codec-http", "github:java", "4.1.125.Final"),
            ("thing", "github:npm", "2.0"),
        ]


class TestParserRepoAdvisories:
    def test_yields_repo_advisories(self, fake_get_query, fake_repo_advisories, ruby_repo_advisories, tmpdir, empty_response, auto_fake_fixdate_finder):
        fake_get_query([empty_response])
        calls = fake_repo_advisories({"ruby/ruby": ruby_repo_advisories})
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret", repos=[RUBY_SOURCE])
        result = list(p.get())
        assert calls == ["ruby/ruby"]
        assert sorted(r["ghsaId"] for r in result) == ["GHSA-34m4-m9fh-gqp5", "GHSA-gfj3-8wj9-qx8p"]
        assert all(r.ecosystems == {"binary"} for r in result)

    def test_repo_advisories_not_persisted(self, fake_get_query, fake_repo_advisories, ruby_repo_advisories, tmpdir, empty_response, auto_fake_fixdate_finder):
        fake_get_query([empty_response])
        fake_repo_advisories({"ruby/ruby": ruby_repo_advisories})
        ws = workspace.Workspace(root=tmpdir.strpath, name="test", create=True)
        p = parser.Parser(ws, "secret", repos=[RUBY_SOURCE])
        list(p.get())
        assert list(db.connection(ws.input_path, serializer="json").get_all()) == []

    def test_global_advisory_wins(self, fake_get_query, fake_repo_advisories, advisories, tmpdir, auto_fake_fixdate_finder):
        # a repository advisory that GitHub has since reviewed into the global database (same GHSA ID)
        fake_get_query([advisories()])
        repo_copy = {
            "ghsa_id": "GHSA-mh6f-8j2x-4483",
            "html_url": "https://github.com/o/r/security/advisories/GHSA-mh6f-8j2x-4483",
            "severity": "low",
            "vulnerabilities": [{"package": {"ecosystem": "", "name": "x"}, "vulnerable_version_range": "< 1", "patched_versions": "1"}],
        }
        fake_repo_advisories({"o/r": [repo_copy]})
        source = parser.RepoAdvisorySource(repo="o/r", ecosystem="binary")
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret", repos=[source])
        result = list(p.get())
        assert [r["ghsaId"] for r in result] == ["GHSA-mh6f-8j2x-4483"]
        assert "binary" not in result[0].ecosystems

    def test_inferred_ecosystem(self, fake_get_query, fake_repo_advisories, tmpdir, empty_response, auto_fake_fixdate_finder):
        fake_get_query([empty_response])
        fake_repo_advisories(
            {
                "o/r": [
                    {
                        "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
                        "vulnerabilities": [{"package": {"ecosystem": "maven", "name": "g:a"}, "vulnerable_version_range": "< 1", "patched_versions": "1"}],
                    },
                    # nothing in a supported ecosystem: skipped rather than emitted without a namespace
                    {
                        "ghsa_id": "GHSA-bbbb-bbbb-bbbb",
                        "vulnerabilities": [{"package": {"ecosystem": "", "name": "x"}, "vulnerable_version_range": "< 1", "patched_versions": "1"}],
                    },
                ],
            },
        )
        source = parser.RepoAdvisorySource(repo="o/r")
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret", repos=[source])
        result = list(p.get())
        assert [(r["ghsaId"], r.ecosystems) for r in result] == [("GHSA-aaaa-aaaa-aaaa", {"java"})]

    def test_unsupported_advisories_logged_once_per_repo(self, fake_get_query, fake_repo_advisories, tmpdir, empty_response, auto_fake_fixdate_finder, caplog):
        fake_get_query([empty_response])
        other = [{"package": {"ecosystem": "other", "name": "x"}, "vulnerable_version_range": "< 1", "patched_versions": "1"}]
        fake_repo_advisories({"o/r": [{"ghsa_id": f"GHSA-{c}{c}{c}{c}-{c}{c}{c}{c}-{c}{c}{c}{c}", "vulnerabilities": other} for c in "abc"]})
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret", repos=[parser.RepoAdvisorySource(repo="o/r")])
        with caplog.at_level("WARNING"):
            assert list(p.get()) == []
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1
        assert "skipping 3 repository advisories from o/r" in warnings[0]

    def test_ghsa_ecosystem_name_in_config(self, fake_get_query, fake_repo_advisories, tmpdir, empty_response, auto_fake_fixdate_finder):
        fake_get_query([empty_response])
        fake_repo_advisories(
            {"o/r": [{"ghsa_id": "GHSA-aaaa-aaaa-aaaa", "vulnerabilities": [{"package": {"ecosystem": "", "name": "g:a"}, "vulnerable_version_range": "< 1", "patched_versions": "1"}]}]},
        )
        p = parser.Parser(workspace.Workspace(root=tmpdir.strpath, name="test", create=True), "secret", repos=[parser.RepoAdvisorySource(repo="o/r", ecosystem="maven")])
        assert [r.ecosystems for r in p.get()] == [{"java"}]


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("", None),
        ("binary", "binary"),
        ("java", "java"),
        ("go", "go"),
        # GHSA ecosystem names, in either case, map to their syft package type
        ("maven", "java"),
        ("MAVEN", "java"),
        ("pip", "python"),
        ("rubygems", "gem"),
    ],
)
def test_repo_source_syft_ecosystem(configured, expected):
    assert parser.RepoAdvisorySource(repo="o/r", ecosystem=configured).syft_ecosystem == expected


def test_provider_writes_repo_advisories(helpers, fake_get_query, fake_repo_advisories, ruby_repo_advisories, empty_response, auto_fake_fixdate_finder):
    fake_get_query([empty_response])
    fake_repo_advisories({"ruby/ruby": ruby_repo_advisories})
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(token="secret", api_url="https://localhost")
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=c)
    provider.update(None)

    assert workspace.result_schemas_valid(require_entries=True)
    written = sorted(os.path.basename(os.path.dirname(f)) + "/" + os.path.basename(f) for f in workspace.result_files())
    assert written == ["github:binary/ghsa-34m4-m9fh-gqp5.json", "github:binary/ghsa-gfj3-8wj9-qx8p.json"]


def test_provider_splits_inferred_ecosystems(helpers, fake_get_query, fake_repo_advisories, empty_response, auto_fake_fixdate_finder):
    # one repository advisory spanning two ecosystems is written once per ecosystem, each with only its own fixes
    fake_get_query([empty_response])
    fake_repo_advisories(
        {
            "o/r": [
                {
                    "ghsa_id": "GHSA-aaaa-aaaa-aaaa",
                    "html_url": "https://github.com/o/r/security/advisories/GHSA-aaaa-aaaa-aaaa",
                    "summary": "s",
                    "severity": "high",
                    "published_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-02T00:00:00Z",
                    "vulnerabilities": [
                        {"package": {"ecosystem": "maven", "name": "g:a"}, "vulnerable_version_range": "< 1.0", "patched_versions": "1.0"},
                        {"package": {"ecosystem": "npm", "name": "thing"}, "vulnerable_version_range": "< 2.0", "patched_versions": "2.0"},
                    ],
                },
            ],
        },
    )
    workspace = helpers.provider_workspace_helper(name=Provider.name())

    c = Config(token="secret", api_url="https://localhost", repos=[parser.RepoAdvisorySource(repo="o/r")])
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=c)
    provider.update(None)

    assert workspace.result_schemas_valid(require_entries=True)
    written = {}
    for f in workspace.result_files():
        with open(f) as fh:
            advisory = json.load(fh)["item"]["Advisory"]
        written[advisory["namespace"]] = [(fix["name"], fix["identifier"]) for fix in advisory["FixedIn"]]
    assert written == {"github:java": [("g:a", "1.0")], "github:npm": [("thing", "2.0")]}


def test_default_config_includes_ruby():
    assert parser.RepoAdvisorySource(repo="ruby/ruby", ecosystem="binary", package="ruby") in Config().repos
