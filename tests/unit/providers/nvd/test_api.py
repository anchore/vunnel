from __future__ import annotations

import json
from datetime import datetime

import pytest
from vunnel.providers.nvd import api
from vunnel.utils import http_wrapper as http


@pytest.fixture()
def simple_mock(mocker):
    subject = api.NvdAPI(api_key="secret", timeout=1)

    first_json_dict = {
        "totalResults": 1,
        "resultsPerPage": 2000,
        "startIndex": 0,
        "vulnerabilities": [{"test": "test"}],  # not real data obviously...
    }

    responses = [
        mocker.Mock(
            status_code=200,
            text=json.dumps(first_json_dict).encode("utf-8"),
        ),
    ]

    return mocker.patch.object(http, "get", side_effect=responses), [first_json_dict], subject


class TestAPI:
    def test_cve_no_api_key(self, simple_mock, mocker):
        mock, responses, subject = simple_mock
        subject.api_key = None

        vulnerabilities = list(subject.cve("CVE-2020-0000"))

        assert vulnerabilities == responses
        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                retries=10,
                params="cveId=CVE-2020-0000",
                headers={"content-type": "application/json"},
                timeout=1,
            ),
        ]

    def test_cve_single_cve(self, simple_mock, mocker):
        mock, responses, subject = simple_mock

        vulnerabilities = list(subject.cve("CVE-2020-0000"))

        assert vulnerabilities == responses
        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="cveId=CVE-2020-0000",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
        ]

    def test_cve_multi_page(self, mocker):
        subject = api.NvdAPI(api_key="secret", timeout=1)

        json_responses = [
            {
                "totalResults": 7,
                "resultsPerPage": 3,
                "startIndex": 0,
                "vulnerabilities": [
                    {"test-1": "test-1"},  # not real data obviously...
                    {"test-2": "test-2"},  # not real data obviously...
                    {"test-3": "test-3"},  # not real data obviously...
                ],
            },
            {
                "totalResults": 7,
                "resultsPerPage": 3,
                "startIndex": 3,
                "vulnerabilities": [
                    {"test-4": "test-4"},  # not real data obviously...
                    {"test-5": "test-5"},  # not real data obviously...
                    {"test-6": "test-6"},  # not real data obviously...
                ],
            },
            {
                "totalResults": 7,
                "resultsPerPage": 3,
                "startIndex": 6,
                "vulnerabilities": [
                    {"test-7": "test-7"},  # not real data obviously...
                ],
            },
        ]

        responses = []
        for json_response in json_responses:
            responses.append(
                mocker.Mock(
                    status_code=200,
                    text=json.dumps(json_response).encode("utf-8"),
                ),
            )

        mock = mocker.patch.object(http, "get", side_effect=responses)

        vulnerabilities = list(subject.cve())

        assert vulnerabilities == json_responses
        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="resultsPerPage=3&startIndex=3",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="resultsPerPage=3&startIndex=6",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
        ]

    def test_cve_pub_date_range(self, simple_mock, mocker):
        mock, responses, subject = simple_mock

        vulnerabilities = list(
            subject.cve(
                pub_start_date=datetime.fromisoformat("2019-12-04"),
                pub_end_date=datetime.fromisoformat("2019-12-05"),
            )
        )

        assert vulnerabilities
        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="pubStartDate=2019-12-04T00:00:00&pubEndDate=2019-12-05T00:00:00",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
        ]

    def test_cve_last_modified_date_range(self, simple_mock, mocker):
        mock, responses, subject = simple_mock

        vulnerabilities = list(
            subject.cve(
                last_mod_start_date=datetime.fromisoformat("2019-12-04"),
                last_mod_end_date=datetime.fromisoformat("2019-12-05"),
            )
        )

        assert vulnerabilities
        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="lastModStartDate=2019-12-04T00:00:00&lastModEndDate=2019-12-05T00:00:00",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
        ]

    def test_results_per_page(self, simple_mock, mocker):
        mock, responses, subject = simple_mock

        with pytest.raises(RuntimeError):
            list(subject.cve(results_per_page=2001))

        list(subject.cve(results_per_page=5))

        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                subject.logger,
                params="resultsPerPage=5",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
        ]

    def test_cve_history(self, simple_mock, mocker):
        mock, responses, subject = simple_mock

        changes = list(subject.cve_history("CVE-2020-0000"))

        assert changes
        assert mock.call_args_list == [
            mocker.call(
                "https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
                subject.logger,
                params="cveId=CVE-2020-0000",
                retries=10,
                headers={"content-type": "application/json", "apiKey": "secret"},
                timeout=1,
            ),
        ]
