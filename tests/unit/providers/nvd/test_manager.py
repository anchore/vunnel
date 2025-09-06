from __future__ import annotations

import datetime
import json

import pytest
from vunnel import workspace, schema
from vunnel.providers.nvd import manager
from vunnel.tool.fixdate.finder import Result


@pytest.mark.parametrize(
    "mock_data_path",
    [
        "test-fixtures/single-entry.json",
    ],
)
def test_parser(tmpdir, helpers, mock_data_path, mocker, auto_fake_fixdate_finder):
    mock_data_path = helpers.local_dir(mock_data_path)

    with open(mock_data_path) as f:
        json_dict = json.load(f)

    expected_vulns = []
    for v in json_dict["vulnerabilities"]:
        cve_id = v["cve"]["id"]
        year = cve_id.split("-")[1]
        identity = f"{year}/{cve_id}"
        expected_vulns.append((identity, v))

    subject = manager.Manager(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        schema=schema.NVDSchema(),
        overrides_url="http://example.com",
    )
    subject.api.cve = mocker.Mock(return_value=[json_dict])
    actual_vulns = list(subject.get(None))

    assert expected_vulns == actual_vulns
    for vuln in actual_vulns:
        assert subject._sqlite_reader().read(vuln[0].lower()) is not None


# sample date and result for testing
_fix_date = datetime.date(2024, 1, 15)
_fix_result = Result(date=_fix_date, kind="first-observed", version="2.3.1")


@pytest.mark.parametrize(
    ("fixdater_config", "record", "expected_record"),
    [
        pytest.param(
            None,
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="no-fixdater-returns-record-unchanged",
        ),
        pytest.param(
            [_fix_result],
            {
                "cve": {
                    "id": "CVE-2024-1234",
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                }
            },
            id="empty-configurations-returns-record-unchanged",
        ),
        pytest.param(
            [_fix_result],
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="no-versionEndExcluding-skips-fix-date-lookup",
        ),
        pytest.param(
            [_fix_result],
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="empty-versionEndExcluding-skips-fix-date-lookup",
        ),
        pytest.param(
            [_fix_result],
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "not-a-cpe",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "not-a-cpe",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="invalid-criteria-skips-fix-date-lookup",
        ),
        pytest.param(
            {
                ("CVE-2024-1234", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "2.3.1"): [_fix_result]
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                            "fix": {
                                                "version": "2.3.1",
                                                "date": "2024-01-15",
                                                "kind": "first-observed",
                                            },
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="valid-versionEndExcluding-with-fix-dates-adds-fix-information",
        ),
        pytest.param(
            {},  # empty responses
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="no-fix-dates-found-leaves-record-unchanged",
        ),
        pytest.param(
            {
                ("CVE-2024-1234", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "2.3.1"): [_fix_result]
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="vulnerable-false-skips-fix-date-lookup",
        ),
        pytest.param(
            {
                ("CVE-2024-1234", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "2.3.1"): [_fix_result]
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:other:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "87654321-4321-8765-cba9-210987654321",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "not-a-cpe",
                                            "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
                                            "versionEndExcluding": "1.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                            "versionEndExcluding": "2.3.1",
                                            "fix": {
                                                "version": "2.3.1",
                                                "date": "2024-01-15",
                                                "kind": "first-observed",
                                            },
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:other:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "87654321-4321-8765-cba9-210987654321",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "not-a-cpe",
                                            "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
                                            "versionEndExcluding": "1.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            },
            id="multiple-cpe-matches-with-mixed-scenarios",
        ),
    ],
)
def test_apply_fix_dates(tmpdir, fake_fixdate_finder, fixdater_config, record, expected_record):
    """test the _apply_fix_dates method with various configuration scenarios."""

    # create manager instance
    if fixdater_config is None:
        fixdater_instance = fake_fixdate_finder()
    else:
        fixdater_instance = fake_fixdate_finder(fixdater_config)

    manager_instance = manager.Manager(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        schema=schema.NVDSchema(),
        overrides_url="http://example.com",
        fixdater=fixdater_instance,
    )

    # apply fix dates
    actual_record = manager_instance._apply_fix_dates(
        cve_id=record["cve"]["id"],
        record=record,
    )

    # verify the result
    assert actual_record == expected_record
