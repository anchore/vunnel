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
        identity = f"{year}/{cve_id}".lower()
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


@pytest.mark.parametrize(
    ("overrides_enabled", "override_data", "expected_configurations"),
    [
        pytest.param(
            False,
            None,
            # original configurations with fix dates applied
            [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                    "versionEndExcluding": "2.0.0",
                                    "fix": {
                                        "date": "2024-03-10",
                                        "kind": "first-observed",
                                        "version": "2.0.0",
                                    },
                                }
                            ],
                        }
                    ]
                }
            ],
            id="overrides-disabled-no-changes",
        ),
        pytest.param(
            True,
            None,
            # no override data, original configurations with fix dates applied
            [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                    "versionEndExcluding": "2.0.0",
                                    "fix": {
                                        "date": "2024-03-10",
                                        "kind": "first-observed",
                                        "version": "2.0.0",
                                    },
                                }
                            ],
                        }
                    ]
                }
            ],
            id="overrides-enabled-no-override-data",
        ),
        pytest.param(
            True,
            {
                "cve": {
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            "versionEndExcluding": "3.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            },
            # override configurations applied with fix dates
            [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "3.0.0",
                                    "fix": {
                                        "date": "2024-03-10",
                                        "kind": "first-observed",
                                        "version": "3.0.0",
                                    },
                                }
                            ],
                        }
                    ]
                }
            ],
            id="overrides-enabled-with-valid-override-data",
        ),
        pytest.param(
            True,
            {"cve": {}},  # override without configurations
            # original configurations with fix dates applied
            [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "12345678-1234-5678-9abc-123456789012",
                                    "versionEndExcluding": "2.0.0",
                                    "fix": {
                                        "date": "2024-03-10",
                                        "kind": "first-observed",
                                        "version": "2.0.0",
                                    },
                                }
                            ],
                        }
                    ]
                }
            ],
            id="overrides-enabled-empty-override-configurations",
        ),
    ],
)
def test_get_main_nvd_download_path_applies_overrides(
    tmpdir, mocker, fake_fixdate_finder, overrides_enabled, override_data, expected_configurations
):
    """test that overrides are applied in the main NVD download path (_unwrap_records) and fix dates are always applied."""

    # configure fixdate finder to return specific fix dates
    fixdate_responses = {
        "CVE-2024-1234": [Result(date=datetime.date(2024, 3, 10), kind="first-observed")]
    }
    fixdater_instance = fake_fixdate_finder(responses=fixdate_responses)

    # mock NVD API response
    nvd_api_response = {
        "vulnerabilities": [
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
                                            "versionEndExcluding": "2.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    # create manager with overrides enabled/disabled
    manager_instance = manager.Manager(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        schema=schema.NVDSchema(),
        overrides_url="http://example.com/overrides.tar.gz",
        fixdater=fixdater_instance,
        overrides_enabled=overrides_enabled,
    )

    # mock API and override methods
    manager_instance.api.cve = mocker.Mock(return_value=[nvd_api_response])
    manager_instance.overrides.download = mocker.Mock()
    manager_instance.overrides.cve = mocker.Mock(return_value=override_data)

    # get results
    results = list(manager_instance.get(None))

    # verify override download was called only when enabled
    if overrides_enabled:
        manager_instance.overrides.download.assert_called_once()
    else:
        manager_instance.overrides.download.assert_not_called()

    # verify override lookup was called for each CVE in the main path
    if overrides_enabled:
        manager_instance.overrides.cve.assert_called_with("CVE-2024-1234")

    # verify configurations in results
    assert len(results) == 1
    record_id, record = results[0]
    assert record_id == "2024/cve-2024-1234"
    assert record["cve"]["configurations"] == expected_configurations

    # verify fix dates were applied regardless of override settings
    final_cpe_match = record["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
    assert "fix" in final_cpe_match, "Fix dates should be applied even when overrides are disabled"
    assert final_cpe_match["fix"]["date"] == "2024-03-10"
    assert final_cpe_match["fix"]["kind"] == "first-observed"




def test_get_overrides_disabled_no_override_calls(tmpdir, mocker, fake_fixdate_finder):
    """test that when overrides are disabled, no override methods are called, but fix dates are still applied."""

    # configure fixdate finder to return specific fix dates
    fixdate_responses = {
        "CVE-2024-1234": [Result(date=datetime.date(2024, 5, 20), kind="first-observed")]
    }
    fixdater_instance = fake_fixdate_finder(responses=fixdate_responses)

    # mock NVD API response
    nvd_api_response = {
        "vulnerabilities": [
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
                                            "versionEndExcluding": "2.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    # create manager with overrides DISABLED
    manager_instance = manager.Manager(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        schema=schema.NVDSchema(),
        overrides_url="http://example.com/overrides.tar.gz",
        fixdater=fixdater_instance,
        overrides_enabled=False,  # DISABLED
    )

    # mock API and override methods
    manager_instance.api.cve = mocker.Mock(return_value=[nvd_api_response])
    manager_instance.overrides.download = mocker.Mock()
    manager_instance.overrides.cves = mocker.Mock(return_value=[])
    manager_instance.overrides.cve = mocker.Mock(return_value=None)

    # mock SQLite reader (should not be used since no fix dates in this test)
    mock_reader = mocker.Mock()
    mock_reader.__enter__ = mocker.Mock(return_value=mock_reader)
    mock_reader.__exit__ = mocker.Mock(return_value=False)
    mock_reader.each = mocker.Mock(return_value=[])
    manager_instance._sqlite_reader = mocker.Mock(return_value=mock_reader)

    # get results
    results = list(manager_instance.get(None))

    # verify we get the original record with fix dates applied
    assert len(results) == 1
    record_id, record = results[0]
    assert record_id == "2024/cve-2024-1234"
    assert record["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] == "2.0.0"

    # verify override download and cves methods were not called, but cve() is still called
    # because _apply_override is always called, it just returns None when disabled
    manager_instance.overrides.download.assert_not_called()
    manager_instance.overrides.cves.assert_not_called()
    # Note: override.cve() is still called but returns None when disabled

    # verify fix dates were applied even though overrides are disabled
    final_cpe_match = record["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
    assert "fix" in final_cpe_match, "Fix dates should be applied even when overrides are disabled"
    assert final_cpe_match["fix"]["date"] == "2024-05-20"
    assert final_cpe_match["fix"]["kind"] == "first-observed"


def test_get_applies_both_overrides_and_fix_dates(tmpdir, mocker, fake_fixdate_finder):
    """test that both overrides and fix dates are applied together in the correct order."""

    # configure fixdate finder to return specific fix dates
    fixdate_responses = {
        "CVE-2024-1234": [Result(date=datetime.date(2024, 6, 15), kind="first-observed")],
        "CVE-99999-1234": [Result(date=datetime.date(2030, 6, 15), kind="first-observed")],
    }
    fixdater_instance = fake_fixdate_finder(responses=fixdate_responses)

    # mock NVD API response
    nvd_api_response = {
        "vulnerabilities": [
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
                                            "versionEndExcluding": "2.0.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    override_data = {
        # override data that changes versionEndExcluding
        "CVE-2024-1234": {
            "cve": {
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
                                        "versionEndExcluding": "3.0.0",  # override changes from 2.0.0 to 3.0.0
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        },
        # override data that synthesizes an entire record for CVE-99999-1234
        "CVE-99999-1234": {
            "_annotation": {
                "description": "this doesn't exist, create it",
            },
            "cve": {
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
                                        "versionEndExcluding": "3.0.0",  # override changes from 2.0.0 to 3.0.0
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        }
    }

    # create manager with both overrides and fix dates enabled
    manager_instance = manager.Manager(
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        schema=schema.NVDSchema(),
        overrides_url="http://example.com/overrides.tar.gz",
        fixdater=fixdater_instance,
        overrides_enabled=True,
    )

    # mock API and override methods
    manager_instance.api.cve = mocker.Mock(return_value=[nvd_api_response])
    manager_instance.overrides.download = mocker.Mock()
    manager_instance.overrides.cve = mocker.Mock(wraps=lambda cve_id: override_data.get(cve_id))
    manager_instance.overrides.cves = mocker.Mock(return_value = list(override_data.keys()))

    # spy on the internal methods to verify they're both called
    apply_override_spy = mocker.spy(manager_instance, '_apply_override')
    apply_fix_dates_spy = mocker.spy(manager_instance, '_apply_fix_dates')
    synthesize_nvd_record_from_override_spy = mocker.spy(manager_instance, '_synthesize_nvd_record_from_override')

    # get results
    results = list(manager_instance.get(None))

    # verify methods were called in expected ways
    synthesize_nvd_record_from_override_spy.assert_called_once_with("CVE-99999-1234")

    assert apply_override_spy.call_count == 2
    apply_override_spy.assert_has_calls([
        mocker.call(
            cve_id="CVE-2024-1234", 
            record=nvd_api_response["vulnerabilities"][0]
        ),
        mocker.call(
            cve_id="CVE-99999-1234", 
            record=synthesize_nvd_record_from_override_spy.spy_return
        )
    ])

    assert apply_fix_dates_spy.call_count == 2
    apply_fix_dates_spy.assert_has_calls([
        mocker.call(
            cve_id="CVE-2024-1234", 
            record=apply_override_spy.spy_return_list[0][1]
        ),
        mocker.call(
            cve_id="CVE-99999-1234", 
            record=synthesize_nvd_record_from_override_spy.spy_return
        )
    ])

    # verify the record passed to _apply_fix_dates has the override applied (3.0.0 not 2.0.0)
    assert apply_fix_dates_spy.spy_return_list[0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] == "3.0.0"
    assert len(results) == 2

    # verify final result for CVE-2024-1234 contains both override changes AND fix date information
    record_id, final_record = results[0]
    assert record_id == "2024/cve-2024-1234"

    # verify override was applied (version changed from 2.0.0 to 3.0.0)
    final_cpe_match = final_record["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
    assert final_cpe_match["versionEndExcluding"] == "3.0.0"

    # verify fix date was applied (should have "fix" field added)
    assert "fix" in final_cpe_match
    assert final_cpe_match["fix"]["date"] == "2024-06-15"
    assert final_cpe_match["fix"]["kind"] == "first-observed"

    # verify final result for CVE-99999-1234 has expected structure
    record_id, final_record = results[1]
    assert record_id == "99999/cve-99999-1234"
    assert final_record["cve"]["descriptions"] == [
        {
            "lang": "en",
            "value": "this doesn't exist, create it"
        }
    ]

    assert final_record["cve"]["sourceIdentifier"] == "anchore"
    assert final_record["cve"]["vulnStatus"] == "Reserved"

    assert final_record["cve"]["lastModified"]
    assert final_record["cve"]["published"]

    # verify override was applied (version changed from 2.0.0 to 3.0.0)
    final_cpe_match = final_record["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
    assert final_cpe_match["versionEndExcluding"] == "3.0.0"

    # verify fix date was applied (should have "fix" field added)
    assert "fix" in final_cpe_match
    assert final_cpe_match["fix"]["date"] == "2030-06-15"
    assert final_cpe_match["fix"]["kind"] == "first-observed"

    # verify override download and lookup were called
    manager_instance.overrides.download.assert_called_once()
    manager_instance.overrides.cve.assert_has_calls([
        mocker.call("CVE-2024-1234"), 
        mocker.call("CVE-99999-1234"),
    ])
