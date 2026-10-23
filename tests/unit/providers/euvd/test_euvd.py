import json
import os

import pytest

from vunnel import result, workspace
from vunnel.providers import euvd
from vunnel.providers.euvd import manager


def test_normalize_record_full(helpers):
    raw_path = helpers.local_dir("test-fixtures/single-entry/example1.json")
    with open(raw_path) as f:
        raw = json.load(f)

    out = manager._normalize_record(raw)
    assert out is not None
    assert out["id"] == "EUVD-2026-26868"
    assert out["enisaUuid"] == "98fbb849-7215-3e29-8a2a-f3d444f9caf3"
    # newline-delimited string fields are split into proper arrays
    assert out["aliases"] == ["CVE-2026-7717"]
    assert out["references"] == [
        "https://vuldb.com/vuln/360893",
        "https://www.totolink.net/",
    ]
    # locale-formatted timestamp is converted to ISO-8601 with UTC tz
    assert out["datePublished"].startswith("2026-05-04T01:00:23")
    assert out["datePublished"].endswith("+00:00")
    # product/vendor pairs are zipped from the parallel arrays
    assert out["products"] == [
        {"vendor": "Totolink", "product": "WA300", "version": "5.2cu.7112_B20190227"},
    ]


def test_normalize_record_handles_missing_fields():
    raw = {
        "id": "EUVD-2026-26800",
        "description": "Missing fields entry",
        "datePublished": None,
        "dateUpdated": None,
        "baseScore": None,
        "baseScoreVersion": None,
        "baseScoreVector": None,
        "references": None,
        "aliases": None,
        "assigner": None,
        "epss": None,
        "enisaIdProduct": [],
        "enisaIdVendor": [],
    }
    out = manager._normalize_record(raw)
    assert out is not None
    assert out["aliases"] == []
    assert out["references"] == []
    assert out["datePublished"] is None
    assert out["dateUpdated"] is None
    assert out["products"] == []


def test_normalize_record_rejects_records_without_id_or_description():
    assert manager._normalize_record({"description": "no id"}) is None
    assert manager._normalize_record({"id": "EUVD-2026-1"}) is None
    assert manager._normalize_record({}) is None
    assert manager._normalize_record(None) is None


def test_normalize_record_zips_uneven_product_vendor_arrays():
    raw = {
        "id": "EUVD-2026-1",
        "description": "x",
        "enisaIdProduct": [
            {"product": {"name": "P1"}, "product_version": "1.0"},
            {"product": {"name": "P2"}, "product_version": ""},
        ],
        "enisaIdVendor": [
            {"vendor": {"name": "V1"}},
        ],
    }
    out = manager._normalize_record(raw)
    assert out["products"] == [
        {"vendor": "V1", "product": "P1", "version": "1.0"},
        {"vendor": None, "product": "P2", "version": None},
    ]


def test_split_newline_list_handles_array_input():
    assert manager._split_newline_list(["a", "b"]) == ["a", "b"]
    assert manager._split_newline_list("a\n\nb\n") == ["a", "b"]
    assert manager._split_newline_list("") == []
    assert manager._split_newline_list(None) == []


def test_normalize_timestamp_handles_unparseable_input():
    assert manager._normalize_timestamp("not a date") is None
    assert manager._normalize_timestamp("") is None
    assert manager._normalize_timestamp(None) is None


def test_manager_paginates_until_empty(tmpdir, mocker):
    pages = [
        {
            "total": 3,
            "items": [
                {
                    "id": "EUVD-2026-1",
                    "description": "first",
                    "datePublished": "May 1, 2026, 1:00:00 AM",
                    "dateUpdated": "May 1, 2026, 1:00:00 AM",
                    "aliases": "CVE-2026-1\n",
                    "references": "https://example.com/1\n",
                    "enisaIdProduct": [],
                    "enisaIdVendor": [],
                },
                {
                    "id": "EUVD-2026-2",
                    "description": "second",
                    "datePublished": "May 1, 2026, 2:00:00 AM",
                    "dateUpdated": "May 1, 2026, 2:00:00 AM",
                    "aliases": "CVE-2026-2\n",
                    "references": "https://example.com/2\n",
                    "enisaIdProduct": [],
                    "enisaIdVendor": [],
                },
            ],
        },
        {
            "total": 3,
            "items": [
                {
                    "id": "EUVD-2026-3",
                    "description": "third",
                    "datePublished": "May 1, 2026, 3:00:00 AM",
                    "dateUpdated": "May 1, 2026, 3:00:00 AM",
                    "aliases": "CVE-2026-3\n",
                    "references": "https://example.com/3\n",
                    "enisaIdProduct": [],
                    "enisaIdVendor": [],
                },
            ],
        },
    ]
    responses = [mocker.Mock(json=mocker.Mock(return_value=p)) for p in pages]
    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=responses)

    subject = manager.Manager(
        url="http://localhost/nowhere",
        workspace=workspace.Workspace(tmpdir, "test", create=True),
        page_size=2,
    )
    out = list(subject.get())
    assert [vid for vid, _ in out] == ["EUVD-2026-1", "EUVD-2026-2", "EUVD-2026-3"]


def test_provider_schema(helpers, disable_get_requests, mocker):
    ws = helpers.provider_workspace_helper(name=euvd.Provider.name())

    raw_path = helpers.local_dir("test-fixtures/valid-catalog-1.json")
    with open(raw_path) as f:
        catalog = json.load(f)
    # Two-page sequence: first page returns the 3-item catalogue, second is empty so
    # pagination terminates cleanly.
    pages = [catalog, {"total": catalog["total"], "items": []}]
    responses = [mocker.Mock(json=mocker.Mock(return_value=p)) for p in pages]
    mocker.patch("vunnel.utils.http_wrapper.get", side_effect=responses)

    cfg = euvd.Config()
    p = euvd.Provider(root=ws.root, config=cfg)
    p.config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p.update(None)

    assert ws.num_result_entries() == 3
    assert ws.result_schemas_valid(require_entries=True)
