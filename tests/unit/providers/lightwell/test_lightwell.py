import os
import zipfile
from unittest.mock import patch

import pytest
from vunnel import result, schema
from vunnel.providers.lightwell import Config, Provider
from vunnel.providers.lightwell.parser import Parser


def _mock_download(fixture_dir):
    """Return a side_effect that builds a zip from the test-fixture advisories."""

    def _download(url, dest, logger, **kwargs):
        with zipfile.ZipFile(dest, "w") as zf:
            advisories_dir = os.path.join(fixture_dir, "lightwell-osv", "advisories")
            for name in sorted(os.listdir(advisories_dir)):
                full = os.path.join(advisories_dir, name)
                zf.write(full, f"lightwell-osv-main/advisories/{name}")

    return _download


@patch("vunnel.providers.lightwell.parser.http.download_to_file")
def test_provider_schema(mock_download, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_download.side_effect = _mock_download(helpers.local_dir("test-fixtures"))
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    assert 3 == workspace.num_result_entries()
    assert workspace.result_schemas_valid(require_entries=True)


@patch("vunnel.providers.lightwell.parser.http.download_to_file")
def test_parser(mock_download, helpers, disable_get_requests, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_download.side_effect = _mock_download(helpers.local_dir("test-fixtures"))
    parser = Parser(ws=workspace, logger=None)
    vuln_tuples = list(parser.get())

    assert [v[0] for v in vuln_tuples] == [
        "RHLW-2026-25544e781d50b856",
        "RHLW-2026-403d1e66c95ef9bb",
        "RHLW-2026-821eaab8409c2a61",
    ]
    for _, vuln_schema, record in vuln_tuples:
        assert vuln_schema == "1.9.0"
        assert record["database_specific"]["anchore"]["record_type"] == "advisory"


@pytest.mark.parametrize(
    "schema_version,expected",
    [
        # records declare 1.9.0, but the Red Hat Lightwell ecosystem only validates against 1.9.2
        ("1.9.0", schema.OSVSchema(version="1.9.2")),
        ("1.9.2", schema.OSVSchema(version="1.9.2")),
        ("0.6.0", None),
        ("2.4.0", None),
    ],
)
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


@patch("vunnel.providers.lightwell.parser.http.download_to_file")
def test_provider_via_snapshot(mock_download, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    mock_download.side_effect = _mock_download(helpers.local_dir("test-fixtures"))
    c = Config()
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(root=workspace.root, config=c)
    p.update(None)

    workspace.assert_result_snapshots()
