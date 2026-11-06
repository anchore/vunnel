import os
import shutil
import subprocess
from unittest.mock import patch

import pytest

from vunnel import result, schema
from vunnel.providers.dhi import Config, Provider
from vunnel.providers.dhi.parser import Parser


def prepare_workspace(helpers):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    source = helpers.local_dir("test-fixtures/advisories")
    shutil.copytree(source, workspace.input_dir / "advisories", dirs_exist_ok=True)
    return workspace


def make_parser(workspace, **kwargs):
    config = Config()
    return Parser(
        ws=workspace,
        repository_url=config.repository_url,
        repository_branch=config.repository_branch,
        advisories_path=config.advisories_path,
        **kwargs,
    )


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_provider_schema(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = prepare_workspace(helpers)
    config = Config()
    config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=config)

    urls, count = provider.update(None)

    assert urls == [config.repository_url]
    assert count == 2
    assert workspace.num_result_entries() == 2
    assert workspace.result_schemas_valid(require_entries=True)


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_provider_via_snapshot(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = prepare_workspace(helpers)
    config = Config()
    config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=config)

    provider.update(None)

    workspace.assert_result_snapshots()


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_selects_only_dhi_records(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    # the fixture mirrors the published layout: year-sharded OSV records with .asc/.sha256 sidecars,
    # a non-DHI record, and a sibling dhi/vex tree, none of which may be read as advisories
    workspace = prepare_workspace(helpers)
    parser = make_parser(workspace)

    records = list(parser.get())

    assert [record[0] for record in records] == ["DHI-CVE-2016-2781-coreutils", "DHI-CVE-2017-18018-coreutils"]
    assert all(record[1] == "1.6.1" for record in records)


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_patches_fix_dates(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    workspace = prepare_workspace(helpers)
    parser = make_parser(workspace)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    # DHI records carry no fix dates, so the advisory published date is used as the (inaccurate) fallback
    alpine_range = records["DHI-CVE-2016-2781-coreutils"]["affected"][0]["ranges"][0]
    assert alpine_range["database_specific"]["anchore"]["fixes"] == [
        {"version": "9.11-r1", "date": "2026-07-29", "kind": "advisory"},
    ]
    debian_range = records["DHI-CVE-2017-18018-coreutils"]["affected"][0]["ranges"][0]
    assert debian_range["database_specific"]["anchore"]["fixes"] == [
        {"version": "9.7-3+dhi4", "date": "2026-07-29", "kind": "advisory"},
    ]


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_rejects_conflicting_duplicate_ids(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    workspace = prepare_workspace(helpers)
    advisories_dir = os.path.join(workspace.input_dir, "advisories", "dhi", "osv")
    os.makedirs(os.path.join(advisories_dir, "2027"))
    with open(os.path.join(advisories_dir, "2026", "DHI-CVE-2016-2781-coreutils.json")) as f:
        conflicting = f.read().replace("9.11-r1", "9.11-r2")
    with open(os.path.join(advisories_dir, "2027", "DHI-CVE-2016-2781-coreutils.json"), "w") as f:
        f.write(conflicting)
    parser = make_parser(workspace)

    with pytest.raises(ValueError, match="conflicting duplicate DHI advisory ID: DHI-CVE-2016-2781-coreutils"):
        list(parser.get())


@patch.object(Parser, "_record_source_revision")
def test_parser_skip_download_requires_checkout(mock_revision, helpers, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    parser = make_parser(workspace, skip_download=True)

    with pytest.raises(RuntimeError, match="DHI advisory checkout does not exist"):
        list(parser.get())


@patch.object(Parser, "_record_source_revision")
def test_parser_clone_failure_surfaces_stderr(mock_revision, helpers, auto_fake_fixdate_finder, caplog):
    workspace = helpers.provider_workspace_helper(name=Provider.name())
    parser = make_parser(workspace)
    error = subprocess.CalledProcessError(128, ["git", "clone"], stderr="fatal: repository not found\n")

    with patch("subprocess.run", side_effect=error), patch("vunnel.utils.time.sleep"), pytest.raises(RuntimeError, match="max retries"):
        list(parser.get())

    assert "fatal: repository not found" in caplog.text


@pytest.mark.parametrize("schema_version, expected", [("1.5.0", schema.OSVSchema("1.5.0")), ("1.6.1", schema.OSVSchema("1.6.1")), ("2.0.0", None)])
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


def test_default_advisories_path():
    assert Config().advisories_path == "dhi/osv"


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:apk/dhi/package?os_distro=alpine&os_name=dhi&os_version=3.24",
        "pkg:apk/dhi/package",
    ],
)
def test_validate_accepts_dhi_package_with_or_without_os_qualifiers(purl):
    record = {
        "id": "DHI-CVE-1234-package",
        "schema_version": "1.6.1",
        "affected": [{"package": {"name": "package", "ecosystem": "Docker Hardened Images:Alpine:3.24", "purl": purl}}],
    }
    assert Parser._validate(record) == ("DHI-CVE-1234-package", "1.6.1")


def test_validate_rejects_non_dhi_package():
    record = {
        "id": "DHI-CVE-1234-package",
        "schema_version": "1.6.1",
        "affected": [
            {
                "package": {
                    "name": "package",
                    "ecosystem": "Docker Hardened Images:Alpine:3.24",
                    "purl": "pkg:apk/alpine/package?os_name=dhi&os_version=3.24",
                },
            },
        ],
    }
    with pytest.raises(ValueError, match="non-DHI OS package PURL"):
        Parser._validate(record)
