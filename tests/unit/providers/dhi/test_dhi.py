import json
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
        compatible_schema=Provider.compatible_schema,
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
    assert count == 3
    assert workspace.num_result_entries() == 3
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

    assert [record[0] for record in records] == [
        "DHI-CVE-2016-2781-coreutils",
        "DHI-CVE-2017-18018-coreutils",
        "DHI-de24-slch-2lnk-uslp",
    ]
    assert all(record[1] == schema.OSVSchema("1.6.1") for record in records)


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
def test_parser_emits_withdrawn_record_without_affected_packages(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    # upstream publishes a withdrawn advisory with a withdrawn timestamp and no affected key
    workspace = prepare_workspace(helpers)
    parser = make_parser(workspace)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    withdrawn = records["DHI-de24-slch-2lnk-uslp"]
    assert withdrawn["withdrawn"] == "2026-11-13T20:35:26Z"
    assert "affected" not in withdrawn


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_emits_withdrawn_record_with_null_affected(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    workspace = prepare_workspace(helpers)
    path = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026", "DHI-de24-slch-2lnk-uslp.json")
    with open(path) as f:
        record = json.load(f)
    record["affected"] = None
    record["aliases"] = None
    with open(path, "w") as f:
        json.dump(record, f)
    parser = make_parser(workspace)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    withdrawn = records["DHI-de24-slch-2lnk-uslp"]
    assert withdrawn["withdrawn"] == "2026-11-13T20:35:26Z"
    assert withdrawn["affected"] is None


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_emits_withdrawn_record_with_affected_packages(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    workspace = prepare_workspace(helpers)
    path = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026", "DHI-CVE-2016-2781-coreutils.json")
    with open(path) as f:
        record = json.load(f)
    record["withdrawn"] = "2026-08-01T00:00:00Z"
    with open(path, "w") as f:
        json.dump(record, f)
    parser = make_parser(workspace)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    withdrawn = records["DHI-CVE-2016-2781-coreutils"]
    assert withdrawn["withdrawn"] == "2026-08-01T00:00:00Z"
    assert withdrawn["affected"][0]["ranges"][0]["database_specific"]["anchore"]["fixes"] == [
        {"version": "9.11-r1", "date": "2026-07-29", "kind": "advisory"},
    ]


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_keeps_first_of_conflicting_duplicate_ids(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, caplog):
    workspace = prepare_workspace(helpers)
    advisories_dir = os.path.join(workspace.input_dir, "advisories", "dhi", "osv")
    os.makedirs(os.path.join(advisories_dir, "2027"))
    with open(os.path.join(advisories_dir, "2026", "DHI-CVE-2016-2781-coreutils.json")) as f:
        conflicting = f.read().replace("9.11-r1", "9.11-r2")
    with open(os.path.join(advisories_dir, "2027", "DHI-CVE-2016-2781-coreutils.json"), "w") as f:
        f.write(conflicting)
    parser = make_parser(workspace)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    assert len(records) == 3
    events = records["DHI-CVE-2016-2781-coreutils"]["affected"][0]["ranges"][0]["events"]
    assert {"fixed": "9.11-r1"} in events
    assert parser.skipped == 1
    assert "DHI-CVE-2016-2781-coreutils conflicts with a record of the same id that was already emitted" in caplog.text


@pytest.mark.parametrize(
    "content, reason",
    [
        ('{"id": "DHI-bad-record", "affected": []}', "DHI-bad-record has no schema_version"),
        ('{"id": "DHI-bad-record", "schema_version": "2.0.0"}', "DHI-bad-record uses unsupported OSV schema version 2.0.0"),
        ('{"id": "DHI-bad-record", ', "dhi/osv/2026/DHI-bad-record.json is not valid JSON"),
        (
            '{"id": "DHI-bad-record", "schema_version": "1.6.1", "affected": [null]}',
            "DHI-bad-record has an affected package that is not an OSV object",
        ),
        (
            '{"id": "DHI-bad-record", "schema_version": "1.6.1", "affected": [{"package": null}]}',
            "DHI-bad-record has an affected package that is not an OSV object",
        ),
        (
            '{"id": "DHI-bad-record", "schema_version": "1.6.1", "affected": [{"package": {"name": "p", "ecosystem": "Docker Hardened Images:Alpine:3.24"}, "ranges": null}]}',
            "DHI-bad-record has an affected package that is not an OSV object",
        ),
    ],
)
@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_skips_invalid_record_and_emits_the_rest(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, caplog, content, reason):
    workspace = prepare_workspace(helpers)
    path = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026", "DHI-bad-record.json")
    with open(path, "w") as f:
        f.write(content)
    parser = make_parser(workspace)

    records = list(parser.get())

    assert [record[0] for record in records] == [
        "DHI-CVE-2016-2781-coreutils",
        "DHI-CVE-2017-18018-coreutils",
        "DHI-de24-slch-2lnk-uslp",
    ]
    assert parser.skipped == 1
    assert "skipping DHI record" in caplog.text
    assert reason in caplog.text


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_provider_skips_unsupported_schema_version(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, disable_get_requests):
    workspace = prepare_workspace(helpers)
    path = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026", "DHI-de24-slch-2lnk-uslp.json")
    with open(path) as f:
        record = json.load(f)
    record["schema_version"] = "2.0.0"
    with open(path, "w") as f:
        json.dump(record, f)
    config = Config()
    config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=config)

    # the provider logger is asserted directly: other tests reconfigure logging, so caplog does not always see it
    with patch.object(provider.logger, "warning") as warning:
        _, count = provider.update(None)

    assert count == 2
    warnings = [call.args[0] for call in warning.call_args_list]
    assert "skipping DHI record: DHI-de24-slch-2lnk-uslp uses unsupported OSV schema version 2.0.0" in warnings
    assert "skipped 1 DHI records, each with a warning above" in warnings


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
    "package",
    [
        {"name": "package", "ecosystem": "Docker Hardened Images:Alpine:3.24", "purl": "pkg:apk/dhi/package?os_name=dhi&os_version=3.24"},
        {"name": "package", "ecosystem": "Alpine:3.24", "purl": "pkg:apk/dhi/package"},
        {"name": "package", "ecosystem": "Docker Hardened Images:Alpine:3.24", "purl": "pkg:apk/alpine/package"},
        {"name": "package", "ecosystem": "Docker Hardened Images:Alpine:3.24", "purl": "not-a-purl"},
        {"name": "package", "ecosystem": "Docker Hardened Images:Alpine:3.24"},
    ],
)
@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_passes_affected_packages_through_as_published(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, package):
    # the provider does not judge an affected package: the consumer of the record decides what it means
    workspace = prepare_workspace(helpers)
    path = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026", "DHI-any-package.json")
    record = {"id": "DHI-any-package", "schema_version": "1.6.1", "affected": [{"package": package, "versions": ["1.0-r0"]}]}
    with open(path, "w") as f:
        json.dump(record, f)
    parser = make_parser(workspace)

    records = {vuln_id: emitted for vuln_id, _, emitted in parser.get()}

    assert records["DHI-any-package"]["affected"] == record["affected"]
    assert parser.skipped == 0


@pytest.mark.parametrize("first", ['{"id": "DHI-twice"}', '{"id": "DHI-twice", "schema_version": "2.0.0"}'])
@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_skipped_record_does_not_block_a_later_record_with_its_id(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, first):
    workspace = prepare_workspace(helpers)
    advisories_dir = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026")
    with open(os.path.join(advisories_dir, "DHI-twice-a.json"), "w") as f:
        f.write(first)
    with open(os.path.join(advisories_dir, "DHI-twice-b.json"), "w") as f:
        f.write('{"id": "DHI-twice", "schema_version": "1.6.1"}')
    parser = make_parser(workspace)

    records = {vuln_id: record for vuln_id, _, record in parser.get()}

    assert records["DHI-twice"] == {"id": "DHI-twice", "schema_version": "1.6.1"}
    assert parser.skipped == 1


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_parser_counts_skips_for_one_run(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder):
    # a provider retry calls get() again on the same parser, and its count must not include the earlier attempt
    workspace = prepare_workspace(helpers)
    path = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026", "DHI-bad-record.json")
    with open(path, "w") as f:
        f.write('{"id": "DHI-bad-record"}')
    parser = make_parser(workspace)

    list(parser.get())
    list(parser.get())

    assert parser.skipped == 1


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_provider_fails_when_every_record_is_skipped(mock_revision, mock_clone, helpers, auto_fake_fixdate_finder, disable_get_requests):
    # one skipped record is tolerated, but a feed with no usable record must not pass as a successful run
    workspace = prepare_workspace(helpers)
    advisories_dir = os.path.join(workspace.input_dir, "advisories", "dhi", "osv", "2026")
    for filename in os.listdir(advisories_dir):
        if not filename.startswith("DHI-") or not filename.endswith(".json"):
            continue
        path = os.path.join(advisories_dir, filename)
        with open(path) as f:
            record = json.load(f)
        record["schema_version"] = "2.0.0"
        with open(path, "w") as f:
            json.dump(record, f)
    config = Config()
    config.runtime.result_store = result.StoreStrategy.FLAT_FILE
    provider = Provider(root=workspace.root, config=config)

    with pytest.raises(RuntimeError, match="no DHI advisory could be read: all 3 records were skipped"):
        provider.update(None)
