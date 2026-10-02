import shutil
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


@patch.object(Parser, "_clone")
@patch.object(Parser, "_record_source_revision")
def test_provider_schema(mock_revision, mock_clone, helpers, disable_get_requests):
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
def test_parser_selects_only_dhi_records(mock_revision, mock_clone, helpers):
    workspace = prepare_workspace(helpers)
    config = Config()
    parser = Parser(
        ws=workspace,
        repository_url=config.repository_url,
        repository_branch=config.repository_branch,
        advisories_path=config.advisories_path,
    )

    records = list(parser.get())

    assert [record[0] for record in records] == ["DHI-CVE-2016-2781-coreutils", "DHI-CVE-2017-18018-coreutils"]
    assert all(record[1] == "1.6.1" for record in records)


@pytest.mark.parametrize("schema_version, expected", [("1.5.0", schema.OSVSchema("1.5.0")), ("1.6.1", schema.OSVSchema("1.6.1")), ("2.0.0", None)])
def test_compatible_schema(schema_version, expected):
    assert Provider.compatible_schema(schema_version) == expected


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
