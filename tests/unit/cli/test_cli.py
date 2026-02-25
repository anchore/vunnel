from __future__ import annotations

import datetime
import os
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from vunnel import cli, provider, providers, result
from vunnel.providers import nvd


def test_list() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list"])
    assert res.exit_code == 0

    expected_names = providers.names()
    assert len(expected_names) > 0

    expected_output = "\n".join(sorted(expected_names))
    assert expected_output.strip() == res.output.strip()


def test_status(helpers, tmpdir, monkeypatch) -> None:
    data_path = helpers.local_dir("test-fixtures/data-1")

    envs = {
        "NVD_API_KEY": "secret",
        "GITHUB_TOKEN": "secret",
    }
    monkeypatch.setattr(os, "environ", envs)

    config = tmpdir.join("vunnel.yaml")
    config.write(f"root: {data_path}")

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["-c", str(config), "status"])
    assert res.exit_code == 0

    expected_output = f"""{data_path}
└── wolfi
       results: 56
       from:    2023-01-17 14:58:13
"""
    assert expected_output.strip() == res.output.strip()


def test_status_json(helpers, tmpdir, monkeypatch) -> None:
    import json

    data_path = helpers.local_dir("test-fixtures/data-1")

    envs = {
        "NVD_API_KEY": "secret",
        "GITHUB_TOKEN": "secret",
    }
    monkeypatch.setattr(os, "environ", envs)

    config = tmpdir.join("vunnel.yaml")
    config.write(f"root: {data_path}")

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["-c", str(config), "status", "--json"])
    assert res.exit_code == 0

    # Parse and verify JSON output
    output_data = json.loads(res.output)

    expected_output = {
        "root": data_path,
        "providers": [
            {
                "name": "wolfi",
                "count": 56,
                "date": "2023-01-17 14:58:13",
                "error": None,
                "enabled": True
            }
        ]
    }

    assert output_data == expected_output

def test_run(mocker, monkeypatch) -> None:
    populate_mock = MagicMock()
    populate_mock.__enter__ = MagicMock(return_value=populate_mock)
    populate_mock.__exit__ = MagicMock(return_value=None)
    create_mock = MagicMock(return_value=populate_mock)
    mocker.patch.object(providers, "create", create_mock)

    envs = {"NVD_API_KEY": "secret"}
    monkeypatch.setattr(os, "environ", envs)

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["-c", "-", "run", "nvd"])
    assert res.exit_code == 0
    assert populate_mock.run.call_count == 1
    assert create_mock.call_args_list == [
        mocker.call(
            "nvd",
            "./data",
            # note: this is the default config
            config=nvd.Config(
                runtime=provider.RuntimeConfig(
                    on_error=provider.OnErrorConfig(
                        action=provider.OnErrorAction.FAIL,
                        retry_count=3,
                        retry_delay=5,
                        input=provider.InputStatePolicy.KEEP,
                        results=provider.InputStatePolicy.KEEP,
                    ),
                    existing_input=provider.InputStatePolicy.KEEP,
                    existing_results=provider.InputStatePolicy.KEEP,
                    result_store=result.StoreStrategy.SQLITE,
                    import_results_host="",
                    import_results_path="providers/{provider_name}/listing.json",
                    import_results_enabled=False,
                ),
                request_timeout=125,
                api_key="secret",
            ),
        ),
    ]


@pytest.mark.parametrize(
    ("args", "clear", "clear_input", "clear_results"),
    (
        (["wolfi"], 1, 0, 0),
        (["wolfi", "-i"], 0, 1, 0),
        (["wolfi", "-r"], 0, 0, 1),
    ),
)
def test_clear(mocker, monkeypatch, args, clear, clear_input, clear_results) -> None:
    workspace_mock = MagicMock()
    provider_mock = MagicMock(workspace=workspace_mock)
    provider_mock.__enter__ = MagicMock(return_value=provider_mock)
    provider_mock.__exit__ = MagicMock(return_value=None)
    create_mock = MagicMock(return_value=provider_mock)
    mocker.patch.object(providers, "create", create_mock)

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["clear", *args])
    assert res.exit_code == 0
    assert workspace_mock.clear.call_count == clear
    assert workspace_mock.clear_input.call_count == clear_input
    assert workspace_mock.clear_results.call_count == clear_results


def test_config(monkeypatch) -> None:
    from importlib import metadata

    envs = {
        "NVD_API_KEY": "secret",
        "GITHUB_TOKEN": "secret",
    }
    monkeypatch.setattr(os, "environ", envs)

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["-c", "-", "config"])
    assert res.exit_code == 0

    vunnel_version = metadata.version("vunnel")
    expected_output = """
log:
  level: INFO
  show_level: true
  show_timestamp: false
  slim: false
providers:
  alma:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  alpine:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  amazon:
    max_allowed_alas_http_403: 25
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
    security_advisories:
      '2': https://alas.aws.amazon.com/AL2/alas.rss
      '2022': https://alas.aws.amazon.com/AL2022/alas.rss
      '2023': https://alas.aws.amazon.com/AL2023/alas.rss
  arch:
    api_url: https://security.archlinux.org/all.json
    request_timeout: 30
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  bitnami:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  chainguard:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  chainguard_libraries:
    openvex_url: https://libraries.cgr.dev/openvex/v1/all.json
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: anchore/vunnel-$VUNNEL_VERSION
  common:
    import_results:
      enabled: false
      host: ''
      path: providers/{provider_name}/listing.json
      skip_newer_archive_check: false
    user_agent: null
  debian:
    releases:
      bookworm: '12'
      bullseye: '11'
      buster: '10'
      duke: '15'
      forky: '14'
      jessie: '8'
      sid: unstable
      stretch: '9'
      trixie: '13'
      wheezy: '7'
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  echo:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  eol:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
    url: https://endoflife.date/api/v1/products/full
  epss:
    dataset: current
    request_timeout: 125
    runtime:
      existing_input: delete
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
    url_template: https://epss.cyentia.com/epss_scores-{}.csv.gz
  fedora:
    bodhi_url: https://bodhi.fedoraproject.org
    releases: []
    request_timeout: 125
    rows_per_page: 100
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: anchore/vunnel-$VUNNEL_VERSION
  github:
    api_url: https://api.github.com/graphql
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
    token: secret
  kev:
    request_timeout: 125
    runtime:
      existing_input: delete
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
    url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  mariner:
    allow_versions:
      - '1.0'
      - '2.0'
      - '3.0'
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  minimos:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  nvd:
    api_key: secret
    overrides_enabled: false
    overrides_url: https://github.com/anchore/nvd-data-overrides/archive/refs/heads/main.tar.gz
    request_retry_count: 10
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: keep
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  oracle:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  rhel:
    csaf_parallelism: 20x
    full_sync_interval: 2
    ignore_hydra_errors: false
    parallelism: 4
    request_timeout: 125
    rhsa_source: CSAF
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
    skip_namespaces:
      - rhel:3
      - rhel:4
  rocky:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  secureos:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: anchore/vunnel-$VUNNEL_VERSION
  sles:
    allow_versions:
      - '11'
      - '12'
      - '15'
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  ubuntu:
    additional_versions: {}
    enable_rev_history: true
    git_branch: master
    git_url: git://git.launchpad.net/ubuntu-cve-tracker
    parallelism: 8x
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: keep
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
  wolfi:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      import_results_enabled: false
      import_results_host: ''
      import_results_path: providers/{provider_name}/listing.json
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
      skip_download: false
      skip_newer_archive_check: false
      user_agent: null
root: ./data
"""
    expected_output = expected_output.replace("$VUNNEL_VERSION", vunnel_version)
    assert expected_output.strip() in res.output


def test_list_json_output() -> None:
    import json

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "-o", "json"])
    assert res.exit_code == 0

    output = json.loads(res.output)
    assert "providers" in output
    assert len(output["providers"]) > 0

    # verify structure of first provider
    first = output["providers"][0]
    assert "name" in first
    assert "version" in first
    assert "schema" in first
    assert "tags" in first
    assert "name" in first["schema"]
    assert "version" in first["schema"]
    assert isinstance(first["tags"], list)


def test_list_tag_filter() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "auxiliary"])
    assert res.exit_code == 0

    # epss and kev have "auxiliary" tag
    lines = res.output.strip().split("\n")
    assert "epss" in lines
    assert "kev" in lines
    # nvd should not be in the list (it has "vulnerability" not "auxiliary")
    assert "nvd" not in lines


def test_list_multiple_tag_filter() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "vulnerability", "--tag", "language"])
    assert res.exit_code == 0

    # providers with both tags
    lines = res.output.strip().split("\n")
    assert "bitnami" in lines
    assert "github" in lines
    assert "chainguard-libraries" in lines
    # alpine has "os" not "language"
    assert "alpine" not in lines


def test_list_nonexistent_tag() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "nonexistent-tag-12345"])
    assert res.exit_code == 0
    assert res.output.strip() == ""


def test_list_tag_filter_json_output() -> None:
    import json

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "auxiliary", "-o", "json"])
    assert res.exit_code == 0

    output = json.loads(res.output)
    assert "providers" in output

    provider_names = [p["name"] for p in output["providers"]]
    assert "epss" in provider_names
    assert "kev" in provider_names
    assert "nvd" not in provider_names


def test_list_tag_negation() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "!auxiliary"])
    assert res.exit_code == 0

    lines = res.output.strip().split("\n")
    # auxiliary providers should be excluded
    assert "epss" not in lines
    assert "kev" not in lines
    # vulnerability providers should be included
    assert "nvd" in lines
    assert "alpine" in lines


def test_list_tag_mixed_include_exclude() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "vulnerability", "--tag", "!os"])
    assert res.exit_code == 0

    lines = res.output.strip().split("\n")
    # providers with "vulnerability" but NOT "os"
    assert "nvd" in lines
    assert "github" in lines
    # providers with "os" should be excluded
    assert "alpine" not in lines
    assert "debian" not in lines


def test_list_tag_multiple_exclusions() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "!os", "--tag", "!language"])
    assert res.exit_code == 0

    lines = res.output.strip().split("\n")
    # providers without "os" or "language" tags
    assert "nvd" in lines
    assert "epss" in lines
    assert "kev" in lines
    # providers with "os" or "language" should be excluded
    assert "alpine" not in lines
    assert "github" not in lines


def test_list_tag_invalid_negation() -> None:
    runner = CliRunner()
    res = runner.invoke(cli.cli, ["list", "--tag", "!"])
    assert res.exit_code != 0
    assert "invalid tag" in res.output.lower()


class TestWorkspaceSelect:
    def test_basic_select_flat_file(self, helpers, tmpdir, monkeypatch) -> None:
        from vunnel import workspace as ws_module

        data_path = helpers.local_dir("test-fixtures/data-1")

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {data_path}")

        output_path = str(tmpdir.join("output"))

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "wolfi", "-i", ".*", output_path],
        )
        assert res.exit_code == 0

        # verify output structure
        dest_ws = ws_module.Workspace(root=output_path, name="wolfi")
        assert os.path.exists(dest_ws.results_path)
        assert not os.path.exists(dest_ws.input_path)
        assert os.path.exists(dest_ws.metadata_path)

    def test_select_with_pattern_filter(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace with known results
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("CVE-2023-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0001"}})
            writer.write("CVE-2023-0002", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0002"}})
            writer.write("CVE-2024-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2024-0001"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "CVE-2023-.*", output_path],
        )
        assert res.exit_code == 0

        # verify only CVE-2023 results are in the output
        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())

        assert ids == ["CVE-2023-0001", "CVE-2023-0002"]

    def test_select_with_sqlite_source(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace with sqlite store
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.SQLITE,
        ) as writer:
            writer.write("CVE-2023-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0001"}})
            writer.write("CVE-2023-0002", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0002"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="sqlite",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", ".*", output_path],
        )
        assert res.exit_code == 0

        # verify results in output
        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())

        assert ids == ["CVE-2023-0001", "CVE-2023-0002"]

    def test_select_with_sqlite_output(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("CVE-2023-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0001"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", ".*", "--store", "sqlite", output_path],
        )
        assert res.exit_code == 0

        # verify sqlite file exists
        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        db_path = os.path.join(dest_ws.results_path, "results.db")
        assert os.path.exists(db_path)

    def test_invalid_regex(self, tmpdir, monkeypatch) -> None:
        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        config = tmpdir.join("vunnel.yaml")
        config.write("root: ./data")

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "nvd", "-i", "[invalid", str(tmpdir.join("output"))],
        )
        assert res.exit_code != 0
        assert "invalid regex" in res.output.lower()

    def test_missing_source_workspace(self, tmpdir, monkeypatch) -> None:
        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {tmpdir.join('nonexistent')}")

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "nvd", "-i", ".*", str(tmpdir.join("output"))],
        )
        # should succeed but skip the missing provider
        assert res.exit_code == 0

    def test_multiple_providers(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create two source workspaces
        source_root = str(tmpdir.join("source"))

        for provider_name in ["provider-a", "provider-b"]:
            source_ws = ws_module.Workspace(root=source_root, name=provider_name, create=True)
            with result_module.Writer(
                source_ws,
                result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
                store_strategy=result_module.StoreStrategy.FLAT_FILE,
            ) as writer:
                writer.write(f"{provider_name}-CVE-0001", schema.OSSchema(), {"Vulnerability": {"id": f"{provider_name}-CVE-0001"}})

            source_ws.record_state(
                version=1,
                distribution_version=1,
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
                urls=[],
                store="flat-file",
            )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "provider-a", "-p", "provider-b", "-i", ".*", output_path],
        )
        assert res.exit_code == 0

        # verify both providers are in output
        for provider_name in ["provider-a", "provider-b"]:
            dest_ws = ws_module.Workspace(root=output_path, name=provider_name)
            assert os.path.exists(dest_ws.results_path)

    def test_replace_flag(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace with two results
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("CVE-2023-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0001"}})
            writer.write("CVE-2023-0002", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0002"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        # first run - select only CVE-2023-0001
        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "CVE-2023-0001", output_path],
        )
        assert res.exit_code == 0

        # verify first run result
        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())
        assert ids == ["CVE-2023-0001"]

        # second run with --replace - select only CVE-2023-0002
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "CVE-2023-0002", "--replace", output_path],
        )
        assert res.exit_code == 0

        # verify only the new selection is in output (replace removed old one)
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())

        assert ids == ["CVE-2023-0002"]

    def test_case_insensitive_matching(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace with lowercase IDs (like rhel provider)
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("rhel:6/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})
            writer.write("rhel:7/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})
            writer.write("rhel:6/cve-2024-12345", schema.OSSchema(), {"Vulnerability": {"id": "cve-2024-12345"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        # search with uppercase pattern - should match lowercase IDs
        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "CVE-2021-30473", output_path],
        )
        assert res.exit_code == 0

        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())

        assert ids == ["rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]

    def test_substring_matching(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace with nested IDs
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("rhel:6/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})
            writer.write("rhel:7/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})
            writer.write("nvd/CVE-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2021-30473"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        # search with pattern that appears in middle of ID (not prefix)
        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "cve-2021-30473", output_path],
        )
        assert res.exit_code == 0

        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())

        # should match all IDs containing the pattern (case-insensitive)
        assert ids == ["nvd/CVE-2021-30473", "rhel:6/cve-2021-30473", "rhel:7/cve-2021-30473"]

    def test_anchored_pattern(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace with different prefixes
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("rhel:6/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})
            writer.write("rhel:7/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})
            writer.write("debian:10/cve-2021-30473", schema.OSSchema(), {"Vulnerability": {"id": "cve-2021-30473"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        # use anchored pattern to select only rhel:6 results
        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "^rhel:6/", output_path],
        )
        assert res.exit_code == 0

        dest_ws = ws_module.Workspace(root=output_path, name="test-provider")
        reader = result_module.FlatFileReader(dest_ws.results_path)
        ids = sorted(reader.ids())

        # should only match rhel:6 IDs
        assert ids == ["rhel:6/cve-2021-30473"]

    def test_dry_run(self, tmpdir, monkeypatch) -> None:
        from vunnel import result as result_module, schema, workspace as ws_module

        envs = {"NVD_API_KEY": "secret", "GITHUB_TOKEN": "secret"}
        monkeypatch.setattr(os, "environ", envs)

        # create source workspace
        source_root = str(tmpdir.join("source"))
        source_ws = ws_module.Workspace(root=source_root, name="test-provider", create=True)

        with result_module.Writer(
            source_ws,
            result_state_policy=result_module.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result_module.StoreStrategy.FLAT_FILE,
        ) as writer:
            writer.write("CVE-2023-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0001"}})
            writer.write("CVE-2023-0002", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2023-0002"}})
            writer.write("CVE-2024-0001", schema.OSSchema(), {"Vulnerability": {"id": "CVE-2024-0001"}})

        source_ws.record_state(
            version=1,
            distribution_version=1,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
            urls=[],
            store="flat-file",
        )

        config = tmpdir.join("vunnel.yaml")
        config.write(f"root: {source_root}")

        output_path = str(tmpdir.join("output"))

        runner = CliRunner()
        res = runner.invoke(
            cli.cli,
            ["-c", str(config), "workspace-select", "-p", "test-provider", "-i", "CVE-2023", "--dry-run", output_path],
        )
        assert res.exit_code == 0

        # verify output shows matching IDs
        assert "test-provider: CVE-2023-0001" in res.output
        assert "test-provider: CVE-2023-0002" in res.output
        assert "CVE-2024-0001" not in res.output

        # verify no output directory was created
        assert not os.path.exists(output_path)
