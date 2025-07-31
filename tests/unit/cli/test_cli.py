from __future__ import annotations

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
    create_mock = MagicMock(return_value=MagicMock(workspace=workspace_mock))
    mocker.patch.object(providers, "create", create_mock)

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["clear", *args])
    assert res.exit_code == 0
    assert workspace_mock.clear.call_count == clear
    assert workspace_mock.clear_input.call_count == clear_input
    assert workspace_mock.clear_results.call_count == clear_results


def test_config(monkeypatch) -> None:
    envs = {
        "NVD_API_KEY": "secret",
        "GITHUB_TOKEN": "secret",
    }
    monkeypatch.setattr(os, "environ", envs)

    runner = CliRunner()
    res = runner.invoke(cli.cli, ["-c", "-", "config"])
    assert res.exit_code == 0
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
    security_advisories:
      '2': https://alas.aws.amazon.com/AL2/alas.rss
      '2022': https://alas.aws.amazon.com/AL2022/alas.rss
      '2023': https://alas.aws.amazon.com/AL2023/alas.rss
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
  common:
    import_results:
      enabled: false
      host: ''
      path: providers/{provider_name}/listing.json
      skip_newer_archive_check: false
  debian:
    releases:
      bookworm: '12'
      bullseye: '11'
      buster: '10'
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
    url_template: https://epss.cyentia.com/epss_scores-{}.csv.gz
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
  rhel:
    full_sync_interval: 2
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
  ubuntu:
    additional_versions: {}
    enable_rev_history: true
    git_branch: master
    git_url: git://git.launchpad.net/ubuntu-cve-tracker
    parallelism: 8
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
root: ./data
"""
    assert expected_output.strip() in res.output
