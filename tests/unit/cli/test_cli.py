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
  alpine:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
  amazon:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
    security_advisories:
      '2': https://alas.aws.amazon.com/AL2/alas.rss
      '2022': https://alas.aws.amazon.com/AL2022/alas.rss
      '2023': https://alas.aws.amazon.com/AL2023/alas.rss
  centos:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
    skip_namespaces:
      - centos:3
      - centos:4
  chainguard:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
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
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
  github:
    api_url: https://api.github.com/graphql
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
    token: secret
  nvd:
    api_key: secret
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: keep
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
  oracle:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
  rhel:
    full_sync_interval: 2
    parallelism: 4
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: keep
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
    skip_namespaces:
      - rhel:3
      - rhel:4
  sles:
    allow_versions:
      - '11'
      - '12'
      - '15'
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
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
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
  wolfi:
    request_timeout: 125
    runtime:
      existing_input: keep
      existing_results: delete-before-write
      on_error:
        action: fail
        input: keep
        results: keep
        retry_count: 3
        retry_delay: 5
      result_store: sqlite
root: ./data
"""
    assert expected_output.strip() in res.output
