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
    assert populate_mock.populate.call_count == 1
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
        )
    ]


@pytest.mark.parametrize(
    "args, clear, clear_input, clear_results",
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
    res = runner.invoke(cli.cli, ["clear"] + args)
    assert res.exit_code == 0
    assert workspace_mock.clear.call_count == clear
    assert workspace_mock.clear_input.call_count == clear_input
    assert workspace_mock.clear_results.call_count == clear_results
