from __future__ import annotations

import pytest
from vunnel import provider, providers, result
from vunnel.cli import config


def test_minimal_config(helpers):
    cfg_path = helpers.local_dir("test-fixtures/minimal.yaml")
    cfg = config.load(path=cfg_path)
    assert cfg == config.Application(log=config.Log(slim=False, level="TRACE"))


def test_full_config(helpers):
    cfg_path = helpers.local_dir("test-fixtures/full.yaml")
    cfg = config.load(path=cfg_path)

    runtime_cfg = provider.RuntimeConfig(
        result_store=result.StoreStrategy.SQLITE,
        existing_input=provider.InputStatePolicy.KEEP,
        existing_results=provider.ResultStatePolicy.KEEP,
        on_error=provider.OnErrorConfig(
            action=provider.OnErrorAction.SKIP,
            retry_count=9,
            retry_delay=12,
            input=provider.InputStatePolicy.DELETE,
            results=provider.ResultStatePolicy.DELETE,
        ),
    )

    assert cfg == config.Application(
        root="/tmp/all-the-dataz",
        log=config.Log(
            slim=True,
            level="trace",
            show_level=False,
            show_timestamp=True,
        ),
        providers=config.Providers(
            alpine=providers.alpine.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            amazon=providers.amazon.Config(
                security_advisories={
                    # this is what we added in the config
                    42: "https://alas.aws.amazon.com/AL2/alas-42.rss",
                    # this is the defaults...
                    2: "https://alas.aws.amazon.com/AL2/alas.rss",
                    2022: "https://alas.aws.amazon.com/AL2022/alas.rss",
                    2023: "https://alas.aws.amazon.com/AL2023/alas.rss",
                },
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            chainguard=providers.chainguard.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            debian=providers.debian.Config(
                releases={
                    # this is the defaults...
                    "trixie": "13",
                    "bookworm": "12",
                    "bullseye": "11",
                    "buster": "10",
                    "stretch": "9",
                    "jessie": "8",
                    "wheezy": "7",
                    "sid": "unstable",
                    # this is what we added in the config
                    "jinx": 87,
                },
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            github=providers.github.Config(
                token="",
                api_url="https://api.gitlab.com/graphql",
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            nvd=providers.nvd.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                overrides_enabled=True,
                overrides_url="https://github.com/anchore/nvd-data-overrides/SOMEWHEREELSE/main.tar.gz",
            ),
            oracle=providers.oracle.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            rhel=providers.rhel.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                parallelism=7,
                full_sync_interval=22,
                skip_namespaces=["rhel:8"],
            ),
            sles=providers.sles.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                allow_versions=[13],
            ),
            ubuntu=providers.ubuntu.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                additional_versions={"zzz": "24.24"},
                enable_rev_history=True,
                parallelism=25,
                git_url="https://xyz.abc",
                git_branch="yoda",
            ),
            wolfi=providers.wolfi.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
        ),
    )


@pytest.mark.parametrize(
    "top_level_import_results,provider_host,provider_path,provider_enabled,want_import_results",
    [
        (
            # top-level values propagate down
            config.ImportResults("http://example.com", "", True),
            "",
            None,
            None,
            config.ImportResults("http://example.com", "{provider_name}/listing.json", True),
        ),
        (
            # runtime defaults come through
            config.ImportResults("", "", None),
            "",
            None,
            None,
            config.ImportResults("", "{provider_name}/listing.json", None),
        ),
        (
            # specific values override top-level values
            config.ImportResults("http://example.com", "some-specific-path/listing.json", False),
            "http://somewhere-else.example.com",
            "specific-path",
            True,
            config.ImportResults("http://somewhere-else.example.com", "specific-path", True),
        ),
    ],
)
def test_import_results_config(top_level_import_results, provider_host, provider_path, provider_enabled, want_import_results):
    runtime_config_args = {}
    if provider_path is not None:
        runtime_config_args["import_results_path"] = provider_path
    if provider_host is not None:
        runtime_config_args["import_results_host"] = provider_host
    if provider_enabled is not None:
        runtime_config_args["import_results_enabled"] = provider_enabled

    cfg = config.Application(
        providers=config.Providers(
            import_results=top_level_import_results,
            nvd=providers.nvd.Config(
                runtime=provider.RuntimeConfig(
                    **runtime_config_args,
                ),
            ),
        ),
    )

    assert cfg.providers.nvd.runtime.import_results_host == want_import_results.host
    assert cfg.providers.nvd.runtime.import_results_path == want_import_results.path
    assert cfg.providers.nvd.runtime.import_results_enabled == want_import_results.enabled
