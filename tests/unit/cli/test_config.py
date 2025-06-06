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
                max_allowed_alas_http_403=33,
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
            epss=providers.epss.Config(
                runtime=runtime_cfg,
                dataset="2025-03-04",
                url_template="https://localhost/epss_scores-{}.csv.gz",
                request_timeout=20,
            ),
            github=providers.github.Config(
                token="",
                api_url="https://api.gitlab.com/graphql",
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            kev=providers.kev.Config(
                runtime=runtime_cfg,
                url="https://anchore.com/kev/data.json",
                request_timeout=20,
            ),
            minimos=providers.minimos.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            nvd=providers.nvd.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                request_retry_count=50,
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
    "common_enabled,provider_enabled,want",
    [
        # default wins if provider is None
        (True, None, True),
        (False, None, False),
        # provider always overrides default
        (True, False, False),
        (False, True, True),
        # if everything agrees, that's the answer
        (True, True, True),
        (False, False, False),
    ],
)
def test_import_results_enabled(common_enabled: bool, provider_enabled: bool | None, want: bool):
    cfg = config.Application(
        providers=config.Providers(
            common=config.CommonProviderConfig(
                import_results=config.ImportResults(
                    enabled=common_enabled,
                )
            ),
            nvd=providers.nvd.Config(
                runtime=provider.RuntimeConfig(
                    import_results_enabled=provider_enabled,
                )
            ),
        )
    )
    assert cfg.providers.nvd.runtime.import_results_enabled == want


@pytest.mark.parametrize(
    "common_path,provider_path,want",
    [
        ("default_value", None, "default_value"),
        ("default_value", "specific_value", "specific_value"),
        ("default_value", "", "default_value"),
        ("default_value", "/", "/"),
    ],
)
def test_import_results_path(common_path: str, provider_path: str | None, want: str):
    cfg = config.Application(
        providers=config.Providers(
            common=config.CommonProviderConfig(
                import_results=config.ImportResults(
                    path=common_path,
                )
            ),
            nvd=providers.nvd.Config(
                runtime=provider.RuntimeConfig(
                    import_results_path=provider_path,
                )
            ),
        )
    )
    assert cfg.providers.nvd.runtime.import_results_path == want


@pytest.mark.parametrize(
    "common_host,provider_host,want",
    [
        ("default-host", None, "default-host"),
        ("default-host", "specific-host", "specific-host"),
        ("default-host", "", "default-host"),  # TODO: should this be "default-host"?
    ],
)
def test_import_results_host(common_host: str, provider_host: str | None, want: str):
    cfg = config.Application(
        providers=config.Providers(
            common=config.CommonProviderConfig(
                import_results=config.ImportResults(
                    host=common_host,
                )
            ),
            nvd=providers.nvd.Config(
                runtime=provider.RuntimeConfig(
                    import_results_host=provider_host,
                )
            ),
        )
    )
    assert cfg.providers.nvd.runtime.import_results_host == want
