from __future__ import annotations

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
                security_advisories={42: "https://alas.aws.amazon.com/AL2/alas-42.rss"},  # cap sensitive!
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            centos=providers.centos.Config(
                runtime=runtime_cfg,
                skip_namespaces=["centos:8"],
                request_timeout=20,
            ),
            chainguard=providers.chainguard.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            debian=providers.debian.Config(
                releases={
                    "trixie": "13",
                    "bookworm": "12",
                    "bullseye": "11",
                    "buster": "10",
                    "stretch": "9",
                    "jessie": "8",
                    "wheezy": "7",
                    "sid": "unstable",
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
