import pytest

from vunnel import provider, providers
from vunnel.cli import config


def test_minimal_config(helpers):
    cfg_path = helpers.local_dir("test-fixtures/minimal.yaml")
    cfg = config.load(path=cfg_path)
    assert cfg == config.Application(log=config.Log(slim=False, level="TRACE"))


def test_full_config(helpers):
    cfg_path = helpers.local_dir("test-fixtures/full.yaml")
    cfg = config.load(path=cfg_path)

    runtime_cfg = provider.RuntimeConfig(
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
        ),
        providers=config.Providers(
            alpine=providers.alpine.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            amazon=providers.amazon.Config(
                security_advisories={42: "https://alas.aws.amazon.com/al2/alas-42.rss"},
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            centos=providers.centos.Config(
                runtime=runtime_cfg,
                skip_namespaces=["centos:8"],
                request_timeout=20,
            ),
            debian=providers.debian.Config(
                distro_map={"jinx": 87},
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
                start_year=1987,
                end_year=2002,
            ),
            oracle=providers.oracle.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
            rhel=providers.rhel.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                max_workers=7,
                full_sync_interval=22,
                skip_namespaces=["rhel:8"],
            ),
            sles=providers.sles.Config(
                runtime=runtime_cfg,
                request_timeout=20,
                allow_versions=[13],
            ),
            wolfi=providers.wolfi.Config(
                runtime=runtime_cfg,
                request_timeout=20,
            ),
        ),
    )
