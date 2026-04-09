from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

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
                    "duke": "15",
                    "forky": "14",
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


class TestApplyEnvOverrides:
    def test_simple_string_override(self, monkeypatch):
        @dataclass
        class SimpleConfig:
            name: str = "default"

        obj = SimpleConfig()
        monkeypatch.setenv("TEST_NAME", "from_env")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.name == "from_env"

    def test_bool_true_override(self, monkeypatch):
        @dataclass
        class BoolConfig:
            enabled: bool = False

        obj = BoolConfig()
        monkeypatch.setenv("TEST_ENABLED", "true")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.enabled is True

    def test_bool_false_override(self, monkeypatch):
        @dataclass
        class BoolConfig:
            enabled: bool = True

        obj = BoolConfig()
        monkeypatch.setenv("TEST_ENABLED", "false")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.enabled is False

    def test_int_override(self, monkeypatch):
        @dataclass
        class IntConfig:
            count: int = 0

        obj = IntConfig()
        monkeypatch.setenv("TEST_COUNT", "42")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.count == 42

    def test_float_override(self, monkeypatch):
        @dataclass
        class FloatConfig:
            rate: float = 0.0

        obj = FloatConfig()
        monkeypatch.setenv("TEST_RATE", "3.14")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.rate == 3.14

    def test_nested_dataclass_override(self, monkeypatch):
        @dataclass
        class InnerConfig:
            value: str = "inner_default"
            count: int = 0

        @dataclass
        class OuterConfig:
            name: str = "outer_default"
            inner: InnerConfig = field(default_factory=InnerConfig)

        obj = OuterConfig()
        monkeypatch.setenv("TEST_NAME", "outer_from_env")
        monkeypatch.setenv("TEST_INNER_VALUE", "inner_from_env")
        monkeypatch.setenv("TEST_INNER_COUNT", "99")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.name == "outer_from_env"
        assert obj.inner.value == "inner_from_env"
        assert obj.inner.count == 99

    def test_deeply_nested_override(self, monkeypatch):
        @dataclass
        class Level3:
            deep: str = "level3_default"

        @dataclass
        class Level2:
            level3: Level3 = field(default_factory=Level3)

        @dataclass
        class Level1:
            level2: Level2 = field(default_factory=Level2)

        obj = Level1()
        monkeypatch.setenv("TEST_LEVEL2_LEVEL3_DEEP", "deep_from_env")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.level2.level3.deep == "deep_from_env"

    def test_no_override_without_env_var(self, monkeypatch):
        monkeypatch.delenv("TEST_NAME", raising=False)

        @dataclass
        class SimpleConfig:
            name: str = "default"

        obj = SimpleConfig()
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.name == "default"

    def test_overrides_existing_non_default_value(self, monkeypatch):
        # this is the key behavior: env var should override even if the object
        # already has a non-default value (e.g., loaded from YAML)
        @dataclass
        class SimpleConfig:
            name: str = "default"

        obj = SimpleConfig(name="from_yaml")
        monkeypatch.setenv("TEST_NAME", "from_env")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.name == "from_env"

    def test_case_insensitive_bool(self, monkeypatch):
        @dataclass
        class BoolConfig:
            enabled: bool = False

        obj = BoolConfig()
        monkeypatch.setenv("TEST_ENABLED", "TRUE")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.enabled is True

    def test_non_dataclass_is_noop(self, monkeypatch):
        # should not raise an error
        obj = {"key": "value"}
        monkeypatch.setenv("TEST_KEY", "new_value")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj == {"key": "value"}

    @pytest.mark.parametrize(
        "env_value,expected",
        [
            ("true", True),
            ("TRUE", True),
            ("True", True),
            ("yes", True),
            ("YES", True),
            ("1", True),
            ("on", True),
            ("ON", True),
            ("false", False),
            ("FALSE", False),
            ("no", False),
            ("0", False),
            ("off", False),
            ("anything_else", False),
        ],
    )
    def test_bool_truthy_values(self, monkeypatch, env_value, expected):
        @dataclass
        class BoolConfig:
            enabled: bool = False

        obj = BoolConfig()
        monkeypatch.setenv("TEST_ENABLED", env_value)
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.enabled is expected

    def test_invalid_int_raises_error(self, monkeypatch):
        @dataclass
        class IntConfig:
            count: int = 0

        obj = IntConfig()
        monkeypatch.setenv("TEST_COUNT", "not_a_number")

        with pytest.raises(ValueError, match="invalid value for TEST_COUNT"):
            config.apply_env_overrides(obj, prefix="TEST")

    def test_invalid_float_raises_error(self, monkeypatch):
        @dataclass
        class FloatConfig:
            rate: float = 0.0

        obj = FloatConfig()
        monkeypatch.setenv("TEST_RATE", "not_a_float")

        with pytest.raises(ValueError, match="invalid value for TEST_RATE"):
            config.apply_env_overrides(obj, prefix="TEST")

    def test_optional_string_override(self, monkeypatch):
        @dataclass
        class OptionalConfig:
            name: Optional[str] = None

        obj = OptionalConfig()
        monkeypatch.setenv("TEST_NAME", "from_env")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.name == "from_env"

    def test_optional_int_override(self, monkeypatch):
        @dataclass
        class OptionalConfig:
            count: Optional[int] = None

        obj = OptionalConfig()
        monkeypatch.setenv("TEST_COUNT", "42")
        config.apply_env_overrides(obj, prefix="TEST")

        assert obj.count == 42


def test_env_vars_override_yaml_config(helpers, monkeypatch):
    # this tests the 12-factor config precedence: env vars should win over YAML
    cfg_path = helpers.local_dir("test-fixtures/minimal.yaml")

    # the YAML file has log.level = "trace", we override via env var
    monkeypatch.setenv("VUNNEL_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("VUNNEL_ROOT", "/env/override/path")
    monkeypatch.setenv("VUNNEL_LOG_SLIM", "true")

    cfg = config.load(path=cfg_path)

    # env vars should take precedence
    assert cfg.log.level == "WARNING"
    assert cfg.root == "/env/override/path"
    assert cfg.log.slim is True
