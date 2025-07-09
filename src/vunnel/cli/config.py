from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

import mergedeep
import yaml
from mashumaro.mixins.dict import DataClassDictMixin

from vunnel import provider, providers


@dataclass
class ImportResults:
    """
    These are the defaults for all providers. Corresponding
    fields on specific providers override these values.

    If a path is "" or None, path will be set to "providers/{provider_name}/listing.json".
    If an empty path is needed, specify "/".
    """

    __default_path__ = "providers/{provider_name}/listing.json"
    host: str = ""
    path: str = __default_path__
    enabled: bool = False
    skip_newer_archive_check: bool = False

    def __post_init__(self) -> None:
        if not self.path:
            self.path = self.__default_path__


@dataclass
class CommonProviderConfig:
    import_results: ImportResults = field(default_factory=ImportResults)


@dataclass
class Providers:
    alma: providers.alma.Config = field(default_factory=providers.alma.Config)
    alpine: providers.alpine.Config = field(default_factory=providers.alpine.Config)
    amazon: providers.amazon.Config = field(default_factory=providers.amazon.Config)
    bitnami: providers.bitnami.Config = field(default_factory=providers.bitnami.Config)
    chainguard: providers.chainguard.Config = field(default_factory=providers.chainguard.Config)
    debian: providers.debian.Config = field(default_factory=providers.debian.Config)
    echo: providers.echo.Config = field(default_factory=providers.echo.Config)
    epss: providers.epss.Config = field(default_factory=providers.epss.Config)
    github: providers.github.Config = field(default_factory=providers.github.Config)
    kev: providers.kev.Config = field(default_factory=providers.kev.Config)
    mariner: providers.mariner.Config = field(default_factory=providers.mariner.Config)
    minimos: providers.minimos.Config = field(default_factory=providers.minimos.Config)
    nvd: providers.nvd.Config = field(default_factory=providers.nvd.Config)
    oracle: providers.oracle.Config = field(default_factory=providers.oracle.Config)
    rhel: providers.rhel.Config = field(default_factory=providers.rhel.Config)
    rocky: providers.rocky.Config = field(default_factory=providers.rocky.Config)
    sles: providers.sles.Config = field(default_factory=providers.sles.Config)
    ubuntu: providers.ubuntu.Config = field(default_factory=providers.ubuntu.Config)
    wolfi: providers.wolfi.Config = field(default_factory=providers.wolfi.Config)

    common: CommonProviderConfig = field(default_factory=CommonProviderConfig)

    def __post_init__(self) -> None:
        for name in self.provider_names():
            runtime_cfg = getattr(self, name).runtime
            if runtime_cfg and isinstance(runtime_cfg, provider.RuntimeConfig):
                if runtime_cfg.import_results_enabled is None:
                    runtime_cfg.import_results_enabled = self.common.import_results.enabled
                if not runtime_cfg.import_results_host:
                    runtime_cfg.import_results_host = self.common.import_results.host
                if not runtime_cfg.import_results_path:
                    runtime_cfg.import_results_path = self.common.import_results.path

    def get(self, name: str) -> Any | None:
        for candidate in self.provider_names():
            if self._normalize_name(candidate) == self._normalize_name(name):
                return getattr(self, candidate)
        return None

    @staticmethod
    def provider_names() -> Generator[str, None, None]:
        for f in fields(Providers):
            if f.name == "common":
                continue
            yield f.name

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.lower().replace("-", "_")


@dataclass
class Log:
    slim: bool = os.environ.get("VUNNEL_LOG_SLIM", default="false") == "true"
    level: str = os.environ.get("VUNNEL_LOG_LEVEL", default="INFO")
    show_timestamp: bool = os.environ.get("VUNNEL_LOG_SHOW_TIMESTAMP", default="false") == "true"
    show_level: bool = os.environ.get("VUNNEL_LOG_SHOW_LEVEL", default="true") == "true"

    def __post_init__(self) -> None:
        self.level = self.level.upper()


@dataclass
class Application(DataClassDictMixin):
    root: str = "./data"
    log: Log = field(default_factory=Log)
    providers: Providers = field(default_factory=Providers)


def load(path: str = ".vunnel.yaml") -> Application:
    try:
        with open(path, encoding="utf-8") as f:
            app_object = yaml.safe_load(f.read()) or {}
            # we need a full default application config first then merge the loaded config on top.
            # Why? cls.from_dict() will create instances from the dataclass default
            # and NOT the field definition from the container. So it is possible to specify a
            # single field in the config and all other fields would be set to the default value
            # based on the dataclass definition and not any field(default_factory=...) hints
            # from the containing class.
            instance = Application().to_dict()

            mergedeep.merge(instance, app_object)
            cfg = Application.from_dict(instance)
            if cfg is None:
                raise FileNotFoundError("parsed empty config")
    except FileNotFoundError:
        cfg = Application()

    return cfg
