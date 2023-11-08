from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Any

import mergedeep
import yaml
from mashumaro.mixins.dict import DataClassDictMixin

from vunnel import providers


@dataclass
class Providers:
    alpine: providers.alpine.Config = field(default_factory=providers.alpine.Config)
    amazon: providers.amazon.Config = field(default_factory=providers.amazon.Config)
    chainguard: providers.chainguard.Config = field(default_factory=providers.chainguard.Config)
    debian: providers.debian.Config = field(default_factory=providers.debian.Config)
    github: providers.github.Config = field(default_factory=providers.github.Config)
    mariner: providers.mariner.Config = field(default_factory=providers.mariner.Config)
    nvd: providers.nvd.Config = field(default_factory=providers.nvd.Config)
    oracle: providers.oracle.Config = field(default_factory=providers.oracle.Config)
    rhel: providers.rhel.Config = field(default_factory=providers.rhel.Config)
    sles: providers.sles.Config = field(default_factory=providers.sles.Config)
    ubuntu: providers.ubuntu.Config = field(default_factory=providers.ubuntu.Config)
    wolfi: providers.wolfi.Config = field(default_factory=providers.wolfi.Config)

    def get(self, name: str) -> Any | None:
        for f in fields(Providers):
            if self._normalize_name(f.name) == self._normalize_name(name):
                return getattr(self, f.name)
        return None

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.lower().replace("-", "_")


@dataclass
class Log:
    slim: bool = os.environ.get("VUNNEL_LOG_SLIM", default="false") == "true"
    level: str = os.environ.get("VUNNEL_LOG_LEVEL", default="INFO")  # noqa: RUF009
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
