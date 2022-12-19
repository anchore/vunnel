import os
from dataclasses import dataclass, field, fields
from typing import Any

import dacite
import yaml

from vunnel import provider, providers


@dataclass
class Providers:
    alpine: providers.alpine.Config = field(default_factory=providers.alpine.Config)
    amazon: providers.amazon.Config = field(default_factory=providers.amazon.Config)
    centos: providers.centos.Config = field(default_factory=providers.centos.Config)
    debian: providers.debian.Config = field(default_factory=providers.debian.Config)
    github: providers.github.Config = field(default_factory=providers.github.Config)
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
    level: str = os.environ.get("VUNNEL_LOG_LEVEL", default="INFO")

    def __post_init__(self) -> None:
        self.level = self.level.upper()


@dataclass
class Application:
    root: str = "./data"
    log: Log = field(default_factory=Log)
    providers: Providers = field(default_factory=Providers)


def load(path: str = ".vunnel.yaml") -> Application:  # noqa
    try:
        with open(path, encoding="utf-8") as f:
            app_object = yaml.safe_load(f.read())
            cfg = dacite.from_dict(
                Application,
                app_object,
                config=dacite.Config(
                    cast=[
                        provider.OnErrorAction,
                        provider.InputStatePolicy,
                        provider.ResultStatePolicy,
                    ],
                    # type_hooks={
                    #
                    # }
                ),
            )
            if cfg is None:
                raise FileNotFoundError("parsed empty config")
    except FileNotFoundError:
        cfg = Application()

    return cfg
