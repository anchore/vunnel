import os
from dataclasses import dataclass, field, fields
from typing import Any, Optional

import yaml

from vunnel import providers, utils


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

    def get(self, name: str) -> Optional[Any]:
        for f in fields(Providers):
            if self._normalize_name(f.name) == self._normalize_name(name):
                return getattr(self, f.name)
        return None

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.lower().replace("-", "_")


@dataclass
class Log:
    slim: bool = os.environ.get("VUNNEL_LOG_SLIM", default=False) == "true"
    level: str = os.environ.get("VUNNEL_LOG_LEVEL", default="INFO")


@dataclass
class Application:
    root: str = "./data"
    log: Log = field(default_factory=Log)
    providers: Providers = field(default_factory=Providers)


def clean_dict_keys(d):
    new = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = clean_dict_keys(v)
        new[k.replace("-", "_")] = v
    return new


def yaml_decoder(data) -> dict[Any, Any]:
    return clean_dict_keys(yaml.load(data, yaml.CSafeLoader))


def load(path: str = ".vunnel.yaml") -> Application:  # pylint: disable=unused-argument
    try:
        with open(path, encoding="utf-8") as f:
            app_object = yaml.safe_load(f.read())
            cfg = utils.dataclass_from_dict(Application, app_object)
            if cfg is None:
                raise FileNotFoundError("parsed empty config")
    except FileNotFoundError:
        cfg = Application()

    return cfg
