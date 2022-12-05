from dataclasses import dataclass, field, fields
from typing import Any, Optional

import yaml

from vunnel import providers


@dataclass
class Providers:
    centos: providers.centos.Config = field(default_factory=providers.centos.Config)
    nvd: providers.nvd.Config = field(default_factory=providers.nvd.Config)

    def get(self, name: str) -> Optional[Any]:
        for f in fields(Providers):
            if self._normalize_name(f.name) == self._normalize_name(name):
                return getattr(self, f.name)
        return None

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.lower().replace("-", "_")


@dataclass
class Application:
    root: str = "./data"
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


def dataclass_from_dict(cls, d):
    try:
        fieldtypes = {f.name: f.type for f in fields(cls)}
        return cls(**{f: dataclass_from_dict(fieldtypes[f], d[f]) for f in d})
    except TypeError:
        pass
    return d


def load(path: str = ".vunnel.yaml") -> Application:  # pylint: disable=unused-argument
    try:
        with open(path, encoding="utf-8") as f:
            app_object = yaml.safe_load(f.read())
            cfg = dataclass_from_dict(Application, app_object)
            if cfg is None:
                raise FileNotFoundError("parsed empty config")
    except FileNotFoundError:
        cfg = Application()

    return cfg
