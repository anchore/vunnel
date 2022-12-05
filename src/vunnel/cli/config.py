from dataclasses import dataclass, field, fields
from typing import Any, Optional

from vunnel import providers


@dataclass
class Providers:
    centos: providers.centos.Config = field(default_factory=providers.centos.Config)
    nvdv2: providers.nvdv2.Config = field(default_factory=providers.nvdv2.Config)

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
    provider: Providers = field(default_factory=Providers)


def load(path: str) -> Application:  # pylint: disable=unused-argument
    # TODO: read application config from disk
    return Application()
