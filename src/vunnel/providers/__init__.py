from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

from vunnel.providers import (
    alpine,
    amazon,
    chainguard,
    debian,
    github,
    mariner,
    nvd,
    oracle,
    rhel,
    sles,
    ubuntu,
    wolfi,
)

if sys.version_info < (3, 10):
    from importlib_metadata import entry_points
else:
    from importlib.metadata import entry_points

if TYPE_CHECKING:
    from vunnel import provider

_providers: dict[str, type[provider.Provider]] = {
    alpine.Provider.name(): alpine.Provider,
    amazon.Provider.name(): amazon.Provider,
    debian.Provider.name(): debian.Provider,
    github.Provider.name(): github.Provider,
    mariner.Provider.name(): mariner.Provider,
    nvd.Provider.name(): nvd.Provider,
    oracle.Provider.name(): oracle.Provider,
    rhel.Provider.name(): rhel.Provider,
    sles.Provider.name(): sles.Provider,
    ubuntu.Provider.name(): ubuntu.Provider,
    wolfi.Provider.name(): wolfi.Provider,
    chainguard.Provider.name(): chainguard.Provider,
}


def create(name: str, workspace_path: str, *args: Any, **kwargs: Any) -> provider.Provider:
    return _providers[name](workspace_path, *args, **kwargs)


def names() -> list[str]:
    return sorted(_providers.keys())


def versions() -> dict[str, int]:
    return {n: p.version() for (n, p) in _providers.items()}


def register(name: str, cls: type[provider.Provider]) -> None:
    if name in _providers and _providers[name] != cls:
        raise KeyError(f"provider {name!r} is already registered to another provider class: {_providers[name]!r}")
    _providers[name] = cls


def load_plugins() -> None:
    plugins = entry_points(group="vunnel.plugins.providers")

    logging.debug(f"discovered plugins: {len(plugins)}")
    for idx, p in enumerate(plugins):
        branch = "├──"
        if idx == len(plugins) - 1:
            branch = "└──"

        logging.debug(f"{branch} {p.name}: {p.value}")

    for tool in plugins:
        try:
            logging.debug(f"loading provider plugin {tool.name!r}")
            tool.load()
        except Exception:
            # note: this should not be fatal. Log and move on.
            logging.exception(f"failed loading provider plugin {tool.name!r}")
