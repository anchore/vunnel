from __future__ import annotations

import enum
import logging
import os
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from vunnel.providers import (
    alma,
    alpine,
    amazon,
    arch,
    bellsoft,
    bitnami,
    chainguard,
    chainguard_libraries,
    debian,
    echo,
    eol,
    epss,
    fedora,
    github,
    govulndb,
    hummingbird,
    kev,
    mariner,
    minimos,
    nvd,
    oracle,
    photon,
    rhel,
    rocky,
    secureos,
    sles,
    ubuntu,
    wolfi,
)

if TYPE_CHECKING:
    from vunnel import provider

from vunnel.provider import get_provider_tags

_providers: dict[str, type[provider.Provider]] = {
    # vulnerability providers
    alma.Provider.name(): alma.Provider,
    alpine.Provider.name(): alpine.Provider,
    amazon.Provider.name(): amazon.Provider,
    arch.Provider.name(): arch.Provider,
    bellsoft.Provider.name(): bellsoft.Provider,
    bitnami.Provider.name(): bitnami.Provider,
    debian.Provider.name(): debian.Provider,
    echo.Provider.name(): echo.Provider,
    fedora.Provider.name(): fedora.Provider,
    github.Provider.name(): github.Provider,
    govulndb.Provider.name(): govulndb.Provider,
    hummingbird.Provider.name(): hummingbird.Provider,
    mariner.Provider.name(): mariner.Provider,
    nvd.Provider.name(): nvd.Provider,
    oracle.Provider.name(): oracle.Provider,
    photon.Provider.name(): photon.Provider,
    rhel.Provider.name(): rhel.Provider,
    rocky.Provider.name(): rocky.Provider,
    secureos.Provider.name(): secureos.Provider,
    sles.Provider.name(): sles.Provider,
    ubuntu.Provider.name(): ubuntu.Provider,
    wolfi.Provider.name(): wolfi.Provider,
    chainguard.Provider.name(): chainguard.Provider,
    chainguard_libraries.Provider.name(): chainguard_libraries.Provider,
    minimos.Provider.name(): minimos.Provider,
    # auxiliary vulnerability data (decorates vulnerability entries from providers)
    kev.Provider.name(): kev.Provider,
    epss.Provider.name(): epss.Provider,
    eol.Provider.name(): eol.Provider,
}


class PluginOverrideMode(str, enum.Enum):
    # fail: a plugin registering a name that already exists as a different class raises (default, historical behavior)
    FAIL = "fail"
    # replace: the plugin wins over the built-in of the same name
    REPLACE = "replace"
    # ignore: the plugin is dropped when a built-in of the same name already exists (built-in wins)
    IGNORE = "ignore"

    @classmethod
    def from_env(cls) -> PluginOverrideMode:
        raw = os.environ.get("VUNNEL_PLUGIN_OVERRIDE_MODE", "").strip().lower()
        try:
            return cls(raw)
        except ValueError:
            return cls.FAIL


def create(name: str, workspace_path: str, *args: Any, **kwargs: Any) -> provider.Provider:
    return _providers[name](workspace_path, *args, **kwargs)


def names() -> list[str]:
    return sorted(_providers.keys())


def versions() -> dict[str, int]:
    return {n: p.version() for (n, p) in _providers.items()}


def register(name: str, cls: type[provider.Provider], mode: PluginOverrideMode | None = None) -> None:
    # plugins call register() themselves during load_plugins(), so the override mode is resolved here at call
    # time from the environment (VUNNEL_PLUGIN_OVERRIDE_MODE) unless an explicit mode is passed. unset/unknown
    # resolves to FAIL, preserving the historical behavior for any direct caller that doesn't opt in.
    effective_mode = mode if mode is not None else PluginOverrideMode.from_env()
    existing = _providers.get(name)
    if existing is not None and existing != cls:
        if effective_mode == PluginOverrideMode.REPLACE:
            logging.warning(f"provider {name!r}: replacing {existing!r} with plugin {cls!r}")
        elif effective_mode == PluginOverrideMode.IGNORE:
            logging.warning(f"provider {name!r}: ignoring plugin {cls!r}, keeping existing {existing!r}")
            return
        else:
            raise KeyError(f"provider {name!r} is already registered to another provider class: {existing!r}")
    _providers[name] = cls


def load_plugins() -> None:
    logging.debug(f"plugin override mode: {PluginOverrideMode.from_env().value}")

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


def provider_class(name: str) -> type[provider.Provider]:
    """Return the provider class for a given provider name."""
    return _providers[name]


def providers_with_tags(required_tags: list[str]) -> list[str]:
    """Return provider names that match tag criteria.

    Tags prefixed with '!' are exclusion filters.
    Providers must have ALL non-negated tags AND NONE of the negated tags.

    Raises:
        ValueError: If a tag is empty or just '!' with no tag name.
    """
    if not required_tags:
        return names()

    include_tags = set()
    exclude_tags = set()
    for tag in required_tags:
        if tag.startswith("!"):
            tag_name = tag[1:]
            if not tag_name:
                raise ValueError("invalid tag: '!' requires a tag name (e.g., '!os')")
            exclude_tags.add(tag_name)
        else:
            include_tags.add(tag)

    result = []
    for name, cls in _providers.items():
        provider_tags = set(get_provider_tags(cls))
        # must have ALL include tags
        if include_tags and not include_tags.issubset(provider_tags):
            continue
        # must have NONE of the exclude tags
        if exclude_tags and exclude_tags.intersection(provider_tags):
            continue
        result.append(name)
    return sorted(result)
