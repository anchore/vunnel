from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from vunnel.providers import (
    alma,
    alpine,
    amazon,
    bitnami,
    chainguard,
    chainguard_libraries,
    debian,
    echo,
    epss,
    github,
    kev,
    mariner,
    minimos,
    nvd,
    oracle,
    rhel,
    rocky,
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
    bitnami.Provider.name(): bitnami.Provider,
    debian.Provider.name(): debian.Provider,
    echo.Provider.name(): echo.Provider,
    github.Provider.name(): github.Provider,
    mariner.Provider.name(): mariner.Provider,
    nvd.Provider.name(): nvd.Provider,
    oracle.Provider.name(): oracle.Provider,
    rhel.Provider.name(): rhel.Provider,
    rocky.Provider.name(): rocky.Provider,
    sles.Provider.name(): sles.Provider,
    ubuntu.Provider.name(): ubuntu.Provider,
    wolfi.Provider.name(): wolfi.Provider,
    chainguard.Provider.name(): chainguard.Provider,
    chainguard_libraries.Provider.name(): chainguard_libraries.Provider,
    minimos.Provider.name(): minimos.Provider,
    # auxiliary vulnerability data (decorates vulnerability entries from providers)
    kev.Provider.name(): kev.Provider,
    epss.Provider.name(): epss.Provider,
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
