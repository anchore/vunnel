from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, fields, is_dataclass
from typing import TYPE_CHECKING, Any, Union, get_args, get_origin, get_type_hints

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
    user_agent: str | None = None


@dataclass
class Providers:
    alma: providers.alma.Config = field(default_factory=providers.alma.Config)
    alpine: providers.alpine.Config = field(default_factory=providers.alpine.Config)
    amazon: providers.amazon.Config = field(default_factory=providers.amazon.Config)
    arch: providers.arch.Config = field(default_factory=providers.arch.Config)
    bitnami: providers.bitnami.Config = field(default_factory=providers.bitnami.Config)
    chainguard: providers.chainguard.Config = field(default_factory=providers.chainguard.Config)
    chainguard_libraries: providers.chainguard_libraries.Config = field(default_factory=providers.chainguard_libraries.Config)
    debian: providers.debian.Config = field(default_factory=providers.debian.Config)
    echo: providers.echo.Config = field(default_factory=providers.echo.Config)
    eol: providers.eol.Config = field(default_factory=providers.eol.Config)
    epss: providers.epss.Config = field(default_factory=providers.epss.Config)
    fedora: providers.fedora.Config = field(default_factory=providers.fedora.Config)
    github: providers.github.Config = field(default_factory=providers.github.Config)
    kev: providers.kev.Config = field(default_factory=providers.kev.Config)
    mariner: providers.mariner.Config = field(default_factory=providers.mariner.Config)
    minimos: providers.minimos.Config = field(default_factory=providers.minimos.Config)
    nvd: providers.nvd.Config = field(default_factory=providers.nvd.Config)
    oracle: providers.oracle.Config = field(default_factory=providers.oracle.Config)
    rhel: providers.rhel.Config = field(default_factory=providers.rhel.Config)
    rocky: providers.rocky.Config = field(default_factory=providers.rocky.Config)
    secureos: providers.secureos.Config = field(default_factory=providers.secureos.Config)
    sles: providers.sles.Config = field(default_factory=providers.sles.Config)
    ubuntu: providers.ubuntu.Config = field(default_factory=providers.ubuntu.Config)
    wolfi: providers.wolfi.Config = field(default_factory=providers.wolfi.Config)

    common: CommonProviderConfig = field(default_factory=CommonProviderConfig)

    def __post_init__(self) -> None:
        for name in self.provider_names():
            cfg = getattr(self, name)

            runtime_cfg = getattr(cfg, "runtime", None)
            if runtime_cfg and isinstance(runtime_cfg, provider.RuntimeConfig):
                if runtime_cfg.import_results_enabled is None:
                    runtime_cfg.import_results_enabled = self.common.import_results.enabled
                if not runtime_cfg.import_results_host:
                    runtime_cfg.import_results_host = self.common.import_results.host
                if not runtime_cfg.import_results_path:
                    runtime_cfg.import_results_path = self.common.import_results.path
                if runtime_cfg.user_agent is None:
                    runtime_cfg.user_agent = self.common.user_agent

    def get(self, name: str) -> Any | None:
        for candidate in self.provider_names():
            if self._normalize_name(candidate) == self._normalize_name(name):
                return getattr(self, candidate)
        return None

    @staticmethod
    def provider_names() -> Generator[str]:
        for f in fields(Providers):
            if f.name == "common":
                continue
            yield f.name

    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.lower().replace("-", "_")


@dataclass
class Log:
    slim: bool = False
    level: str = "INFO"
    show_timestamp: bool = False
    show_level: bool = True

    def __post_init__(self) -> None:
        self.level = self.level.upper()


@dataclass
class Application(DataClassDictMixin):
    root: str = "./data"
    log: Log = field(default_factory=Log)
    providers: Providers = field(default_factory=Providers)


def _resolve_field_type(obj: Any, field_name: str) -> type | None:
    """
    Resolve the actual type of a dataclass field, handling forward references
    and Optional/Union types.
    """
    try:
        hints = get_type_hints(type(obj))
        field_type = hints.get(field_name)
    except Exception:
        return None

    if field_type is None:
        return None

    # handle Optional[X] and Union[X, None] by extracting the non-None type
    origin = get_origin(field_type)
    if origin is Union:
        # get_args returns the types in the union, e.g., (str, None) for Optional[str]
        args = [arg for arg in get_args(field_type) if arg is not type(None)]
        if len(args) == 1:
            return args[0]
        # for complex unions, fall back to string handling
        return None

    return field_type


def _parse_bool(value: str) -> bool:
    """Parse a string value to boolean, accepting common truthy/falsy values."""
    return value.lower() in ("true", "yes", "1", "on")


def apply_env_overrides(obj: Any, prefix: str = "VUNNEL") -> None:
    """
    Recursively apply env var overrides to dataclass fields.

    Derives env var names from the nested path:
      Application.root             -> VUNNEL_ROOT
      Application.log.slim         -> VUNNEL_LOG_SLIM
      Application.log.level        -> VUNNEL_LOG_LEVEL
      Application.log.show_level   -> VUNNEL_LOG_SHOW_LEVEL

    Supported types:
      - str: assigned directly
      - bool: accepts "true", "yes", "1", "on" (case-insensitive) as truthy
      - int: parsed as integer
      - float: parsed as float

    Environment variables always take precedence over config file values.
    """
    if not is_dataclass(obj):
        return

    for f in fields(obj):
        env_name = f"{prefix}_{f.name}".upper()
        current_value = getattr(obj, f.name)

        # recurse into nested dataclasses
        if is_dataclass(current_value):
            apply_env_overrides(current_value, env_name)
            continue

        if env_name not in os.environ:
            continue

        env_value = os.environ[env_name]

        # resolve the field's type, handling Optional and forward references
        field_type = _resolve_field_type(obj, f.name)

        try:
            coerced_value: bool | int | float | str
            if field_type is bool:
                coerced_value = _parse_bool(env_value)
            elif field_type is int:
                coerced_value = int(env_value)
            elif field_type is float:
                coerced_value = float(env_value)
            else:
                # default to string assignment
                coerced_value = env_value

            setattr(obj, f.name, coerced_value)
            logging.debug("config override: %s=%s", env_name, env_value)

        except ValueError as e:
            type_name = field_type.__name__ if field_type else "unknown"
            raise ValueError(f"invalid value for {env_name}: {env_value!r} (expected {type_name})") from e


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

    # ensure env vars take precedence over config file values
    apply_env_overrides(cfg)

    return cfg
