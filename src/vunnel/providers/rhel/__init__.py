import datetime
from dataclasses import dataclass, field

from vunnel import provider, result
from vunnel.providers.rhel_csaf import Config as CSAFConfig
from vunnel.providers.rhel_csaf import Provider as RHEL_CSAFProvider
from vunnel.providers.rhel_legacy import Config as LegacyConfig
from vunnel.providers.rhel_legacy import Provider as LegacyRHELProvider

CSAF_PROVIDER = "csaf"
LEGACY_PROVIDER = "legacy"


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
        ),
    )
    request_timeout: int = 125
    parallelism: int = 4
    full_sync_interval: int = 2
    skip_namespaces: list[str] = field(default_factory=lambda: ["rhel:3", "rhel:4"])
    provider_type: str = CSAF_PROVIDER  # "legacy" or "csaf"

    def to_specific_config(self) -> LegacyConfig | CSAFConfig:
        if self.provider_type == LEGACY_PROVIDER:
            return LegacyConfig(
                runtime=self.runtime,
                request_timeout=self.request_timeout,
                parallelism=self.parallelism,
                full_sync_interval=self.full_sync_interval,
                skip_namespaces=self.skip_namespaces,
            )
        if self.provider_type == CSAF_PROVIDER:
            # other fields don't make sense for CSAF Provider
            return CSAFConfig(
                runtime=self.runtime,
                skip_namespaces=self.skip_namespaces,
            )
        raise ValueError(f"invalid config type {self.provider_type}, expected '{LEGACY_PROVIDER}' or '{CSAF_PROVIDER}'")


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()
        super().__init__(root, runtime_cfg=config.runtime)
        self.logger.info(f"config: {config}")
        self._provider_instance: RHEL_CSAFProvider | LegacyRHELProvider | None = None
        specific_config = config.to_specific_config()
        if isinstance(specific_config, CSAFConfig):
            self.logger.info(f"Using provider: {config.provider_type}")
            self._provider_instance = RHEL_CSAFProvider(root, specific_config)
        elif isinstance(specific_config, LegacyConfig):
            self.logger.info(f"Using provider: {config.provider_type}")
            self._provider_instance = LegacyRHELProvider(root, specific_config)
        else:
            raise ValueError(f"unknown provider type {config.provider_type}, expected {LEGACY_PROVIDER} or {CSAF_PROVIDER}")
        self.config = config

    @classmethod
    def name(cls) -> str:
        return "rhel"

    def update(self, last_updated: datetime.datetime | None = None) -> tuple[list[str], int]:
        if not self._provider_instance:
            raise ValueError("attempt to call update on delegating provider with no underlying provider")
        return self._provider_instance.update(last_updated)
