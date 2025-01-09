import pytest
from vunnel.providers.rhel import CSAF_PROVIDER, LEGACY_PROVIDER, Config, Provider
from vunnel.providers.rhel_csaf import Provider as CSAFProvider
from vunnel.providers.rhel_legacy import Provider as LegacyProvider


@pytest.mark.parametrize(
    "config,expected_provider_type",
    [
        (Config(), CSAFProvider),
        (Config(provider_type="csaf"), CSAFProvider),
        (Config(provider_type=CSAF_PROVIDER), CSAFProvider),
        (Config(provider_type="legacy"), LegacyProvider),
        (Config(provider_type=LEGACY_PROVIDER), LegacyProvider),
    ],
)
def test_rhel_base_provider(config: Config, expected_provider_type, tmp_path):
    p = Provider(root=tmp_path, config=config)
    assert isinstance(p._provider_instance, expected_provider_type)
