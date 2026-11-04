from __future__ import annotations

import pytest

from vunnel import result
from vunnel.providers.chainguard_libraries import Config, Provider


def test_provider_via_snapshot(helpers, disable_get_requests, monkeypatch, auto_fake_fixdate_finder):
    workspace = helpers.provider_workspace_helper(
        name=Provider.name(),
        input_fixture="test-fixtures/input",
        snapshot_prefix="openvex"
    )
    c = Config()
    # keep all of the default values for the result store, but override the strategy
    c.runtime.result_store = result.StoreStrategy.FLAT_FILE
    p = Provider(
        root=workspace.root,
        config=c,
    )
    def mock_download(filename: str):
        return None
    monkeypatch.setattr(p.parser, "_download", mock_download)

    p.update(None)

    workspace.assert_result_snapshots()


def test_version_markers_merge_from_config_file(tmpdir, auto_fake_fixdate_finder):
    from vunnel.cli import config

    cfg_path = tmpdir.join("vunnel.yaml")
    cfg_path.write(
        """
providers:
  chainguard_libraries:
    version_markers:
      npm: null
      gem: -cgr.
""",
    )
    c = config.load(str(cfg_path)).providers.chainguard_libraries
    p = Provider(root=str(tmpdir), config=c)

    # unmentioned defaults survive the merge, a null removes one, and a new type can be added
    assert p.parser.version_markers == {"pypi": "+cgr.", "maven": ".cgr.", "golang": "-cgr.", "gem": "-cgr."}


def test_version_markers_rejects_env_string(tmpdir, auto_fake_fixdate_finder):
    c = Config()
    # env var overrides assign the raw string to non-scalar fields
    c.version_markers = "pypi=+cgr."  # type: ignore[assignment]

    with pytest.raises(ValueError, match="version_markers must be a map"):
        Provider(root=str(tmpdir), config=c)
