from __future__ import annotations

import pytest

from vunnel import result
from vunnel.providers.hummingbird import Config, Provider
from vunnel.providers.hummingbird.parser import Parser
from vunnel.utils.csaf_types import from_path


@pytest.fixture()
def mock_input_path(helpers):
    return helpers.local_dir("test-fixtures/input")


class TestParser:
    """Unit tests for the CSAF VEX subsetting logic."""

    @pytest.fixture()
    def sample_doc(self, helpers):
        path = helpers.local_dir("test-fixtures/input/advisories/2026/cve-2026-12345.json")
        return from_path(path)

    @pytest.fixture()
    def non_hb_doc(self, helpers):
        path = helpers.local_dir("test-fixtures/input/advisories/2026/cve-2026-99999.json")
        return from_path(path)

    def test_subset_skips_non_hummingbird_cve(self, non_hb_doc):
        """A CVE with no hummingbird products should be skipped entirely."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        assert p._subset_document(non_hb_doc) is None

    def test_subset_keeps_hummingbird_products(self, sample_doc):
        """Subsetting should keep hummingbird platform and package branches."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        branch_ids = {b.product.product_id for b in result.product_tree.product_branches() if b.product}
        assert "hummingbird-1" in branch_ids
        assert "testpkg-0:1.2.3-1.hum1.src" in branch_ids
        assert "otherpkg" in branch_ids

    def test_subset_filters_rhel_relationships(self, sample_doc):
        """RHEL relationships sharing a package name should be filtered out."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        rel_ids = {r.full_product_name.product_id for r in result.product_tree.relationships}
        assert "hummingbird-1:testpkg-0:1.2.3-1.hum1.src" in rel_ids
        assert "hummingbird-1:otherpkg" in rel_ids
        assert "rhel-9:otherpkg" not in rel_ids

    def test_subset_filters_product_status(self, sample_doc):
        """Product status should only contain hummingbird composite IDs."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        ps = result.vulnerabilities[0].product_status
        assert ps is not None
        assert ps.fixed == ["hummingbird-1:testpkg-0:1.2.3-1.hum1.src"]
        assert ps.known_not_affected == ["hummingbird-1:otherpkg"]
        assert ps.known_affected == []

    def test_subset_filters_scores(self, sample_doc):
        """Scores should only reference hummingbird product IDs."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        score_products = result.vulnerabilities[0].scores[0].products
        assert "rhel-9:otherpkg" not in score_products
        assert "hummingbird-1:testpkg-0:1.2.3-1.hum1.src" in score_products
        assert "hummingbird-1:otherpkg" in score_products

    def test_subset_filters_remediations(self, sample_doc):
        """Remediations should only contain hummingbird product IDs."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        rem = result.vulnerabilities[0].remediations[0]
        assert rem.product_ids == ["hummingbird-1:testpkg-0:1.2.3-1.hum1.src"]

    def test_subset_removes_rhel_branches(self, sample_doc):
        """RHEL platform branch should not survive pruning."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        branch_ids = {b.product.product_id for b in result.product_tree.product_branches() if b.product}
        assert "rhel-9" not in branch_ids

    def test_subset_preserves_purls(self, sample_doc):
        """Package branches must retain their PURL for downstream use."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        purls = {b.purl() for b in result.product_tree.product_branches() if b.purl()}
        assert "pkg:rpm/redhat/testpkg@1.2.3-1.hum1?arch=src" in purls
        assert "pkg:rpm/redhat/otherpkg" in purls


class TestProviderSchema:
    """Integration test: run the provider end-to-end and validate result schema."""

    def test_provider_schema(self, helpers, mock_input_path):
        workspace = helpers.provider_workspace_helper(
            name="hummingbird",
            input_fixture=mock_input_path,
        )
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.runtime.skip_download = True
        p = Provider(root=workspace.root, config=c)

        p.update(None)

        # only cve-2026-12345 should produce output (cve-2026-99999 has no hummingbird content)
        assert workspace.num_result_entries() == 1

    def test_provider_skip_download(self, helpers, mock_input_path, monkeypatch):
        """With skip_download=True, no HTTP requests should be made."""
        workspace = helpers.provider_workspace_helper(
            name="hummingbird",
            input_fixture=mock_input_path,
        )
        c = Config()
        c.runtime.result_store = result.StoreStrategy.FLAT_FILE
        c.runtime.skip_download = True
        p = Provider(root=workspace.root, config=c)

        monkeypatch.setattr("vunnel.utils.http_wrapper.get", _fail_on_http)

        p.update(None)

        assert workspace.num_result_entries() == 1


# ── helpers ───────────────────────────────────────────────────────────


def _fail_on_http(*args, **kwargs):
    raise RuntimeError("HTTP request attempted during skip_download test")


class _NullLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def exception(self, *a, **k): pass


def _make_logger():
    return _NullLogger()
