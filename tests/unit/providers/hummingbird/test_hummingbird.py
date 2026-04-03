from __future__ import annotations

import orjson
import pytest

from vunnel import result
from vunnel.providers.hummingbird import Config, Provider
from vunnel.providers.hummingbird.parser import Parser


@pytest.fixture()
def mock_input_path(helpers):
    return helpers.local_dir("test-fixtures/input")


class TestParser:
    """Unit tests for the CSAF VEX subsetting logic."""

    @pytest.fixture()
    def parser(self, helpers, mock_input_path):
        workspace = helpers.provider_workspace_helper(
            name="hummingbird",
            input_fixture=mock_input_path,
        )
        return Parser(
            workspace=workspace,
            logger=Provider.__new__(Provider).__class__.__mro__[0].__new__(Provider).__class__.__mro__[0],
            skip_download=True,
        )

    @pytest.fixture()
    def sample_doc(self, helpers):
        path = helpers.local_dir("test-fixtures/input/advisories/2026/cve-2026-12345.json")
        with open(path, "rb") as f:
            return orjson.loads(f.read())

    def test_subset_skips_non_hummingbird_cve(self, helpers):
        """A CVE with no hummingbird products should be skipped entirely."""
        path = helpers.local_dir("test-fixtures/input/advisories/2026/cve-2026-99999.json")
        with open(path, "rb") as f:
            doc = orjson.loads(f.read())
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(doc)
        assert result is None

    def test_subset_keeps_hummingbird_products(self, sample_doc):
        """Subsetting should keep hummingbird platform and package branches."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        # verify product tree has hummingbird platform branch
        branch_ids = _collect_branch_product_ids(result["product_tree"]["branches"])
        assert "hummingbird-1" in branch_ids

        # verify package branches with PURLs are preserved
        assert "testpkg-0:1.2.3-1.hum1.src" in branch_ids
        assert "otherpkg" in branch_ids

    def test_subset_filters_rhel_relationships(self, sample_doc):
        """RHEL relationships sharing a package name should be filtered out."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        rel_ids = {r["full_product_name"]["product_id"] for r in result["product_tree"]["relationships"]}
        # hummingbird relationships kept
        assert "hummingbird-1:testpkg-0:1.2.3-1.hum1.src" in rel_ids
        assert "hummingbird-1:otherpkg" in rel_ids
        # RHEL relationship filtered
        assert "rhel-9:otherpkg" not in rel_ids

    def test_subset_filters_product_status(self, sample_doc):
        """Product status should only contain hummingbird composite IDs."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        vuln = result["vulnerabilities"][0]
        ps = vuln["product_status"]

        assert ps["fixed"] == ["hummingbird-1:testpkg-0:1.2.3-1.hum1.src"]
        assert ps["known_not_affected"] == ["hummingbird-1:otherpkg"]
        # RHEL known_affected should be gone
        assert "known_affected" not in ps

    def test_subset_filters_scores(self, sample_doc):
        """Scores should only reference hummingbird product IDs."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        vuln = result["vulnerabilities"][0]
        score_products = vuln["scores"][0]["products"]
        assert "rhel-9:otherpkg" not in score_products
        assert "hummingbird-1:testpkg-0:1.2.3-1.hum1.src" in score_products
        assert "hummingbird-1:otherpkg" in score_products

    def test_subset_filters_remediations(self, sample_doc):
        """Remediations should only contain hummingbird product IDs."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        vuln = result["vulnerabilities"][0]
        rem = vuln["remediations"][0]
        assert rem["product_ids"] == ["hummingbird-1:testpkg-0:1.2.3-1.hum1.src"]

    def test_subset_removes_rhel_branches(self, sample_doc):
        """RHEL platform branch should not survive pruning."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        branch_ids = _collect_branch_product_ids(result["product_tree"]["branches"])
        assert "rhel-9" not in branch_ids

    def test_subset_preserves_purls(self, sample_doc):
        """Package branches must retain their PURL for downstream use."""
        p = Parser(workspace=None, logger=_make_logger(), skip_download=True)
        result = p._subset_document(sample_doc)
        assert result is not None

        purls = _collect_branch_purls(result["product_tree"]["branches"])
        assert "pkg:rpm/redhat/testpkg@1.2.3-1.hum1?arch=src" in purls
        assert "pkg:rpm/redhat/otherpkg" in purls


class TestProviderSchema:
    """Integration test: run the provider end-to-end and validate result schema."""

    def test_provider_schema(self, helpers, mock_input_path, monkeypatch):
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

        # if any HTTP request is made, this will raise
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


def _collect_branch_product_ids(branches: list[dict]) -> set[str]:
    ids = set()
    for b in branches:
        p = b.get("product")
        if p and p.get("product_id"):
            ids.add(p["product_id"])
        ids |= _collect_branch_product_ids(b.get("branches", []))
    return ids


def _collect_branch_purls(branches: list[dict]) -> set[str]:
    purls = set()
    for b in branches:
        p = b.get("product")
        if p:
            helper = p.get("product_identification_helper", {})
            purl = helper.get("purl")
            if purl:
                purls.add(purl)
        purls |= _collect_branch_purls(b.get("branches", []))
    return purls
