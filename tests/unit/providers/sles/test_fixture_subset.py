from __future__ import annotations

import os

import pytest

from vunnel.utils.csaf_types import from_path

from .fixture_subset import subset_for_sles


@pytest.fixture
def fixture_dir(helpers):
    return helpers.local_dir("test-fixtures/csaf")


class TestSubsetForSles:
    """Covers the fixture-generation trimmer. Not provider code -- but the committed
    fixtures are only as trustworthy as this is, so it stays tested."""

    def test_subset_keeps_only_in_scope_platforms(self, fixture_dir):
        doc = from_path(os.path.join(fixture_dir, "cve-2019-8608.json"))
        subsetted = subset_for_sles(doc, allow_versions=["15"])
        assert subsetted is not None

        names = {b.product.name for b in subsetted.product_tree.product_branches() if b.product}
        assert "SUSE Linux Enterprise Server 15 SP1" in names
        assert "SUSE Linux Enterprise Server 15 SP1-LTSS" in names
        # out-of-scope product lines from the real doc must not survive subsetting
        assert not any("SAP" in n or "Storage" in n or "Helion" in n for n in names)

    def test_subset_returns_none_when_nothing_in_scope(self, fixture_dir):
        doc = from_path(os.path.join(fixture_dir, "cve-2004-2771.json"))
        assert subset_for_sles(doc, allow_versions=["99"]) is None
