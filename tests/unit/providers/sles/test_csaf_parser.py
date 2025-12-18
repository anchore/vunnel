from __future__ import annotations

import pytest

from vunnel.providers.sles.csaf_parser import is_sles_cpe, subset_csaf_for_sles


class TestIsSlesCpe:
    @pytest.mark.parametrize(
        "cpe,expected",
        [
            # Should match - base SLES
            ("cpe:/o:suse:sles:15:sp6", True),
            ("cpe:/o:suse:sles:12:sp5", True),
            ("cpe:/o:suse:sles:15:sp2", True),
            # Should match - LTSS variants
            ("cpe:/o:suse:sles-ltss:15:sp1", True),
            ("cpe:/o:suse:sles-ltss:12:sp4", True),
            ("cpe:/o:suse:sles-ltss:15", True),  # no SP
            # Should match - older LTSS format (11)
            ("cpe:/o:suse:suse_sles_ltss:11:sp4", True),
            # Should match - BCL
            ("cpe:/o:suse:sles-bcl:12:sp2", True),
            # Should match - ESPOS
            ("cpe:/o:suse:sles-espos:12:sp4", True),
            # Should NOT match - SAP
            ("cpe:/o:suse:sles_sap:15:sp6", False),
            ("cpe:/o:suse:sles_sap:12:sp5", False),
            # Should NOT match - Teradata
            ("cpe:/o:suse:sles_teradata:12:sp3", False),
            # Should NOT match - Extreme Core
            ("cpe:/o:suse:suse_sles_ltss-extreme-core:11:sp4", False),
            # Should NOT match - Cloud host images (too many parts)
            ("cpe:/o:suse:sles:15:sp1:chost-amazon:suse-sles-15-sp1-chost-byos-v20210304-hvm-ssd-x86_64", False),
            ("cpe:/o:suse:sles:15:sp3:chost-google:sles-15-sp3-chost-byos-v20220718-x86-64", False),
            ("cpe:/o:suse:sles:15:sp4:chost-microsoft:suse-sles-15-sp4-chost-byos-v20220718-x86_64", False),
            # Should NOT match - other products
            ("cpe:/o:suse:sled:15:sp6", False),  # Desktop
            ("cpe:/o:suse:sle-hpc:15:sp6", False),  # HPC
            ("cpe:/o:suse:sle_hpc-espos:15:sp4", False),  # HPC ESPOS
            ("cpe:/o:suse:ses:7.1", False),  # Enterprise Storage
            ("cpe:/o:suse:sll:8", False),  # Liberty Linux
            # Edge cases
            ("", False),
            ("cpe:/o:suse:sles", False),  # no version
        ],
    )
    def test_is_sles_cpe(self, cpe: str, expected: bool):
        assert is_sles_cpe(cpe) == expected


class TestSubsetCsafForSles:
    def _make_doc_with_branches_and_relationships(
        self,
        platforms: list[dict],
        relationships: list[dict],
        product_status: dict,
        packages: list[dict] | None = None,
    ) -> dict:
        """Helper to create a CSAF doc with proper branch/relationship structure.

        Args:
            platforms: Platform branches (with CPEs)
            relationships: Package-to-platform relationships
            product_status: Vulnerability product status dict
            packages: Optional package branches (with PURLs) - separate subtree
        """
        vendor_branches = [
            {
                "category": "product_family",
                "name": "SUSE Linux Enterprise",
                "branches": platforms,
            }
        ]
        if packages:
            vendor_branches.append({
                "category": "product_family",
                "name": "SUSE Package Hub",
                "branches": packages,
            })

        return {
            "document": {"title": "Test CVE"},
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": "SUSE",
                        "branches": vendor_branches,
                    }
                ],
                "relationships": relationships,
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-1234",
                    "product_status": product_status,
                }
            ],
        }

    def _make_platform_branch(self, name: str, cpe: str) -> dict:
        """Helper to create a platform branch with CPE."""
        return {
            "category": "product_name",
            "name": name,
            "product": {
                "name": name,
                "product_id": name,
                "product_identification_helper": {"cpe": cpe},
            },
        }

    def _make_relationship(self, platform_id: str, package_id: str) -> dict:
        """Helper to create a package relationship."""
        return {
            "category": "default_component_of",
            "full_product_name": {
                "name": f"{package_id} as component of {platform_id}",
                "product_id": f"{platform_id}:{package_id}",
            },
            "product_reference": package_id,
            "relates_to_product_reference": platform_id,
        }

    def _make_package_branch(self, package_id: str, purl: str, cpe: str | None = None) -> dict:
        """Helper to create a package branch with PURL and optional CPE."""
        helper: dict = {"purl": purl}
        if cpe:
            helper["cpe"] = cpe
        return {
            "category": "product_version",
            "name": package_id,
            "product": {
                "name": package_id,
                "product_id": package_id,
                "product_identification_helper": helper,
            },
        }

    def test_returns_none_when_no_sles_products(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": ["SUSE Linux Enterprise Desktop 15 SP6:package-1.0"],
            },
        )
        result = subset_csaf_for_sles(doc)
        assert result is None

    def test_filters_to_sles_only(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": [
                    "SUSE Linux Enterprise Server 15 SP6:package-1.0",
                    "SUSE Linux Enterprise Desktop 15 SP6:package-1.0",
                ],
            },
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None
        vuln = result["vulnerabilities"][0]
        assert vuln["product_status"]["recommended"] == [
            "SUSE Linux Enterprise Server 15 SP6:package-1.0",
        ]
        # Only SLES relationship should remain
        assert len(result["product_tree"]["relationships"]) == 1

    def test_includes_ltss_variants(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP3-LTSS",
                    "cpe:/o:suse:sles-ltss:15:sp3",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP3-LTSS",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": ["SUSE Linux Enterprise Server 15 SP3-LTSS:package-1.0"],
            },
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None
        assert "SUSE Linux Enterprise Server 15 SP3-LTSS:package-1.0" in result["vulnerabilities"][0]["product_status"]["recommended"]

    def test_excludes_cloud_host_images(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SLES 15 SP3 CHOST Images for Amazon EC2",
                    "cpe:/o:suse:sles:15:sp3:chost-amazon:suse-sles-15-sp3-chost-byos-v20220718-hvm-ssd-x86_64",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SLES 15 SP3 CHOST Images for Amazon EC2",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": [
                    "SUSE Linux Enterprise Server 15 SP6:package-1.0",
                    "SLES 15 SP3 CHOST Images for Amazon EC2:package-1.0",
                ],
            },
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None
        # Only base SLES should remain, not cloud host
        assert result["vulnerabilities"][0]["product_status"]["recommended"] == [
            "SUSE Linux Enterprise Server 15 SP6:package-1.0",
        ]

    def test_excludes_sap_variants(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server for SAP Applications 15 SP6",
                    "cpe:/o:suse:sles_sap:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Server for SAP Applications 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": [
                    "SUSE Linux Enterprise Server 15 SP6:package-1.0",
                    "SUSE Linux Enterprise Server for SAP Applications 15 SP6:package-1.0",
                ],
            },
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None
        assert result["vulnerabilities"][0]["product_status"]["recommended"] == [
            "SUSE Linux Enterprise Server 15 SP6:package-1.0",
        ]

    def test_returns_none_when_only_known_not_affected(self):
        """If only known_not_affected remains after filtering, skip the record."""
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "known_not_affected": ["SUSE Linux Enterprise Server 15 SP6:package-1.0"],
            },
        )
        result = subset_csaf_for_sles(doc)
        assert result is None

    def test_returns_doc_when_has_actionable_status(self):
        """Should return doc if there's recommended/fixed/known_affected for SLES."""
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-0.9",
                ),
            ],
            product_status={
                "known_not_affected": ["SUSE Linux Enterprise Server 15 SP6:package-1.0"],
                "known_affected": ["SUSE Linux Enterprise Server 15 SP6:package-0.9"],
            },
        )
        result = subset_csaf_for_sles(doc)
        assert result is not None
        assert "known_affected" in result["vulnerabilities"][0]["product_status"]

    def test_preserves_platform_branches_with_cpes(self):
        """Platform branches with CPEs should be preserved."""
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": ["SUSE Linux Enterprise Server 15 SP6:package-1.0"],
            },
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None
        # The SLES platform branch should be preserved with its CPE
        sle_branches = result["product_tree"]["branches"][0]["branches"][0]["branches"]
        assert len(sle_branches) == 1
        assert sle_branches[0]["name"] == "SUSE Linux Enterprise Server 15 SP6"
        assert sle_branches[0]["product"]["product_identification_helper"]["cpe"] == "cpe:/o:suse:sles:15:sp6"

    def test_preserves_document_metadata(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": ["SUSE Linux Enterprise Server 15 SP6:package-1.0"],
            },
        )
        doc["document"]["category"] = "csaf_vex"
        doc["document"]["csaf_version"] = "2.0"

        result = subset_csaf_for_sles(doc)

        assert result is not None
        assert result["document"] == doc["document"]

    def test_does_not_modify_original(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": [
                    "SUSE Linux Enterprise Server 15 SP6:package-1.0",
                    "SUSE Linux Enterprise Desktop 15 SP6:package-1.0",
                ],
            },
        )
        original_products = doc["vulnerabilities"][0]["product_status"]["recommended"].copy()

        subset_csaf_for_sles(doc)

        # Original should be unchanged
        assert doc["vulnerabilities"][0]["product_status"]["recommended"] == original_products

    def test_filters_remediations(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": ["SUSE Linux Enterprise Server 15 SP6:package-1.0"],
            },
        )
        doc["vulnerabilities"][0]["remediations"] = [
            {
                "category": "vendor_fix",
                "details": "Update package",
                "product_ids": [
                    "SUSE Linux Enterprise Server 15 SP6:package-1.0",
                    "SUSE Linux Enterprise Desktop 15 SP6:package-1.0",
                ],
            }
        ]

        result = subset_csaf_for_sles(doc)

        assert result is not None
        remediation = result["vulnerabilities"][0]["remediations"][0]
        assert remediation["product_ids"] == [
            "SUSE Linux Enterprise Server 15 SP6:package-1.0",
        ]

    def test_filters_scores(self):
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "package-1.0",
                ),
            ],
            product_status={
                "recommended": ["SUSE Linux Enterprise Server 15 SP6:package-1.0"],
            },
        )
        doc["vulnerabilities"][0]["scores"] = [
            {
                "cvss_v3": {"baseScore": 7.5, "version": "3.1"},
                "products": [
                    "SUSE Linux Enterprise Server 15 SP6:package-1.0",
                    "SUSE Linux Enterprise Desktop 15 SP6:package-1.0",
                ],
            }
        ]

        result = subset_csaf_for_sles(doc)

        assert result is not None
        score = result["vulnerabilities"][0]["scores"][0]
        assert score["products"] == [
            "SUSE Linux Enterprise Server 15 SP6:package-1.0",
        ]

    def test_preserves_package_branches_with_purls(self):
        """Package branches with PURLs should be preserved when related to SLES platforms."""
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "kernel-default-5.14.21",
                ),
            ],
            product_status={
                "fixed": ["SUSE Linux Enterprise Server 15 SP6:kernel-default-5.14.21"],
            },
            packages=[
                self._make_package_branch(
                    "kernel-default-5.14.21",
                    "pkg:rpm/suse/kernel-default@5.14.21?arch=x86_64",
                ),
                self._make_package_branch(
                    "other-package-1.0",
                    "pkg:rpm/suse/other-package@1.0?arch=x86_64",
                ),
            ],
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None

        # Find all PURLs in the result
        def find_purls(obj: dict | list) -> list[str]:
            purls = []
            if isinstance(obj, dict):
                if "purl" in obj and obj["purl"]:
                    purls.append(obj["purl"])
                for v in obj.values():
                    purls.extend(find_purls(v))
            elif isinstance(obj, list):
                for item in obj:
                    purls.extend(find_purls(item))
            return purls

        purls = find_purls(result["product_tree"]["branches"])

        # The kernel package PURL should be preserved (related to SLES)
        assert "pkg:rpm/suse/kernel-default@5.14.21?arch=x86_64" in purls
        # The other package PURL should NOT be preserved (not related to SLES)
        assert "pkg:rpm/suse/other-package@1.0?arch=x86_64" not in purls

    def test_filters_out_non_sles_package_branches(self):
        """Package branches not related to SLES platforms should be filtered out."""
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
                self._make_platform_branch(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "cpe:/o:suse:sled:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "sles-package-1.0",
                ),
                self._make_relationship(
                    "SUSE Linux Enterprise Desktop 15 SP6",
                    "desktop-package-1.0",
                ),
            ],
            product_status={
                "fixed": [
                    "SUSE Linux Enterprise Server 15 SP6:sles-package-1.0",
                    "SUSE Linux Enterprise Desktop 15 SP6:desktop-package-1.0",
                ],
            },
            packages=[
                self._make_package_branch(
                    "sles-package-1.0",
                    "pkg:rpm/suse/sles-package@1.0",
                ),
                self._make_package_branch(
                    "desktop-package-1.0",
                    "pkg:rpm/suse/desktop-package@1.0",
                ),
            ],
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None

        def find_purls(obj: dict | list) -> list[str]:
            purls = []
            if isinstance(obj, dict):
                if "purl" in obj and obj["purl"]:
                    purls.append(obj["purl"])
                for v in obj.values():
                    purls.extend(find_purls(v))
            elif isinstance(obj, list):
                for item in obj:
                    purls.extend(find_purls(item))
            return purls

        purls = find_purls(result["product_tree"]["branches"])

        # SLES package PURL should be preserved
        assert "pkg:rpm/suse/sles-package@1.0" in purls
        # Desktop package PURL should NOT be preserved
        assert "pkg:rpm/suse/desktop-package@1.0" not in purls

    def test_strips_application_cpes_but_preserves_purls(self):
        """Application CPEs on packages should be stripped, but PURLs preserved."""
        doc = self._make_doc_with_branches_and_relationships(
            platforms=[
                self._make_platform_branch(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "cpe:/o:suse:sles:15:sp6",
                ),
            ],
            relationships=[
                self._make_relationship(
                    "SUSE Linux Enterprise Server 15 SP6",
                    "ctdb-4.22.3",
                ),
            ],
            product_status={
                "fixed": ["SUSE Linux Enterprise Server 15 SP6:ctdb-4.22.3"],
            },
            packages=[
                self._make_package_branch(
                    "ctdb-4.22.3",
                    "pkg:rpm/suse/ctdb@4.22.3",
                    # This is an application CPE with potentially malformed version
                    cpe="cpe:2.3:a:ctdb_project:ctdb:4.22.3+git.401.c70158430cc:*:*:*:*:*:*:*",
                ),
            ],
        )
        result = subset_csaf_for_sles(doc)

        assert result is not None

        # Find all CPEs and PURLs in the result
        def find_helpers(obj: dict | list) -> list[dict]:
            helpers = []
            if isinstance(obj, dict):
                if "product_identification_helper" in obj:
                    helpers.append(obj["product_identification_helper"])
                for v in obj.values():
                    helpers.extend(find_helpers(v))
            elif isinstance(obj, list):
                for item in obj:
                    helpers.extend(find_helpers(item))
            return helpers

        helpers = find_helpers(result["product_tree"]["branches"])

        # Should have helpers (platform CPE + package PURL)
        assert len(helpers) >= 2

        # Platform CPE should be preserved
        platform_cpes = [h.get("cpe") for h in helpers if h.get("cpe", "").startswith("cpe:/o:suse:sles:")]
        assert "cpe:/o:suse:sles:15:sp6" in platform_cpes

        # Application CPE should be stripped
        app_cpes = [h.get("cpe") for h in helpers if h.get("cpe", "").startswith("cpe:2.3:a:")]
        assert len(app_cpes) == 0

        # Package PURL should be preserved
        purls = [h.get("purl") for h in helpers if h.get("purl")]
        assert "pkg:rpm/suse/ctdb@4.22.3" in purls
