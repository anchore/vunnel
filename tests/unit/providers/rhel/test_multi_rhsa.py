"""Tests for the Option A "multiple advisory fixes for one package" emission shape.

Red Hat sometimes ships more than one fix for the same package within a single RHEL major
version. Two flavors matter:

  - distinct upstream bases: a backport on an older minor (python3.9 3.9.18-3.el9_4.5 for 9.4)
    plus a rebase to a newer upstream on a later minor (3.9.19-8.el9 for 9.5).
  - SAME upstream base: fixes on several minor streams that differ only by their .elN_M dist
    tag (e.g. glibc 2.34-60.el9_2.7 for the 9.2 Z-stream and 2.34-100.el9 for the 9.3 GA).

The Hydra API flattens all of these into "Red Hat Enterprise Linux N", so a naive "fixed in the
highest version" record falsely flags a host that already carries its own stream's (lower-EVR)
fix - and the same-base case cannot be separated by RPM version comparison at all (the leading
release is a single total order).

Option A keeps one record per CVE and emits, additively, every distinct called-out fix build
paired with its advisory in AdditionalAdvisoryFixes, plus folds ALL contributing advisories into
VendorAdvisory.AdvisorySummary. The grype matcher then reads the installed package's own dist-tag
minor and selects the matching per-stream build at match time.

The integration test below drives the real CSAF parser against subsetted-but-real CSAF advisories
(RHSA-2024:6163, RHSA-2024:9371) and a subsetted-but-real Hydra CVE record.
See https://access.redhat.com/security/cve/cve-2024-8088#cve-affected-packages
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import orjson
import pytest

from vunnel import workspace
from vunnel.providers.rhel.csaf_parser import CSAFParser
from vunnel.providers.rhel.csaf_client import CSAFClient
from vunnel.providers.rhel.parser import AffectedRelease, Parser, _get_version_base
from vunnel.providers.rhel.rhsa_provider import CSAFRHSAProvider


@pytest.fixture()
def fixture_dir():
    return Path(__file__).parent / "test-fixtures"


def _ar(version: str, rhsa: str | None = None, platform: str = "9", module: str | None = None) -> AffectedRelease:
    ar = AffectedRelease(name="pkg", version=version, platform=platform, module=module)
    ar.rhsa_id = rhsa
    return ar


class TestGetVersionBase:
    @pytest.mark.parametrize(
        "version,expected",
        [
            ("0:3.9.19-8.el9", "0:3.9.19"),
            ("3.9.18-3.el9_4.5", "3.9.18"),
            ("1:2.27-34.base.el7", "1:2.27"),
            ("4:20210216-1.20210608.1.el8_4", "4:20210216"),
            # no release component: returned unchanged
            ("3.9.19", "3.9.19"),
        ],
    )
    def test_get_version_base(self, version, expected):
        assert _get_version_base(version) == expected


class TestSameBaseAdditionalAdvisoryFixes:
    """Directly exercises _parse_affected_release for the same-base multi-stream case, which is the
    scenario Option A's matcher-side selection exists for. Two glibc fixes share the upstream base
    2.34 and differ only by dist tag (.el9_2.7 vs .el9); both must be carried as distinct
    AdditionalAdvisoryFixes paired with their advisories."""

    def _driver_with_static_rhsa(self, tmpdir):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        driver = Parser(workspace=ws, skip_namespaces=[])
        # Resolve each affected-release's fix version straight from its parsed package string and
        # advisory, so the test exercises the bucket reduction without any CSAF/OVAL plumbing.
        versions = {
            "RHSA-2023:5453": "0:2.34-60.el9_2.7",
            "RHBA-2024:2413": "0:2.34-100.el9",
        }
        driver._fetch_rhsa_fix_version = lambda cve_id, ar_obj, override_package_name=None: (  # type: ignore[method-assign]
            versions.get(ar_obj.rhsa_id),
            None,
        )
        return driver

    def _affected_release_payload(self):
        # two streams, same upstream base 2.34, differing only by .elN_M dist tag
        return {
            "affected_release": [
                {
                    "product_name": "Red Hat Enterprise Linux 9",
                    "package": "glibc-0:2.34-60.el9_2.7",
                    "advisory": "RHSA-2023:5453",
                    "cpe": "cpe:/o:redhat:enterprise_linux:9",
                },
                {
                    "product_name": "Red Hat Enterprise Linux 9",
                    "package": "glibc-0:2.34-100.el9",
                    "advisory": "RHBA-2024:2413",
                    "cpe": "cpe:/o:redhat:enterprise_linux:9",
                },
            ],
        }

    def test_carries_every_distinct_stream_fix(self, tmpdir):
        driver = self._driver_with_static_rhsa(tmpdir)
        fixed_ins = driver._parse_affected_release("CVE-2023-4813", self._affected_release_payload())

        glibc = [f for f in fixed_ins if f.package == "glibc" and f.platform == "9"]
        assert len(glibc) == 1
        record = glibc[0]

        # canonical (single-constraint fallback) is the highest build
        assert record.version == "0:2.34-100.el9"
        # Option A does not emit a VulnerableRange (the matcher does per-stream selection)
        assert record.vulnerable_range is None

        # every distinct fix build is carried with its advisory, newest first
        carried = [(af.version, af.advisory.rhsa_id) for af in record.additional_advisories]
        assert carried == [
            ("0:2.34-100.el9", "RHBA-2024:2413"),
            ("0:2.34-60.el9_2.7", "RHSA-2023:5453"),
        ]

    def test_emitted_json_shape(self, tmpdir, auto_fake_fixdate_finder):
        driver = self._driver_with_static_rhsa(tmpdir)
        results = driver._parse_cve("CVE-2023-4813", {**self._affected_release_payload(), "threat_severity": "moderate"})

        rhel9 = [r for r in results if r.namespace == "rhel:9"]
        assert len(rhel9) == 1
        fixed_in = [f for f in rhel9[0].payload["Vulnerability"]["FixedIn"] if f["Name"] == "glibc"]
        assert len(fixed_in) == 1
        record = fixed_in[0]

        assert record["Version"] == "0:2.34-100.el9"
        assert "VulnerableRange" not in record

        # AdvisorySummary folds ALL contributing advisories (both streams), de-duplicated
        ids = [s["ID"] for s in record["VendorAdvisory"]["AdvisorySummary"]]
        assert ids == ["RHBA-2024:2413", "RHSA-2023:5453"]

        # AdditionalAdvisoryFixes carries each distinct fix build + its advisory, matching the
        # {Version, Advisory:{ID,Link}} shape the grype side consumes
        assert record["AdditionalAdvisoryFixes"] == [
            {
                "Version": "0:2.34-100.el9",
                "Advisory": {"ID": "RHBA-2024:2413", "Link": "https://access.redhat.com/errata/RHBA-2024:2413"},
            },
            {
                "Version": "0:2.34-60.el9_2.7",
                "Advisory": {"ID": "RHSA-2023:5453", "Link": "https://access.redhat.com/errata/RHSA-2023:5453"},
            },
        ]

    def test_single_stream_still_carries_its_single_fix(self, tmpdir):
        """A package with only one called-out fix is backwards compatible: one AdditionalAdvisoryFixes
        entry, no VulnerableRange, canonical version unchanged."""
        driver = self._driver_with_static_rhsa(tmpdir)
        payload = {
            "affected_release": [
                {
                    "product_name": "Red Hat Enterprise Linux 9",
                    "package": "glibc-0:2.34-60.el9_2.7",
                    "advisory": "RHSA-2023:5453",
                    "cpe": "cpe:/o:redhat:enterprise_linux:9",
                },
            ],
        }
        fixed_ins = driver._parse_affected_release("CVE-2023-4813", payload)
        glibc = [f for f in fixed_ins if f.package == "glibc"][0]
        assert glibc.version == "0:2.34-60.el9_2.7"
        assert glibc.vulnerable_range is None
        assert [(af.version, af.advisory.rhsa_id) for af in glibc.additional_advisories] == [
            ("0:2.34-60.el9_2.7", "RHSA-2023:5453"),
        ]


def _wire_csaf_rhsa_provider(ws: workspace.Workspace, fixture_dir: Path) -> Mock:
    """Build a Mock CSAFRHSAProvider backed by the real CSAFParser, resolving fixes from
    the subsetted real CSAF advisories for RHSA-2024:6163 and RHSA-2024:9371."""
    from vunnel.utils.csaf_types import from_path

    adv_dir = fixture_dir / "csaf" / "advisories" / "2024"
    docs = {
        "RHSA-2024:6163": from_path(adv_dir / "rhsa-2024_6163.json"),
        "RHSA-2024:9371": from_path(adv_dir / "rhsa-2024_9371.json"),
    }

    mock_client = Mock(spec=CSAFClient)
    mock_client.csaf_doc_for_rhsa.side_effect = lambda rhsa: docs.get(rhsa)

    csaf_parser = CSAFParser(workspace=ws, client=mock_client, logger=Mock(), download_timeout=125)

    mock_rhsa_provider = Mock(spec=CSAFRHSAProvider)
    mock_rhsa_provider.get_fixed_version_and_module.side_effect = lambda cve_id, ar, override_pkg: csaf_parser.get_fix_info(
        cve_id,
        ar.as_dict(),
        override_pkg or ar.name,
    )
    return mock_rhsa_provider


class TestCVE2024_8088:
    """End-to-end through _parse_cve with subsetted real CSAF + Hydra data (distinct-base case)."""

    @pytest.fixture()
    def hydra_cve(self, fixture_dir):
        path = fixture_dir / "csaf" / "hydra" / "cve-2024-8088.json"
        with open(path, "rb") as f:
            return orjson.loads(f.read())

    def _python39_fixed_in(self, results):
        rhel9 = [r for r in results if r.namespace == "rhel:9"]
        assert len(rhel9) == 1, f"expected exactly one rhel:9 payload, got namespaces {[r.namespace for r in results]}"
        fixed_in = rhel9[0].payload["Vulnerability"]["FixedIn"]
        py = [f for f in fixed_in if f["Name"] == "python3.9"]
        assert len(py) == 1, f"expected exactly one python3.9 FixedIn, got {fixed_in}"
        return py[0]

    def test_emits_additional_advisory_fixes(self, hydra_cve, fixture_dir, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        driver = Parser(workspace=ws, skip_namespaces=[])
        driver.rhsa_provider = _wire_csaf_rhsa_provider(ws, fixture_dir)

        record = self._python39_fixed_in(driver._parse_cve("CVE-2024-8088", hydra_cve))

        # both distinct stream builds are carried, newest first, each paired with its advisory; the
        # grype matcher selects between them by the installed package's dist-tag minor at match time.
        assert record["AdditionalAdvisoryFixes"] == [
            {
                "Version": "0:3.9.19-8.el9",
                "Advisory": {"ID": "RHSA-2024:9371", "Link": "https://access.redhat.com/errata/RHSA-2024:9371"},
            },
            {
                "Version": "0:3.9.18-3.el9_4.5",
                "Advisory": {"ID": "RHSA-2024:6163", "Link": "https://access.redhat.com/errata/RHSA-2024:6163"},
            },
        ]
        # Option A drives stream selection in the matcher, not via a VulnerableRange constraint
        assert "VulnerableRange" not in record

    def test_canonical_version_is_newest_stream(self, hydra_cve, fixture_dir, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        driver = Parser(workspace=ws, skip_namespaces=[])
        driver.rhsa_provider = _wire_csaf_rhsa_provider(ws, fixture_dir)

        record = self._python39_fixed_in(driver._parse_cve("CVE-2024-8088", hydra_cve))

        # the single-constraint fallback / user-facing "fixed in" is the newest stream's fix
        assert record["Version"] == "0:3.9.19-8.el9"
        assert record["VersionFormat"] == "rpm"

    def test_folds_both_advisories_newest_first(self, hydra_cve, fixture_dir, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        driver = Parser(workspace=ws, skip_namespaces=[])
        driver.rhsa_provider = _wire_csaf_rhsa_provider(ws, fixture_dir)

        record = self._python39_fixed_in(driver._parse_cve("CVE-2024-8088", hydra_cve))

        summaries = record["VendorAdvisory"]["AdvisorySummary"]
        ids = [s["ID"] for s in summaries]
        # both RHSAs that touched this package are surfaced, newest fix first
        assert ids == ["RHSA-2024:9371", "RHSA-2024:6163"]
