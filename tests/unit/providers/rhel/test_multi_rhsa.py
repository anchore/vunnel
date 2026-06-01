"""Tests for the "multiple RHSAs for one package" matching mechanism (Phase 1).

Red Hat sometimes ships more than one fix for the same package within a single RHEL
major version: a Z-stream/EUS backport that keeps the older upstream base on an older
minor, plus an upstream rebase on a later minor. The Hydra API flattens both into
"Red Hat Enterprise Linux N", so a naive "fixed in the highest version" record falsely
flags a host that already carries the older stream's backport.

The canonical real-world example is CVE-2024-8088 / python3.9 on RHEL 9:
  - RHSA-2024:6163 fixes the 9.4 Z-stream at python3.9-0:3.9.18-3.el9_4.5
  - RHSA-2024:9371 fixes the 9.5 GA build at python3.9-0:3.9.19-8.el9

Phase 1 emits a VulnerableRange constraint that partitions the two streams by their
upstream version base so that existing grype/grype-db match correctly with no upgrade:

    < 0:3.9.18-3.el9_4.5 || >= 0:3.9.19, < 0:3.9.19-8.el9

The integration test below drives the real CSAF parser against subsetted-but-real CSAF
advisories (RHSA-2024:6163, RHSA-2024:9371) and a subsetted-but-real Hydra CVE record.
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
from vunnel.providers.rhel.parser import AffectedRelease, Parser, _build_vulnerable_range, _get_version_base
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


class TestBuildVulnerableRange:
    def test_distinct_bases_python39(self):
        # the canonical CVE-2024-8088 shape (already deduped + sorted ascending by base)
        fixes = [_ar("0:3.9.18-3.el9_4.5"), _ar("0:3.9.19-8.el9")]
        assert _build_vulnerable_range(fixes) == "< 0:3.9.18-3.el9_4.5 || >= 0:3.9.19, < 0:3.9.19-8.el9"

    def test_three_distinct_bases(self):
        fixes = [
            _ar("4:20200609-2.20201027.1.el8_3"),
            _ar("4:20210216-1.20210608.1.el8_4"),
            _ar("4:20240910-1.el8_5"),
        ]
        assert _build_vulnerable_range(fixes) == (
            "< 4:20200609-2.20201027.1.el8_3 || >= 4:20210216, < 4:20210216-1.20210608.1.el8_4 || >= 4:20240910, < 4:20240910-1.el8_5"
        )

    def test_single_fix_returns_none(self):
        assert _build_vulnerable_range([_ar("0:3.9.19-8.el9")]) is None

    def test_empty_returns_none(self):
        assert _build_vulnerable_range([]) is None


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
    """End-to-end through _parse_cve with subsetted real CSAF + Hydra data."""

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

    def test_emits_partitioned_vulnerable_range(self, hydra_cve, fixture_dir, tmpdir, auto_fake_fixdate_finder):
        ws = workspace.Workspace(tmpdir, "test", create=True)
        driver = Parser(workspace=ws, skip_namespaces=[])
        driver.rhsa_provider = _wire_csaf_rhsa_provider(ws, fixture_dir)

        results = driver._parse_cve("CVE-2024-8088", hydra_cve)
        record = self._python39_fixed_in(results)

        # the two streams are partitioned by upstream version base; a 9.4 host at or above
        # 3.9.18-3.el9_4.5 is < 3.9.19 and therefore matches no clause (not vulnerable).
        assert record["VulnerableRange"] == "< 0:3.9.18-3.el9_4.5 || >= 0:3.9.19, < 0:3.9.19-8.el9"

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
