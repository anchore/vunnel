from __future__ import annotations

import logging
import os
import tarfile
import types

import orjson
import pytest

from vunnel.providers.sles.csaf_advisory_client import SLESCSAFAdvisoryClient, strip_arch
from vunnel.providers.sles.csaf_parser import FixDates
from vunnel.tool.fixdate.finder import Finder


def _advisory(release_date: str, cve: str, product_ids: list[str]) -> dict:
    return {
        "document": {"tracking": {"id": "SUSE-SU-TEST", "initial_release_date": release_date}},
        "vulnerabilities": [{"cve": cve, "product_status": {"recommended": product_ids}}],
    }


def _archive(tmp_path, docs: dict[str, dict | bytes]) -> str:
    """Build a csaf.tar.bz2-shaped archive so the real streaming reader is exercised."""
    path = os.path.join(tmp_path, "csaf.tar.bz2")
    raw_dir = os.path.join(tmp_path, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    with tarfile.open(path, mode="w:bz2") as tar:
        for name, doc in docs.items():
            src = os.path.join(raw_dir, name)
            payload = doc if isinstance(doc, bytes) else orjson.dumps(doc)
            with open(src, "wb") as fh:
                fh.write(payload)
            tar.add(src, arcname=f"csaf/{name}")
    return path


def _client(tmp_path, archive_path) -> SLESCSAFAdvisoryClient:
    ws = types.SimpleNamespace(input_path=str(tmp_path))
    client = SLESCSAFAdvisoryClient(workspace=ws, logger=logging.getLogger("test"), skip_download=True)
    client.archive_path = archive_path
    return client


@pytest.mark.parametrize(
    ("nevra", "expected"),
    [
        # the advisory feed's arch suffix, which the VEX feed omits
        ("python3-uamqp-1.5.3-150100.4.13.1.x86_64", "python3-uamqp-1.5.3-150100.4.13.1"),
        ("kernel-default-5.3.18-150300.59.87.1.aarch64", "kernel-default-5.3.18-150300.59.87.1"),
        ("some-data-1.0-1.1.noarch", "some-data-1.0-1.1"),
        # a trailing component that is NOT an arch must survive: release strings
        # routinely end in a dotted number.
        ("mailx-12.5-150600.16.3", "mailx-12.5-150600.16.3"),
        ("libaom0-1.0.0-150200.3.1", "libaom0-1.0.0-150200.3.1"),
    ],
)
def test_strip_arch(nevra, expected):
    assert strip_arch(nevra) == expected


class TestFixDateIndex:
    def test_indexes_cve_and_nevr(self, tmp_path):
        archive = _archive(
            tmp_path,
            {
                "suse-su-2024_0591-1.json": _advisory(
                    "2024-02-22T13:46:16Z",
                    "CVE-2024-25110",
                    ["SUSE Linux Enterprise Server 15 SP5:python3-uamqp-1.5.3-150100.4.13.1.x86_64"],
                ),
            },
        )
        dates = _client(tmp_path, archive).fix_dates()
        assert dates == {("CVE-2024-25110", "python3-uamqp-1.5.3-150100.4.13.1"): "2024-02-22"}

    def test_earliest_advisory_wins(self, tmp_path):
        """A NEVR is often shipped by several advisories (a later one re-shipping the
        same build); the fix became available on the first of them."""
        pid = "SUSE Linux Enterprise Server 15 SP5:foo-1.0-1.1.x86_64"
        archive = _archive(
            tmp_path,
            {
                "suse-su-2024_0002-1.json": _advisory("2024-06-01T00:00:00Z", "CVE-2024-0001", [pid]),
                "suse-su-2024_0001-1.json": _advisory("2024-03-01T00:00:00Z", "CVE-2024-0001", [pid]),
                "suse-su-2024_0003-1.json": _advisory("2024-09-01T00:00:00Z", "CVE-2024-0001", [pid]),
            },
        )
        dates = _client(tmp_path, archive).fix_dates()
        assert dates[("CVE-2024-0001", "foo-1.0-1.1")] == "2024-03-01"

    def test_non_utf8_document_is_recovered(self, tmp_path):
        """~185 real documents carry latin-1 bytes in prose while declaring UTF-8.
        They must not be dropped: every field this index reads is ASCII regardless."""
        doc = _advisory(
            "2024-02-22T00:00:00Z",
            "CVE-2024-25110",
            ["SUSE Linux Enterprise Server 15 SP5:foo-1.0-1.1.x86_64"],
        )
        raw = orjson.dumps(doc)
        # splice an invalid-UTF-8 byte into a prose field, as SUSE's generator does
        broken = raw.replace(b'"SUSE-SU-TEST"', b'"SUSE-SU-TEST \xe9"')
        archive = _archive(tmp_path, {"suse-su-broken-1.json": broken})

        dates = _client(tmp_path, archive).fix_dates()
        assert dates == {("CVE-2024-25110", "foo-1.0-1.1"): "2024-02-22"}

    def test_non_sle_platforms_are_not_indexed(self, tmp_path):
        """openSUSE and RHSA rebuilds share the archive but can never date a SLES fix."""
        archive = _archive(
            tmp_path,
            {
                "opensuse-su-2024_1-1.json": _advisory(
                    "2024-01-01T00:00:00Z",
                    "CVE-2024-0001",
                    ["openSUSE Leap 15.6:foo-1.0-1.1.x86_64"],
                ),
            },
        )
        assert _client(tmp_path, archive).fix_dates() == {}

    def test_missing_archive_is_an_error(self, tmp_path):
        client = _client(tmp_path, os.path.join(tmp_path, "absent.tar.bz2"))
        with pytest.raises(FileNotFoundError):
            client.fix_dates()


class _NoStore:
    """A first-observed store with nothing in it, so Kind reveals which source won."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def download(self):
        return None

    def find(self, *args, **kwargs):
        return []


class TestFixDates:
    def test_advisory_date_is_used_when_known(self):
        fix_dates = FixDates(
            Finder(strategies=[], first_observed=_NoStore()),
            {("CVE-2024-25110", "python3-uamqp-1.5.3-150100.4.13.1"): "2024-02-22"},
        )
        available = fix_dates.available_for(
            cve_id="CVE-2024-25110",
            namespace="sles:15.5",
            package="python3-uamqp",
            nevr="python3-uamqp-1.5.3-150100.4.13.1",
            version="0:1.5.3-150100.4.13.1",
        )
        assert available.Date == "2024-02-22"
        assert available.Kind == "advisory"

    def test_falls_back_when_no_advisory_ships_that_build(self):
        """VEX's `recommended` is the currently-shipping rebuild, which is often newer
        than the advisory that fixed the CVE -- so ~42% of fixed records have no
        advisory date and must fall through to the finder rather than inventing one."""
        finder = Finder(strategies=[], first_observed=_NoStore())
        finder.first_observed = _NoStore()
        fix_dates = FixDates(finder, {})
        assert (
            fix_dates.available_for(
                cve_id="CVE-2022-26700",
                namespace="sles:15.7",
                package="typelib-1_0-WebKit2-4_0",
                nevr="typelib-1_0-WebKit2-4_0-2.48.1-150600.12.36.5",
                version="0:2.48.1-150600.12.36.5",
            )
            is None
        )

    def test_ltss_looks_up_the_plain_namespace(self):
        """`sles:X.Y+ltss` is a namespace this provider introduces, so no historical
        first-observed data is filed under it and the finder matches the ecosystem
        exactly -- every LTSS lookup would miss and stamp today's date. The plain track
        carries the same fix at the same version for ~93% of LTSS fixed records, so the
        lookup drops the channel suffix."""
        seen = []

        class _Recorder(_NoStore):
            def find(self, vuln_id, cpe_or_package, fix_version, ecosystem=None):
                seen.append(ecosystem)
                return []

        fix_dates = FixDates(Finder(strategies=[], first_observed=_Recorder()), {})
        fix_dates.available_for("CVE-2023-53526", "sles:15.5+ltss", "kernel-default", "kernel-default-5.14.21", "0:5.14.21")

        assert seen == ["sles:15.5"]

    def test_plain_namespace_is_passed_through_unchanged(self):
        seen = []

        class _Recorder(_NoStore):
            def find(self, vuln_id, cpe_or_package, fix_version, ecosystem=None):
                seen.append(ecosystem)
                return []

        fix_dates = FixDates(Finder(strategies=[], first_observed=_Recorder()), {})
        fix_dates.available_for("CVE-2023-53526", "sles:15.5", "kernel-default", "kernel-default-5.14.21", "0:5.14.21")

        assert seen == ["sles:15.5"]

    def test_no_date_for_unfixed_or_not_affected(self):
        """Version "None" (vulnerable, no fix) and "0" (not affected) describe no fix,
        so there is no fix date to report."""
        fix_dates = FixDates(
            Finder(strategies=[], first_observed=_NoStore()),
            {("CVE-2024-0001", "foo-1.0-1.1"): "2024-02-22"},
        )
        for version in ("None", "0"):
            assert fix_dates.available_for("CVE-2024-0001", "sles:15.5", "foo", "foo-1.0-1.1", version) is None
