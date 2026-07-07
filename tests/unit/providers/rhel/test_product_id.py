import pytest

from vunnel.providers.rhel.product_id import ProductIdInfo, minor_from_dist_tag, parse_product_id


class TestParseProductId:
    @pytest.mark.parametrize(
        ("product_id", "expected"),
        [
            # ------------------------------------------------------------------
            # OLD format: {Repo}-{major}.{minor}[.{Z}][.{markers}]:{nevra}
            # ------------------------------------------------------------------
            # GA build (task example) -> generally available, explicit "ga" channel
            (
                "AppStream-9.5.0.GA:webkit2gtk3-0:2.44.3-2.el9.x86_64",
                ProductIdInfo(minor=5, channel="ga"),
            ),
            # GA build, BaseOS repo
            (
                "BaseOS-8.10.0.GA:glibc-0:2.28-251.el8.x86_64",
                ProductIdInfo(minor=10, channel="ga"),
            ),
            # z-stream (.elN_M) build, EUS channel
            (
                "AppStream-8.2.0.Z.EUS:bind-32:9.11.13-6.el8_2.3.x86_64",
                ProductIdInfo(minor=2, channel="eus"),
            ),
            # MULTI-DIGIT minor (RHEL 8.10) in an old-format z-stream prefix -> minor 10
            (
                "BaseOS-8.10.0.Z.MAIN:glibc-0:2.28-251.el8_10.5.x86_64",
                ProductIdInfo(minor=10, channel="ga"),
            ),
            # z-stream, MAIN.EUS marker chain (BaseOS) -> eus
            (
                "BaseOS-9.4.0.Z.MAIN.EUS:glibc-0:2.34-100.el9_4.x86_64",
                ProductIdInfo(minor=4, channel="eus"),
            ),
            # z-stream MAIN only (no extended-support marker -> generally available "ga")
            (
                "AppStream-8.9.0.Z.MAIN:webkit2gtk3-0:2.40.5-1.el8_9.1.x86_64",
                ProductIdInfo(minor=9, channel="ga"),
            ),
            # z-stream ENS marker is UNRECOGNIZED (neither general nor extended) -> channel None (unknown)
            (
                "AppStream-8.8.0.Z.ENS:foo-0:1-1.el8_8.x86_64",
                ProductIdInfo(minor=8, channel=None),
            ),
            # AUS channel
            (
                "AppStream-8.4.0.Z.AUS:httpd-0:2.4.37-21.el8_4.aarch64",
                ProductIdInfo(minor=4, channel="aus"),
            ),
            # TUS channel
            (
                "AppStream-8.6.0.Z.TUS:kernel-0:4.18.0-372.el8_6.x86_64",
                ProductIdInfo(minor=6, channel="tus"),
            ),
            # E4S channel
            (
                "AppStream-9.2.0.Z.E4S:sudo-0:1.9.5p2-9.el9_2.2.x86_64",
                ProductIdInfo(minor=2, channel="e4s"),
            ),
            # two-number short form, GA -> "ga"
            (
                "AppStream-8.6.GA:foo-0:1.0-1.el8.x86_64",
                ProductIdInfo(minor=6, channel="ga"),
            ),
            # two-number short form, Z only (general -> "ga")
            (
                "AppStream-9.5.Z:foo-0:1.0-1.el9_5.x86_64",
                ProductIdInfo(minor=5, channel="ga"),
            ),
            # modular build (+elN.M dist tag) with EUS prefix marker; minor comes from prefix, not the +el tag
            (
                "AppStream-8.1.0.Z.EUS:libecap-0:1.0.1-2.module+el8.1.0+4044+36416a77.x86_64::squid:4",
                ProductIdInfo(minor=1, channel="eus"),
            ),
            # modular GA build
            (
                "AppStream-9.4.0.GA:ruby-0:3.1.4-1.module+el9.4.0+1234+abcd.x86_64::ruby:3.1",
                ProductIdInfo(minor=4, channel="ga"),
            ),
            # repo label containing a hyphen (e.g. "AppStream-NFV") still parses major.minor + channel
            (
                "AppStream-NFV-9.3.0.Z.EUS:foo-0:1-1.el9_3.x86_64",
                ProductIdInfo(minor=3, channel="eus"),
            ),
            # ------------------------------------------------------------------
            # NEW format: rhel-{major}.{minor}[-marker]::repo:{nevra}
            # ------------------------------------------------------------------
            # GA build (task example) -> generally available "ga"
            (
                "rhel-9.5::appstream:webkit2gtk3-0:2.44.3-2.el9",
                ProductIdInfo(minor=5, channel="ga"),
            ),
            # z-stream-ish new-format build (no marker -> generally available "ga")
            (
                "rhel-9.4::baseos:glibc-0:2.34-100.el9_4",
                ProductIdInfo(minor=4, channel="ga"),
            ),
            # MULTI-DIGIT minor (RHEL 8.10) in the new format -> minor 10
            (
                "rhel-8.10::baseos:glibc-0:2.28-251.el8_10",
                ProductIdInfo(minor=10, channel="ga"),
            ),
            # new format with -eus marker (normalized to lowercase token)
            (
                "rhel-8.6-eus::appstream:httpd-0:2.4.37-21.el8_6",
                ProductIdInfo(minor=6, channel="eus"),
            ),
            # new format with -e4s marker (case-insensitive, normalized to lowercase)
            (
                "rhel-9.2-e4s::appstream:sudo-0:1.9.5p2-9.el9_2.2",
                ProductIdInfo(minor=2, channel="e4s"),
            ),
            # new format modular build -> "ga"
            (
                "rhel-9.4::appstream:ruby-0:3.1.4-1.module+el9.4.0+1234+abcd::ruby:3.1",
                ProductIdInfo(minor=4, channel="ga"),
            ),
            # ------------------------------------------------------------------
            # ELS: extended *lifecycle* support, major-only (no minor) but a real channel
            # ------------------------------------------------------------------
            (
                "7Server-ELS:webkitgtk4-0:2.48.3-2.el7_9.x86_64",
                ProductIdInfo(minor=None, channel="els"),
            ),
            # RHEL 6 ELS with an .EXTENSION repo segment after the ELS marker (real bind example
            # from RHSA-2025:23414) -> still minor None, channel "els"
            (
                "6Server-ELS.EXTENSION:bind-32:9.8.2-0.68.rc1.el6_10.17.x86_64",
                ProductIdInfo(minor=None, channel="els"),
            ),
            ("NServer-ELS:foo-0:1-1.el7.x86_64", ProductIdInfo(minor=None, channel="els")),
            # ------------------------------------------------------------------
            # Unrecognized input -> channel None (UNKNOWN, not assumed GA); minor None when
            # it cannot be recovered either. Do not guess.
            # ------------------------------------------------------------------
            # garbage / empty / None
            ("", ProductIdInfo(minor=None, channel=None)),
            (None, ProductIdInfo(minor=None, channel=None)),
            ("not-a-product-id", ProductIdInfo(minor=None, channel=None)),
            ("Red Hat OpenShift Container Platform 4.12", ProductIdInfo(minor=None, channel=None)),
        ],
    )
    def test_parse_product_id(self, product_id, expected):
        assert parse_product_id(product_id) == expected

    def test_returns_namedtuple_fields(self):
        info = parse_product_id("AppStream-9.5.0.GA:webkit2gtk3-0:2.44.3-2.el9.x86_64")
        assert info.minor == 5
        assert info.channel == "ga"

    def test_unrecognized_marker_is_unknown_not_ga(self):
        # an unexpected marker (ENS) is neither general nor extended -> channel None (unknown)
        info = parse_product_id("AppStream-8.8.0.Z.ENS:foo-0:1-1.el8_8.x86_64")
        assert info.minor == 8
        assert info.channel is None

    def test_channel_token_is_lowercase(self):
        info = parse_product_id("AppStream-8.2.0.Z.EUS:bind-32:9.11.13-6.el8_2.3.x86_64")
        assert info.channel == "eus"

    def test_old_and_new_format_agree_on_minor(self):
        old = parse_product_id("AppStream-9.5.0.GA:webkit2gtk3-0:2.44.3-2.el9.x86_64")
        new = parse_product_id("rhel-9.5::appstream:webkit2gtk3-0:2.44.3-2.el9")
        assert old.minor == new.minor == 5


class TestMinorFromDistTag:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            # Z-stream / EUS dist tag ".elN_M" -> M (the glibc CVE-2023-4813 case)
            ("0:2.34-60.el9_2.7", 2),
            ("0:2.34-100.el9_4", 4),
            ("32:9.11.13-6.el8_2.3", 2),
            ("4.18.0-372.el8_6", 6),
            # MULTI-DIGIT minor in the dist tag ".el8_10" (RHEL 8.10) -> 10
            ("0:2.28-251.el8_10.5", 10),
            ("2.28-251.el8_10", 10),
            # release without epoch still parses
            ("2.34-60.el9_2.7", 2),
            # modular "+elN.M" dist tag -> M
            ("0:1.0.1-2.module+el8.1.0+4044+36416a77", 1),
            ("0:3.1.4-1.module+el9.4.0+1234+abcd", 4),
            # bare GA tag ".elN" (no minor) -> None; only the FPI can supply a GA build's minor
            ("0:2.34-100.el9", None),
            ("0:2.44.3-2.el9", None),
            ("1:2.27-34.base.el7", None),
            # GA respin suffix ".elN.M" (a DOT after a plain ".el") is a rebuild counter, NOT a minor
            ("7.2-3.el7.1", None),
            ("2:0.12.1.2-2.209.el6.1", None),
            # no recognizable dist tag / empty / None -> None
            ("0:1.2.3-4", None),
            ("", None),
            (None, None),
        ],
    )
    def test_minor_from_dist_tag(self, version, expected):
        assert minor_from_dist_tag(version) == expected
