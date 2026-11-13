import copy

import pytest

from vunnel.providers.rhel.parser import Parser


PACKAGE = "eap7-hal-console"
VERSION = "0:3.3.13-1.Final_redhat_00001.1.el7eap"
CPE = "cpe:/a:redhat:jboss_enterprise_application_platform:7.4::el7"


def release(cpe=CPE, package=PACKAGE, version=VERSION):
    return {
        "product_name": "Red Hat JBoss Enterprise Application Platform 7.4 on RHEL 7",
        "cpe": cpe,
        "package": f"{package}-{version}",
        "advisory": "RHSA-2022:5892",
    }


@pytest.mark.parametrize(
    "other_cpe,other_package,conflict",
    [
        ("cpe:/a:redhat:jboss_enterprise_application_platform:7.3::el7", PACKAGE, True),
        (
            "cpe:/a:redhat:jboss_enterprise_application_platform_eus:7.3::el7",
            PACKAGE,
            True,
        ),
        (
            "cpe:/a:redhat:jboss_enterprise_application_platform_els:7.4::el7",
            PACKAGE,
            True,
        ),
        (CPE, PACKAGE, False),
        (
            "cpe:/a:redhat:jboss_enterprise_application_platform:7.3::el8",
            PACKAGE,
            False,
        ),
        (
            "cpe:/a:redhat:jboss_enterprise_application_platform:7.3::el7",
            "eap7-other",
            False,
        ),
    ],
)
def test_disclosed_eap_product_conflicts(other_cpe, other_package, conflict):
    driver = Parser.__new__(Parser)
    content = {"affected_release": [release(), release(other_cpe, other_package)]}
    original = copy.deepcopy(content)

    conflicts = driver._find_eap_rpm_product_conflicts(content)

    assert ((PACKAGE, "7") in conflicts) == conflict
    assert content == original
    assert driver._parse_eap74_rpm_platform(
        content["affected_release"][0], conflicts
    ) == (None if conflict else "7")


@pytest.mark.parametrize(
    "state", ["Affected", "Not affected", "Will not fix", "Under investigation"]
)
def test_package_state_can_disclose_product_conflict(state):
    driver = Parser.__new__(Parser)
    candidate = release()
    content = {
        "affected_release": [candidate],
        "package_state": [
            {
                "cpe": "cpe:/a:redhat:jboss_enterprise_application_platform_eus:7.3::el7",
                "package_name": PACKAGE,
                "fix_state": state,
            }
        ],
    }
    conflicts = driver._find_eap_rpm_product_conflicts(content)

    assert conflicts == {(PACKAGE, "7")}
    assert driver._parse_eap74_rpm_platform(candidate, conflicts) is None
    eap74_state = {
        "product_name": candidate["product_name"],
        "cpe": CPE,
        "package_name": PACKAGE,
        "fix_state": "Affected",
    }
    assert driver._parse_eap74_state_platform(eap74_state, conflicts) is None


@pytest.mark.parametrize(
    "section,item",
    [
        ("affected_release", None),
        ("affected_release", {}),
        ("affected_release", {"cpe": []}),
        ("affected_release", {"cpe": CPE, "package": []}),
        ("package_state", {"cpe": CPE, "package_name": []}),
        ("package_state", {"cpe": "not-a-cpe", "package_name": PACKAGE}),
    ],
)
def test_conflict_scan_ignores_unusable_entries(section, item):
    driver = Parser.__new__(Parser)
    content = {"affected_release": [release()]}
    content.setdefault(section, []).append(item)
    assert driver._find_eap_rpm_product_conflicts(content) == set()


def test_single_product_retains_affected_state_handling():
    driver = Parser.__new__(Parser)
    item = {
        "product_name": release()["product_name"],
        "cpe": CPE,
        "package_name": PACKAGE,
        "fix_state": "Affected",
    }
    content = {"affected_release": [release()], "package_state": [item]}
    conflicts = driver._find_eap_rpm_product_conflicts(content)
    assert conflicts == set()
    assert driver._parse_eap74_state_platform(item, conflicts) == "7"
