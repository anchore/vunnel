import pytest

from vunnel.providers.rhel_csaf.transformer import base_vulnerability, marked_will_not_fix
from vunnel.utils.csaf_types import (
    TLP,
    AggregateSeverity,
    CSAFDoc,
    Distribution,
    Document,
    Generator,
    GeneratorEngine,
    Note,
    ProductTree,
    Publisher,
    Reference,
    Remediation,
    Tracking,
    Vulnerability,
)


def csaf_test_builder(cve_id: str, description: str, severity: str, link: str) -> CSAFDoc:
    return CSAFDoc(
        document=Document(
            aggregate_severity=AggregateSeverity(namespace="", text=severity),
            category="csaf_vex",
            csaf_version="ignored",
            distribution=Distribution(text="", tlp=TLP(label="", url="")),
            lang="en",
            notes=[],
            publisher=Publisher(category="", contact_details="", issuing_authority="", name="", namespace=""),
            references=[],
            title="ignored",
            tracking=Tracking(
                current_release_date="",
                generator=Generator(date="", engine=GeneratorEngine(name="", version="")),
                id="",
                initial_release_date="",
                revision_history=[],
                status="",
                version="",
            ),
        ),
        product_tree=ProductTree(branches=[], relationships=[]),
        vulnerabilities=[
            Vulnerability(
                title="example-cve",
                cve=cve_id,
                notes=[
                    Note(
                        category="description",
                        title="Vulnerability description",
                        text=description,
                    )
                ],
                references=[
                    Reference(category="self", summary="", url=link),
                ],
            ),
        ],
    )


def test_base_vulnerability():
    cve_id = "CVE-123-Example"
    description = "example descritpion"
    severity = "important"
    link = "https://example.com/CVE-123-Example"
    namespace = "rhel:8"
    csaf = csaf_test_builder(cve_id, description, severity, link)

    vuln = base_vulnerability(csaf, namespace)

    assert vuln.Name == cve_id
    assert vuln.NamespaceName == namespace
    assert vuln.Description == description
    assert vuln.Severity == "High", "failed to normalize description"
    assert vuln.Link == link


@pytest.mark.parametrize("remediations,product_id,want_marked_will_not_fix",
                         [
                         ([], "any", False),
                         (
                            [Remediation(category="no_fix_planned", product_ids=set(["too-old-product"]), details="seriuosly, upgrade")],
                            "too-old-product",
                            True
                         ),
                         (
                            [Remediation(category="no_fix_planned", product_ids=set(["too-old-product"]), details="seriuosly, upgrade")],
                            "newer-product",
                            False,
                         )
                         ])
def test_marked_will_not_fix(remediations, product_id, want_marked_will_not_fix):
    assert marked_will_not_fix(remediations, product_id) == want_marked_will_not_fix
