from vunnel import workspace
from vunnel.providers.sles.csaf_parser import CSAFParser
from vunnel.utils.csaf_types import Branch, Product, ProductIdentificationHelper

from unittest.mock import MagicMock
import pytest
from collections import namedtuple


def test_platform_cpe_regex():
    branches_iterable = [
        # SLES 11 not in allow_versions, excluded
        Branch.from_dict(
              {
                "category": "product_name",
                "name": "SUSE Linux Enterprise Server 11 SP4 LTSS",
                "product": {
                  "name": "SUSE Linux Enterprise Server 11 SP4 LTSS",
                  "product_id": "SUSE Linux Enterprise Server 11 SP4 LTSS",
                  "product_identification_helper": {
                    "cpe": "cpe:/o:suse:suse_sles_ltss:11:sp4"
                  }
                }
              },
        ),
        # SLES 15 SP1-LTSS, included
        Branch.from_dict(
              {
                "category": "product_name",
                "name": "SUSE Linux Enterprise Server 12 SP5-LTSS",
                "product": {
                  "name": "SUSE Linux Enterprise Server 12 SP5-LTSS",
                  "product_id": "SUSE Linux Enterprise Server 12 SP5-LTSS",
                  "product_identification_helper": {
                    "cpe": "cpe:/o:suse:sles-ltss-extended-security:12:sp5"
                  }
                }
              },
        ),
        # SLES 15 SP1-LTSS, included
        Branch(
            category="product_name",
            name="SUSE Linux Enterprise Server 15 SP1-LTSS",
            product=Product(
                name="SUSE Linux Enterprise Server 15 SP1-LTSS",
                product_id="SUSE Linux Enterprise Server 15 SP1-LTSS",
                product_identification_helper=ProductIdentificationHelper(
                    cpe="cpe:/o:suse:sles-ltss:15:sp1"
                )
            ),
        ),
        # Missing CPE, excluded
        Branch.from_dict(
              {
                "category": "product_name",
                "name": "SUSE Linux Enterprise Server LTSS Extended Security 12 SP5",
                "product": {
                  "name": "SUSE Linux Enterprise Server LTSS Extended Security 12 SP5",
                  "product_id": "SUSE Linux Enterprise Server LTSS Extended Security 12 SP5"
                }
              },
        ),
        # SLES 15 SP3-LTSS, included
        Branch.from_dict(
              {
                "category": "product_name",
                "name": "SUSE Linux Enterprise Server 15 SP3-LTSS",
                "product": {
                  "name": "SUSE Linux Enterprise Server 15 SP3-LTSS",
                  "product_id": "SUSE Linux Enterprise Server 15 SP3-LTSS",
                  "product_identification_helper": {
                    "cpe": "cpe:/o:suse:sles-ltss:15:sp3"
                  }
                }
              },
        ),
        # SAP product, not core SLES. Excluded
        Branch.from_dict(
              {
                "category": "product_name",
                "name": "SUSE Linux Enterprise Server for SAP Applications 15 SP3",
                "product": {
                  "name": "SUSE Linux Enterprise Server for SAP Applications 15 SP3",
                  "product_id": "SUSE Linux Enterprise Server for SAP Applications 15 SP3",
                  "product_identification_helper": {
                    "cpe": "cpe:/o:suse:sles_sap:15:sp3"
                  }
                }
              },
        ),
        # SLES 15 SP4, included
        Branch.from_dict(
              {
                "category": "product_name",
                "name": "SUSE Linux Enterprise Server for SAP Applications 15 SP4",
                "product": {
                  "name": "SUSE Linux Enterprise Server for SAP Applications 15 SP4",
                  "product_id": "SUSE Linux Enterprise Server for SAP Applications 15 SP4",
                  "product_identification_helper": {
                    "cpe": "cpe:/o:suse:sles_sap:15:sp4"
                  }
                }
              },
        )
    ]

    want = {
        "SUSE Linux Enterprise Server 12 SP5-LTSS": "sles:12.5",
        "SUSE Linux Enterprise Server 15 SP1-LTSS": "sles:15.1",
        "SUSE Linux Enterprise Server 15 SP3-LTSS": "sles:15.3",
    }
    parser = CSAFParser(workspace=MagicMock(), allow_versions=["12", "15"])
    got = parser.get_allowed_platforms(branches_iterable)
    assert got == want
    for k in sorted(got.keys()):
        assert got[k] == want.get(k)
    for k in sorted(want.keys()):
        assert got.get(k) == want[k]



@pytest.fixture
def doc_with_parent():
    doc = MagicMock()
    doc.product_tree = MagicMock()
    doc.product_tree.parent = MagicMock()
    doc.product_tree.parent.side_effect = lambda x: x.split(":")[0]
    return doc

def test_fixed_from_product_id(doc_with_parent):
    TestCase = namedtuple("TestCase", ["product_id", "expected_name", "expected_version"])
    tests = [
        TestCase(
            "SUSE Linux Enterprise Server 15 SP3-LTSS:curl",
            "curl",
            "",
        ),
        TestCase(
            "SUSE Linux Enterprise Server 12 SP5-LTSS:libcurl4-32bit-8.0.1-11.105.1",
            "libcurl4-32bit",
            "8.0.1-11.105.1",
        ),
    ]
    parser = CSAFParser(workspace=MagicMock(), allow_versions=[12, 15])

    for t in tests:
        fixed_in = parser.fixed_from_product_id(doc_with_parent, t.product_id, "sles:15.3")
        assert fixed_in.Name == t.expected_name
        assert fixed_in.Version == t.expected_version

