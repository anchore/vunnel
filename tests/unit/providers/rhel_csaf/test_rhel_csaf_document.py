import pytest
from pathlib import Path

import orjson
from deepdiff import DeepDiff
from vunnel.providers.rhel_csaf.csaf_document import RHEL_CSAFDocument

FIXTURE_DIR = Path(__file__).parent / "test-fixtures"

# Parameterized data structure for specific field assertions
csaf_test_cases = [
    # "cve-2021-46661.json",
    # "cve-2019-12900.json",
    "cve-2019-18276.json",
    # "cve-2024-27316.json",
    "cve-2019-16161.json",
]


def get_csaf_document_path(filename):
    return FIXTURE_DIR / filename

def get_result_json_for_path(csaf_filename):
    result_file = FIXTURE_DIR / f"result-for-{csaf_filename}"
    with open(result_file) as FH:
        return orjson.loads(FH.read())

def dict_sort_key(d: dict) -> str:
    return "".join(f"{key}:{d[key]}" for key in sorted(d.keys()))

@pytest.mark.parametrize("csaf_filename", csaf_test_cases)
def test_vuln_basic_data(csaf_filename):
    csaf_path = get_csaf_document_path(csaf_filename)
    results = get_result_json_for_path(csaf_filename)
    doc = RHEL_CSAFDocument.from_path(csaf_path)
    expected = [r["item"]["Vulnerability"] for r in results]
    actual = [v.to_payload_omit_empty()["Vulnerability"] for v in doc.vulnerabilities()]
    diff = DeepDiff(expected, actual, group_by=("NamespaceName","Name"))
    # assert not diff, f"diff! {pformat(diff, width=120)}"
    assert not diff, f"diff!\n{diff.pretty()}"
