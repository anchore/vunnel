# pylint: skip-file
from dataclasses import asdict, dataclass, field
from operator import itemgetter
from typing import Any

severity_order = {
    "Unknown": 0,
    "Negligible": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}

vulnerability_element = {
    "Vulnerability": {
        "Severity": None,
        "NamespaceName": None,
        "FixedIn": [],
        "Link": None,
        "Description": "",
        "Metadata": {},
        "Name": None,
        "CVSS": [],
    }
}


def order_payload(payload, feed_type):
    if payload and feed_type:
        if (
            feed_type == "vulnerabilities"
            and "Vulnerability" in payload
            and "FixedIn" in payload["Vulnerability"]
            and payload["Vulnerability"]["FixedIn"]
        ):
            payload["Vulnerability"]["FixedIn"].sort(key=(itemgetter("Name", "Version")))
        elif feed_type == "packages":
            for content in payload.values():
                for key, value in content.items():
                    if isinstance(value, list):
                        value.sort()
        else:
            pass

    return payload


@dataclass
class FixedIn:
    """
    Class representing a fix record for return back to the service from the driver. The semantics of the version are:
    "None" -> Package is vulnerable and no fix available yet
    ! "None" -> Version of package with a fix for a vulnerability. Assume all older versions of the package are vulnerable.

    """

    Name: str
    NamespaceName: str
    VersionFormat: str
    Version: str


@dataclass
class CVSSBaseMetrics:
    base_score: float
    exploitability_score: float
    impact_score: float
    base_severity: str


@dataclass
class CVSS:
    version: str
    vector_string: str
    base_metrics: CVSSBaseMetrics
    status: str


@dataclass
class Vulnerability:
    """
    Class representing the record to be returned. Uses strange capitalization
    to be backwards compatible in the json output with previous version of feed data.
    """

    Name: str
    NamespaceName: str
    Description: str
    Severity: str
    Link: str
    CVSS: list[CVSS]
    FixedIn: list[FixedIn]
    Metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self):
        return {"Vulnerability": asdict(self)}
