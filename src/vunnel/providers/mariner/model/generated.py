from dataclasses import dataclass, field
from typing import List, Optional, Union
from xsdata.models.datatype import XmlDateTime


@dataclass
class Evr:
    class Meta:
        name = "evr"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

    datatype: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    operation: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    value: str = field(
        default=""
    )


@dataclass
class Object:
    class Meta:
        name = "object"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

    object_ref: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class RpminfoObject:
    class Meta:
        name = "rpminfo_object"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

    id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    name: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class State:
    class Meta:
        name = "state"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

    state_ref: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Affected:
    class Meta:
        name = "affected"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    family: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    platform: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Criterion:
    class Meta:
        name = "criterion"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    comment: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    test_ref: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class Generator:
    class Meta:
        name = "generator"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    product_name: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
        }
    )
    product_version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
        }
    )
    schema_version: Optional[float] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
        }
    )
    timestamp: Optional[XmlDateTime] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
        }
    )
    content_version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
        }
    )


@dataclass
class Reference:
    class Meta:
        name = "reference"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    ref_id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    ref_url: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    source: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )


@dataclass
class RpminfoState:
    class Meta:
        name = "rpminfo_state"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

    id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    evr: Optional[Evr] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class RpminfoTest:
    class Meta:
        name = "rpminfo_test"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

    check: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    comment: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    object_value: Optional[Object] = field(
        default=None,
        metadata={
            "name": "object",
            "type": "Element",
        }
    )
    state: Optional[State] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Criteria:
    class Meta:
        name = "criteria"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    operator: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    criterion: Optional[Criterion] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Metadata:
    class Meta:
        name = "metadata"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    title: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    affected: Optional[Affected] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    reference: Optional[Reference] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    patchable: Optional[Union[bool, str]] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    advisory_date: Optional[XmlDateTime] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    advisory_id: Optional[Union[str, int]] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    severity: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    description: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class Objects:
    class Meta:
        name = "objects"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    rpminfo_object: List[RpminfoObject] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
        }
    )


@dataclass
class Definition:
    class Meta:
        name = "definition"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    class_value: Optional[str] = field(
        default=None,
        metadata={
            "name": "class",
            "type": "Attribute",
        }
    )
    id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
        }
    )
    metadata: Optional[Metadata] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    criteria: Optional[Criteria] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class States:
    class Meta:
        name = "states"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    rpminfo_state: List[RpminfoState] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
        }
    )


@dataclass
class Tests:
    class Meta:
        name = "tests"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    rpminfo_test: List[RpminfoTest] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
        }
    )


@dataclass
class Definitions:
    class Meta:
        name = "definitions"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    definition: List[Definition] = field(
        default_factory=list,
        metadata={
            "type": "Element",
        }
    )


@dataclass
class OvalDefinitions:
    class Meta:
        name = "oval_definitions"
        namespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

    schema_location: Optional[str] = field(
        default=None,
        metadata={
            "name": "schemaLocation",
            "type": "Attribute",
            "namespace": "http://www.w3.org/2001/XMLSchema-instance",
        }
    )
    generator: Optional[Generator] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    definitions: Optional[Definitions] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    tests: Optional[Tests] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    objects: Optional[Objects] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
    states: Optional[States] = field(
        default=None,
        metadata={
            "type": "Element",
        }
    )
