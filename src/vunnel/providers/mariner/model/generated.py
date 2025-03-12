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
            "required": True,
        },
    )
    operation: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    value: str = field(
        default="",
        metadata={
            "required": True,
        },
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
            "required": True,
        },
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
            "required": True,
        },
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    name: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "required": True,
        },
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
            "required": True,
        },
    )
    platform: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "required": True,
        },
    )
    test_ref: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
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
            "required": True,
        },
    )
    product_version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
            "required": True,
        },
    )
    schema_version: Optional[float] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
            "required": True,
        },
    )
    timestamp: Optional[XmlDateTime] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
            "required": True,
        },
    )
    content_version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://oval.mitre.org/XMLSchema/oval-common-5",
            "required": True,
        },
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
            "required": True,
        },
    )
    ref_url: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    source: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
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
            "required": True,
        },
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    evr: Optional[Evr] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "required": True,
        },
    )
    comment: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    object_value: Optional[Object] = field(
        default=None,
        metadata={
            "name": "object",
            "type": "Element",
            "required": True,
        },
    )
    state: Optional[State] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "required": True,
        },
    )
    criterion: List[Criterion] = field(
        default_factory=list,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "required": True,
        },
    )
    affected: Optional[Affected] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    reference: Optional[Reference] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    patchable: Optional[Union[bool, str]] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    advisory_date: Optional[XmlDateTime] = field(
        default=None,
        metadata={
            "type": "Element",
        },
    )
    advisory_id: Optional[Union[str, int]] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    severity: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    description: Optional[str] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "min_occurs": 1,
        },
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
            "required": True,
        },
    )
    id: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    version: Optional[int] = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )
    metadata: Optional[Metadata] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    criteria: Optional[Criteria] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
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
            "min_occurs": 1,
        },
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
            "min_occurs": 1,
        },
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
            "min_occurs": 1,
        },
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
            "required": True,
        },
    )
    generator: Optional[Generator] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    definitions: Optional[Definitions] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    tests: Optional[Tests] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    objects: Optional[Objects] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
    states: Optional[States] = field(
        default=None,
        metadata={
            "type": "Element",
            "required": True,
        },
    )
