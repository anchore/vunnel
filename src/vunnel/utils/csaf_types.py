from collections.abc import Generator as IterGenerator
from dataclasses import dataclass, field
from typing import Any

from mashumaro import field_options
from mashumaro.config import BaseConfig
from mashumaro.mixins.orjson import DataClassORJSONMixin


class OmitNoneORJSONModel(DataClassORJSONMixin):
    class Config(BaseConfig):
        omit_none = True


def _omit_empty(d: dict[str, Any], *keys: str) -> dict[str, Any]:
    """Every list-typed CSAF property is optional-when-empty per spec (arrays are
    consistently `minItems: 1` where present at all) -- but a `default_factory=list`
    field always serializes as `[]` under mashumaro's `omit_none` (which only omits
    None, not empty collections). Drop the key entirely so re-serialized/subsetted
    documents stay schema-valid."""
    for key in keys:
        if key in d and not d[key]:
            del d[key]
    return d


@dataclass
class CVSS_V3(DataClassORJSONMixin):
    # required per CVSS v3.0/v3.1 schema
    base_score: float = field(metadata=field_options(alias="baseScore"))
    base_severity: str = field(metadata=field_options(alias="baseSeverity"))
    vector_string: str = field(metadata=field_options(alias="vectorString"))
    version: str = field(metadata=field_options(alias="version"))
    # optional per spec (derivable from vector string)
    attack_complexity: str | None = field(default=None, metadata=field_options(alias="attackComplexity"))
    attack_vector: str | None = field(default=None, metadata=field_options(alias="attackVector"))
    availability_impact: str | None = field(default=None, metadata=field_options(alias="availabilityImpact"))
    confidentiality_impact: str | None = field(default=None, metadata=field_options(alias="confidentialityImpact"))
    integrity_impact: str | None = field(default=None, metadata=field_options(alias="integrityImpact"))
    privileges_required: str | None = field(default=None, metadata=field_options(alias="privilegesRequired"))
    scope: str | None = field(default=None, metadata=field_options(alias="scope"))
    user_interaction: str | None = field(default=None, metadata=field_options(alias="userInteraction"))

    class Config(BaseConfig):
        serialize_by_alias = True  # normal CSAF is snake_case, but embeds camelCase CVSS objects
        omit_none = True


@dataclass
class CVSS_V2(DataClassORJSONMixin):
    # required per CVSS v2.0 schema
    base_score: float = field(metadata=field_options(alias="baseScore"))
    vector_string: str = field(metadata=field_options(alias="vectorString"))
    version: str = field(metadata=field_options(alias="version"))
    # optional per spec (derivable from vector string)
    access_complexity: str | None = field(default=None, metadata=field_options(alias="accessComplexity"))
    access_vector: str | None = field(default=None, metadata=field_options(alias="accessVector"))
    authentication: str | None = field(default=None, metadata=field_options(alias="authentication"))
    availability_impact: str | None = field(default=None, metadata=field_options(alias="availabilityImpact"))
    confidentiality_impact: str | None = field(default=None, metadata=field_options(alias="confidentialityImpact"))
    integrity_impact: str | None = field(default=None, metadata=field_options(alias="integrityImpact"))

    class Config(BaseConfig):
        serialize_by_alias = True  # normal CSAF is snake_case, but embeds camelCase CVSS objects
        omit_none = True


@dataclass
class Reference(OmitNoneORJSONModel):
    category: str
    summary: str
    url: str


@dataclass
class Note(OmitNoneORJSONModel):
    category: str
    text: str
    title: str


@dataclass
class ProductStatus(OmitNoneORJSONModel):
    # all 8 properties defined by the CSAF 2.0 spec (section 3.2.3.9); RHEL's CSAF only
    # ever populates fixed/known_affected/known_not_affected/under_investigation, but
    # other publishers (e.g. SUSE) use the full set.
    first_affected: list[str] = field(default_factory=list)
    first_fixed: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    known_affected: list[str] = field(default_factory=list)
    known_not_affected: list[str] = field(default_factory=list)
    last_affected: list[str] = field(default_factory=list)
    recommended: list[str] = field(default_factory=list)
    under_investigation: list[str] = field(default_factory=list)

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        return _omit_empty(
            d,
            "first_affected",
            "first_fixed",
            "fixed",
            "known_affected",
            "known_not_affected",
            "last_affected",
            "recommended",
            "under_investigation",
        )


@dataclass
class Threat(OmitNoneORJSONModel):
    category: str
    details: str
    product_ids: list[str] = field(default_factory=list)

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        return _omit_empty(d, "product_ids")


@dataclass
class CWE(OmitNoneORJSONModel):
    id: str
    name: str


@dataclass
class Flag(OmitNoneORJSONModel):
    label: str
    product_ids: list[str]


@dataclass
class VulnID(OmitNoneORJSONModel):
    system_name: str
    text: str


@dataclass
class Remediation(OmitNoneORJSONModel):
    category: str
    details: str
    product_ids: list[str]
    date: str | None = None
    url: str | None = None


@dataclass
class Score(OmitNoneORJSONModel):
    products: list[str]
    cvss_v3: CVSS_V3 | None = None
    cvss_v2: CVSS_V2 | None = None


@dataclass
class Vulnerability(OmitNoneORJSONModel):
    title: str
    cve: str
    cwe: CWE | None = None
    discovery_date: str | None = None
    flags: list[Flag] = field(default_factory=list)
    ids: list[VulnID] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)
    product_status: ProductStatus | None = None
    references: list[Reference] | None = None
    release_date: str | None = None
    remediations: list[Remediation] = field(default_factory=list)
    scores: list[Score] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        return _omit_empty(d, "flags", "ids", "notes", "remediations", "scores", "threats")


@dataclass
class FullProductName(OmitNoneORJSONModel):
    name: str
    product_id: str


@dataclass
class Relationship(OmitNoneORJSONModel):
    category: str
    full_product_name: FullProductName
    product_reference: str
    relates_to_product_reference: str


@dataclass
class ProductIdentificationHelper(OmitNoneORJSONModel):
    cpe: str | None = None
    purl: str | None = None


@dataclass
class Product(OmitNoneORJSONModel):
    name: str
    product_id: str
    product_identification_helper: ProductIdentificationHelper | None = None


@dataclass
class Branch(OmitNoneORJSONModel):
    category: str
    name: str
    branches: list["Branch"] = field(default_factory=list)
    product: Product | None = None

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        # spec section 3.2.2.1: a branch has exactly 3 properties -- category, name,
        # and EITHER branches OR product, never both/neither. A leaf branch (the
        # common case: no children, just `product`) must omit `branches` entirely
        # rather than serialize an empty array, or `maxProperties: 3` rejects it.
        return _omit_empty(d, "branches")

    def purl(self) -> str | None:
        if self.product and self.product.product_identification_helper:
            return self.product.product_identification_helper.purl
        return None

    def cpe(self) -> str | None:
        if self.product and self.product.product_identification_helper:
            return self.product.product_identification_helper.cpe
        return None

    def product_id(self) -> str | None:
        if self.product:
            return self.product.product_id
        return None

    def product_branches(self) -> IterGenerator["Branch"]:
        yield self
        for b in self.branches:
            yield from b.product_branches()

    def product_version_branches(self) -> IterGenerator["Branch"]:
        for b in self.product_branches():
            if b.category == "product_version":
                yield b

    def product_name_branches(self) -> IterGenerator["Branch"]:
        for b in self.product_branches():
            if b.category == "product_name":
                yield b


@dataclass
class ProductTree(OmitNoneORJSONModel):
    relationships: list[Relationship] = field(default_factory=list)
    branches: list[Branch] = field(default_factory=list)
    product_id_to_parent: dict[str, str] = field(
        init=False,
        metadata={"serialize": "omit"},  # field is a cache for runtime efficiency, but not part of spec
    )
    product_id_to_purl: dict[str, str] = field(
        init=False,
        metadata={"serialize": "omit"},  # field is a cache for runtime efficiency, but not part of spec
    )
    product_id_to_cpe: dict[str, str] = field(
        init=False,
        metadata={"serialize": "omit"},  # field is a cache for runtime efficiency, but not part of spec
    )

    def __post_init__(self) -> None:
        self.product_id_to_parent = {}
        for r in self.relationships:
            self.product_id_to_parent[r.full_product_name.product_id] = r.relates_to_product_reference

        self.product_id_to_purl = {}
        self.product_id_to_cpe = {}
        for b in self.product_branches():
            pid = b.product_id()
            if not pid:
                continue
            purl = b.purl()
            if purl:
                self.product_id_to_purl[pid] = purl
            cpe = b.cpe()
            if cpe:
                self.product_id_to_cpe[pid] = cpe

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        return _omit_empty(d, "relationships", "branches")

    def product_branches(self) -> IterGenerator[Branch]:
        for b in self.branches:
            yield from b.product_branches()

    def parent(self, product_id: str) -> str | None:
        return self.product_id_to_parent.get(product_id)

    def purl_for_product_id(self, product_id: str) -> str | None:
        return self.product_id_to_purl.get(product_id)

    def cpe_for_product_id(self, product_id: str) -> str | None:
        return self.product_id_to_cpe.get(product_id)


@dataclass
class AggregateSeverity(OmitNoneORJSONModel):
    namespace: str
    text: str


@dataclass
class TLP(OmitNoneORJSONModel):
    label: str
    url: str


@dataclass
class Distribution(OmitNoneORJSONModel):
    text: str
    tlp: TLP


@dataclass
class Publisher(OmitNoneORJSONModel):
    # spec section 3.2.1.8: only category/name/namespace are mandatory --
    # contact_details and issuing_authority are both optional (SUSE's docs omit
    # issuing_authority entirely).
    category: str
    name: str
    namespace: str
    contact_details: str | None = None
    issuing_authority: str | None = None


@dataclass
class GeneratorEngine(OmitNoneORJSONModel):
    name: str
    version: str


@dataclass
class Generator(OmitNoneORJSONModel):
    date: str
    engine: GeneratorEngine


@dataclass
class RevisionEntry(OmitNoneORJSONModel):
    date: str
    number: str  # yes, really
    summary: str


@dataclass
class Tracking(OmitNoneORJSONModel):
    current_release_date: str
    generator: Generator
    id: str
    initial_release_date: str
    revision_history: list[RevisionEntry]
    status: str
    version: str


@dataclass
class Document(OmitNoneORJSONModel):
    category: str
    csaf_version: str
    publisher: Publisher
    title: str
    tracking: Tracking
    aggregate_severity: AggregateSeverity | None = None
    distribution: Distribution | None = None
    lang: str | None = None
    notes: list[Note] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        return _omit_empty(d, "notes", "references")


@dataclass
class CSAFDoc(OmitNoneORJSONModel):
    document: Document
    # spec section 3.2: only `document` is mandatory -- `product_tree` and
    # `vulnerabilities` are both optional. A publisher can validly emit a
    # document-only CSAF doc (e.g. SUSE does this for CVEs it has decided don't
    # apply to any of its products).
    product_tree: ProductTree | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    def __post_serialize__(self, d: dict[str, Any]) -> dict[str, Any]:
        return _omit_empty(d, "vulnerabilities")


def from_path(path: str) -> CSAFDoc:
    with open(path) as fh:
        return CSAFDoc.from_json(fh.read())
