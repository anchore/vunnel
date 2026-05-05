from collections.abc import Generator as IterGenerator
from dataclasses import dataclass, field
from typing import Any

from mashumaro import field_options
from mashumaro.config import BaseConfig
from mashumaro.mixins.orjson import DataClassORJSONMixin


class OmitNoneORJSONModel(DataClassORJSONMixin):
    class Config(BaseConfig):
        omit_none = True
        omit_default = True


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
    fixed: list[str] = field(default_factory=list)
    known_affected: list[str] = field(default_factory=list)
    known_not_affected: list[str] = field(default_factory=list)
    under_investigation: list[str] = field(default_factory=list)


@dataclass
class Threat(OmitNoneORJSONModel):
    category: str
    details: str
    product_ids: list[str] = field(default_factory=list)


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

    def __post_init__(self) -> None:
        self.product_id_to_parent = {}
        for r in self.relationships:
            self.product_id_to_parent[r.full_product_name.product_id] = r.relates_to_product_reference

        self.product_id_to_purl = {}
        for b in self.product_branches():
            purl = b.purl()
            pid = b.product_id()
            if purl and pid:
                self.product_id_to_purl[pid] = purl

    def product_branches(self) -> IterGenerator[Branch]:
        for b in self.branches:
            yield from b.product_branches()

    def parent(self, product_id: str) -> str | None:
        return self.product_id_to_parent.get(product_id)

    def purl_for_product_id(self, product_id: str) -> str | None:
        return self.product_id_to_purl.get(product_id)


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
    tlp: TLP
    text: str | None = None


@dataclass
class Publisher(OmitNoneORJSONModel):
    category: str
    contact_details: str
    issuing_authority: str
    name: str
    namespace: str


@dataclass
class GeneratorEngine(OmitNoneORJSONModel):
    name: str
    version: str | None = None


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
    title: str
    tracking: Tracking
    aggregate_severity: AggregateSeverity | None = None
    distribution: Distribution | None = None
    lang: str | None = None
    publisher: Publisher | None = None
    notes: list[Note] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)


@dataclass
class CSAFDoc(OmitNoneORJSONModel):
    document: Document
    product_tree: ProductTree
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @classmethod
    def __pre_deserialize__(cls, d: dict[str, Any]) -> dict[str, Any]:
        """Resolve $ref pointers that some upstream CSAF producers (e.g. openEuler)
        emit instead of inline arrays. All observed references point to
        ``$.vulnerabilities[N].product_status.fixed``; we dereference them so that
        downstream consumers see concrete ``list[str]`` values."""
        for vuln in d.get("vulnerabilities", []):
            fixed = (vuln.get("product_status") or {}).get("fixed", [])
            for score in vuln.get("scores", []):
                if isinstance(score.get("products"), dict):
                    score["products"] = fixed
            for remediation in vuln.get("remediations", []):
                if isinstance(remediation.get("product_ids"), dict):
                    remediation["product_ids"] = fixed
            for threat in vuln.get("threats", []):
                if isinstance(threat.get("product_ids"), dict):
                    threat["product_ids"] = fixed
            for flag in vuln.get("flags", []):
                if isinstance(flag.get("product_ids"), dict):
                    flag["product_ids"] = fixed
        return d


def from_path(path: str) -> CSAFDoc:
    with open(path) as fh:
        return CSAFDoc.from_json(fh.read())
