import re
from collections.abc import Generator as IterGenerator
from dataclasses import dataclass, field

import orjson
from mashumaro import field_options
from mashumaro.config import BaseConfig, TO_DICT_ADD_OMIT_NONE_FLAG
from mashumaro.mixins.orjson import DataClassORJSONMixin

class OmitNoneORJSONModel(DataClassORJSONMixin):
    class Config(BaseConfig):
        omit_none = True

@dataclass
class CVSS_V3(DataClassORJSONMixin):
    attack_complexity: str = field(metadata=field_options(alias="attackComplexity"))
    attack_vector: str = field(metadata=field_options(alias="attackVector"))
    availability_impact: str = field(metadata=field_options(alias="availabilityImpact"))
    base_score: float = field(metadata=field_options(alias="baseScore"))
    base_severity: str = field(metadata=field_options(alias="baseSeverity"))
    confidentiality_impact: str = field(metadata=field_options(alias="confidentialityImpact"))
    integrity_impact: str = field(metadata=field_options(alias="integrityImpact"))
    privileges_required: str = field(metadata=field_options(alias="privilegesRequired"))
    scope: str = field(metadata=field_options(alias="scope"))
    user_interaction: str = field(metadata=field_options(alias="userInteraction"))
    vector_string: str = field(metadata=field_options(alias="vectorString"))
    version: str = field(metadata=field_options(alias="version"))

    class Config(BaseConfig):
        serialize_by_alias = True  # normal CSAF is snake_case, but embeds camelCase CVSS objects


@dataclass
class CVSS_V2(DataClassORJSONMixin):
    access_complexity: str = field(metadata=field_options(alias="accessComplexity"))
    access_vector: str = field(metadata=field_options(alias="accessVector"))
    authentication: str = field(metadata=field_options(alias="authentication"))
    availability_impact: str = field(metadata=field_options(alias="availabilityImpact"))
    base_score: float = field(metadata=field_options(alias="baseScore"))
    confidentiality_impact: str = field(metadata=field_options(alias="confidentialityImpact"))
    integrity_impact: str = field(metadata=field_options(alias="integrityImpact"))
    vector_string: str = field(metadata=field_options(alias="vectorString"))
    version: str = field(metadata=field_options(alias="version"))

    class Config(BaseConfig):
        serialize_by_alias = True  # normal CSAF is snake_case, but embeds camelCase CVSS objects


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
    cwe: str | None = None
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

    def all_advisory_urls(self) -> set[str]:
        result = set()
        for r in self.remediations:
            if r.category == "vendor_fix" and r.url:
                result.add(r.url)

        return result

    def advisory_url_for_product(self, product_id: str) -> str | None:
        for r in self.remediations:
            if r.category == "vendor_fix" and product_id in r.product_ids:
                return r.url
        return None


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

    def acculumulate_categories_recursively(self, accumulator: set[str]) -> None:
        accumulator.add(self.category)
        for b in self.branches:
            b.acculumulate_categories_recursively(accumulator)

    def source_rpm_product_ids(self) -> set[str]:
        result = set()
        if (
            self.product
            and self.product.product_identification_helper
            and (
                (self.product.product_identification_helper.purl and "arch=src" in self.product.product_identification_helper.purl)
                or re.search(r"\.el\d+.src$", self.product.product_id)
            )
        ):
            result.add(self.product.product_id)

        for b in self.branches:
            result = result | b.source_rpm_product_ids()
        return result

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

    def product_branches(self) -> IterGenerator["Branch", None, None]:
        for b in self.branches:
            if b.product:
                yield b
            elif b.branches:
                yield from b.product_branches()

    def product_version_branches(self) -> IterGenerator["Branch", None, None]:
        stack = [self]
        while stack:
            current = stack.pop()
            if current.category == "product_version":
                yield current
            stack.extend(current.branches)
        # if self.category == "product_version":
        #     yield self
        # for b in self.branches:
        #     yield from b.product_version_branches()

    def product_name_branches(self) -> IterGenerator["Branch", None, None]:
        if self.category == "product_name":
            yield self
        for b in self.branches:
            yield from b.product_name_branches()


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

    def parent(self, product_id: str) -> str | None:
        return self.product_id_to_parent.get(product_id)

    def first_parent(self, product_id: str) -> str:
        here: str | None = product_id
        last_product_id = product_id
        while here:
            last_product_id = here
            here = self.parent(here)
        return last_product_id

    def second_parent(self, product_id: str) -> str | None:
        root = self.first_parent(product_id)  # Find the root using first_parent
        here: str | None = product_id
        previous = None

        # Traverse up the tree until we reach the root
        while here and here != root:
            previous = here  # Track the child of the root
            here = self.parent(here)  # Move up one level

        if previous != product_id:
            return previous
        return None

    def distinct_branch_categories(self) -> set[str]:
        result: set[str] = set()
        for b in self.branches:
            b.acculumulate_categories_recursively(result)

        return result

    def has_ancestor(self, product_id: str, maybe_ancestor_id: str) -> bool:
        parent = self.parent(product_id)
        while parent:
            if parent == maybe_ancestor_id:
                return True
            parent = self.parent(parent)
        return False

    def product_branches(self) -> IterGenerator[Branch, None, None]:
        for b in self.branches:
            if b.product:
                yield b
            else:
                yield from b.product_branches()

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
    text: str
    tlp: TLP


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
    aggregate_severity: AggregateSeverity
    category: str
    csaf_version: str
    distribution: Distribution
    lang: str
    notes: list[Note]
    publisher: Publisher
    references: list[Reference]
    title: str
    tracking: Tracking


@dataclass
class CSAFDoc(OmitNoneORJSONModel):
    document: Document
    product_tree: ProductTree
    vulnerabilities: list[Vulnerability]

    class Config(BaseConfig):
        code_generation_options = [TO_DICT_ADD_OMIT_NONE_FLAG]


def from_path(path: str) -> CSAFDoc:
    with open(path) as fh:
        return CSAFDoc.from_json(fh.read())
