import re
from dataclasses import dataclass, field

import orjson
from mashumaro.config import BaseConfig
from mashumaro.mixins.dict import DataClassDictMixin


# Custom Config to handle camel case for mashumaro
class CamelCaseConfig(BaseConfig):
    @staticmethod
    def decode_field(name: str) -> str:
        # Convert camelCase to snake_case
        return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


@dataclass
class CVSS_V3(DataClassDictMixin):
    attack_complexity: str
    attack_vector: str
    availability_impact: str
    base_score: str
    base_severity: str
    confidentiality_impact: str
    integrity_impact: str
    privileges_required: str
    scope: str
    user_interaction: str
    vector_string: str
    version: str

    class Config(CamelCaseConfig):
        pass

    @classmethod
    def from_json(cls, json_data: str):
        data = orjson.loads(json_data)
        return cls.from_dict(data)


@dataclass
class Reference(DataClassDictMixin):
    category: str
    summary: str
    url: str


@dataclass
class Note(DataClassDictMixin):
    category: str
    text: str
    title: str


@dataclass
class ProductStatus(DataClassDictMixin):
    fixed: list[str] = field(default_factory=list)
    known_affected: list[str] = field(default_factory=list)
    known_not_affected: list[str] = field(default_factory=list)


@dataclass
class Threat(DataClassDictMixin):
    category: str
    details: str
    product_ids: list[str] = field(default_factory=list)


@dataclass
class CWE(DataClassDictMixin):
    id: str
    name: str


@dataclass
class Flag(DataClassDictMixin):
    label: str
    product_ids: list[str]


@dataclass
class VulnID(DataClassDictMixin):
    system_name: str
    text: str


@dataclass
class Remediation(DataClassDictMixin):
    category: str
    details: str
    product_ids: list[str]
    url: str | None = None


@dataclass
class Score(DataClassDictMixin):
    cvss_v3: CVSS_V3
    products: list[str]


@dataclass
class Vulnerability(DataClassDictMixin):
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
    threats: list[Threat] = field(default_factory=list)

    def all_advisory_urls(self) -> set[str]:
        result = set()
        for r in self.remediations:
            if r.category == "vendor_fix":
                result.add(r.url)

        return result

    def advisory_url_for_product(self, product_id: str) -> str | None:
        for r in self.remediations:
            if r.category == "vendor_fix" and product_id in r.product_ids:
                return r.url
        return None


@dataclass
class FullProductName(DataClassDictMixin):
    name: str
    product_id: str


@dataclass
class Relationship(DataClassDictMixin):
    category: str
    full_product_name: FullProductName
    product_reference: str
    relates_to_product_reference: str


@dataclass
class ProductIdentificationHelper(DataClassDictMixin):
    cpe: str | None = None
    purl: str | None = None


@dataclass
class Product(DataClassDictMixin):
    name: str
    product_id: str
    product_identification_helper: ProductIdentificationHelper | None = None


@dataclass
class Branch:
    category: str
    name: str
    branches: list["Branch"] = field(default_factory=list)
    product: Product | None = None

    def acculumulate_categories_recursively(self, accumulator: set[str]):
        accumulator.add(self.category)
        for b in self.branches:
            b.acculumulate_categories_recursively(accumulator)

    def source_rpm_product_ids(self) -> set[str]:
        result = set()
        if (
            self.product
            and self.product.product_identification_helper
            and (
                (
                    self.product.product_identification_helper.purl
                    and "arch=src" in self.product.product_identification_helper.purl
                )
                or re.search(r"\.el\d+.src$", self.product.product_id)
            )
        ):
            result.add(self.product.product_id)

        for b in self.branches:
            result = result | b.source_rpm_product_ids()
        return result

    def product_branches(self) -> list["Branch"]:
        result = []
        for b in self.branches:
            if b.product:
                result.append(b)
            elif b.branches:
                result.extend(b.product_branches())
        return result

    def product_version_branches(self) -> list["Branch"]:
        result = []
        if self.category == "product_version":
            result.append(self)
        for b in self.branches:
            result.extend(b.product_version_branches())

        return result

    def product_name_branches(self) -> list["Branch"]:
        result = []
        if self.category == "product_name":
            result.append(self)
        for b in self.branches:
            result.extend(b.product_name_branches())

        return result


@dataclass
class ProductTree(DataClassDictMixin):
    relationships: list[Relationship] = field(default_factory=list)
    branches: list[Branch] = field(default_factory=list)
    product_id_to_parent: dict[str, str] = field(init=False)

    def __post_init__(self):
        self.product_id_to_parent = {}
        for r in self.relationships:
            self.product_id_to_parent[r.full_product_name.product_id] = r.relates_to_product_reference

    def parent(self, product_id: str) -> str | None:
        return self.product_id_to_parent.get(product_id)

    def first_parent(self, product_id: str) -> str:
        here = product_id
        last_product_id = product_id
        while here:
            last_product_id = here
            here = self.parent(here)
        return last_product_id

    def second_parent(self, product_id: str) -> str | None:
        root = self.first_parent(product_id)  # Find the root using first_parent
        here = product_id
        previous = None

        # Traverse up the tree until we reach the root
        while here and here != root:
            previous = here  # Track the child of the root
            here = self.parent(here)  # Move up one level

        return previous  # This is the immediate child of the root

    def distinct_branch_categories(self) -> set[str]:
        result = set()
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

    def product_branches(self) -> list[Branch]:
        result = []
        for b in self.branches:
            if b.product:
                result.append(b)
            else:
                result.extend(b.product_branches())
        return result


@dataclass
class AggregateSeverity(DataClassDictMixin):
    namespace: str
    text: str


@dataclass
class TLP(DataClassDictMixin):
    label: str
    url: str


@dataclass
class Distribution(DataClassDictMixin):
    text: str
    tlp: TLP


@dataclass
class Publisher(DataClassDictMixin):
    category: str
    contact_details: str
    issuing_authority: str
    name: str
    namespace: str


@dataclass
class GeneratorEngine(DataClassDictMixin):
    name: str
    version: str


@dataclass
class Generator(DataClassDictMixin):
    date: str
    engine: GeneratorEngine


@dataclass
class RevisionEntry(DataClassDictMixin):
    date: str
    number: str  # yes, really
    summary: str


@dataclass
class Tracking(DataClassDictMixin):
    current_release_date: str
    generator: Generator
    id: str
    initial_release_date: str
    revision_history: list[RevisionEntry]
    status: str
    version: str


@dataclass
class Document(DataClassDictMixin):
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
class CSAF_JSON(DataClassDictMixin):
    document: Document
    product_tree: ProductTree
    vulnerabilities: list[Vulnerability]


def from_path(path: str) -> CSAF_JSON:
    with open(path) as fh:
        data = orjson.loads(fh.read())
        return CSAF_JSON.from_dict(data)
