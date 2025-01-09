import re
from dataclasses import dataclass, field
from decimal import Decimal

import orjson
from cvss import CVSS3
from cvss.exceptions import CVSS3Error
from mashumaro import field_options
from mashumaro.config import BaseConfig
from mashumaro.mixins.dict import DataClassDictMixin

from vunnel.utils.vulnerability import CVSS, CVSSBaseMetrics


# TODO: is this still doing anything?
# Custom Config to handle camel case for mashumaro
class CamelCaseConfig(BaseConfig):
    @staticmethod
    def decode_field(name: str) -> str:
        # Convert camelCase to snake_case
        return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


@dataclass
class CVSS_V3(DataClassDictMixin):
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

    class Config(CamelCaseConfig):
        pass


@dataclass
class CVSS_V2(DataClassDictMixin):
    access_complexity: str = field(metadata=field_options(alias="accessComplexity"))
    access_vector: str = field(metadata=field_options(alias="accessVector"))
    authentication: str = field(metadata=field_options(alias="authentication"))
    availability_impact: str = field(metadata=field_options(alias="availabilityImpact"))
    base_score: float = field(metadata=field_options(alias="baseScore"))
    confidentiality_impact: str = field(metadata=field_options(alias="confidentialityImpact"))
    integrity_impact: str = field(metadata=field_options(alias="integrityImpact"))
    vector_string: str = field(metadata=field_options(alias="vectorString"))
    version: str = field(metadata=field_options(alias="version"))

    class Config(CamelCaseConfig):
        pass


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
    fixed: set[str] = field(default_factory=set)
    known_affected: set[str] = field(default_factory=set)
    known_not_affected: set[str] = field(default_factory=set)
    under_investigation: set[str] = field(default_factory=set)


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
    product_ids: set[str]


@dataclass
class VulnID(DataClassDictMixin):
    system_name: str
    text: str


@dataclass
class Remediation(DataClassDictMixin):
    category: str
    details: str
    product_ids: set[str]
    url: str | None = None


@dataclass
class Score(DataClassDictMixin):
    products: set[str]
    cvss_v3: CVSS_V3 | None = None
    cvss_v2: CVSS_V2 | None = None

    def to_vunnel_cvss(self, status: str = "draft") -> CVSS | None:
        if self.cvss_v3:
            try:
                cvss3_obj = CVSS3(self.cvss_v3.vector_string)
                return CVSS(
                    version=self.cvss_v3.version,
                    vector_string=self.cvss_v3.vector_string,
                    base_metrics=CVSSBaseMetrics(
                        base_score=self.cvss_v3.base_score,
                        exploitability_score=float(cvss3_obj.esc.quantize(Decimal("1.0"))),
                        impact_score=float(cvss3_obj.isc.quantize(Decimal("1.0"))),
                        base_severity=cvss3_obj.severities()[0],
                    ),
                    status=status,
                )
            except CVSS3Error:
                return None
        # TODO: handle CVSS v2
        return None


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

    def __post_init__(self) -> None:
        self.product_id_to_parent = {}
        for r in self.relationships:
            self.product_id_to_parent[r.full_product_name.product_id] = r.relates_to_product_reference

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
class CSAFDoc(DataClassDictMixin):
    document: Document
    product_tree: ProductTree
    vulnerabilities: list[Vulnerability]


def from_path(path: str) -> CSAFDoc:
    with open(path) as fh:
        data = orjson.loads(fh.read())
        return CSAFDoc.from_dict(data)
