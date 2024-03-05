UNKNOWN_VALUES =  {"", "-", "n/a", "unknown", "[unknown]", "(as-yet-unknown)"}

def is_unknown(value: str | None) -> bool:
    if not value:
        return True

    if value.lower().strip().strip("*").strip() in UNKNOWN_VALUES:
        return True

    return False


def normalize(value: str | None) -> str | None:
    if is_unknown(value):
        return None

    return value.lower().strip()

def normalize_collection_url(collection_url: str) -> str | None:
    collection_url = normalize(collection_url)

    if not collection_url:
        return None

    collection_url = collection_url.removesuffix("/")
    collection_url = collection_url.removeprefix("http://")
    collection_url = collection_url.removeprefix("https://")
    collection_url = collection_url.replace("repo1.maven.org", "repo.maven.apache.org")
    collection_url = collection_url.replace("pypi.python.org", "pypi.org")

    if collection_url.startswith("repo.maven.apache.org/maven2/"):
        return "repo.maven.apache.org/maven2"

    if collection_url.startswith("pypi.org/"):
        return "pypi.org"

    return collection_url


def cpes_from_collection_url(collection_url: str, package_name: str) -> list[str] | None:
    collection_url = normalize_collection_url(collection_url)
    package_name = normalize(package_name)

    if not collection_url or not package_name:
        return None

    if "repo.maven.apache.org/maven2" in collection_url:
        components = package_name.split(":")
        if len(components) == 2:
            return [f"cpe:2.3:a:{components[0]}:{components[1]}:*:*:*:*:*:*:*:*"]

    return None


def generate_candidates(value: str) -> list[str]:
    # Use a list because ordering is important (we want the original value to take precendence
    # over the additional generated ones)
    candidates = []
    value = normalize(value)

    if value:
        candidates.append(value)
        for s1, s2 in [(" ", "_"),(" ", "-"),("-", " "),("-", "_"),("_", " "),("_", "-")]:
            v = value.replace(s1, s2)
            if v not in candidates:
                candidates.append(v)

    return list(candidates)


def cpes_from_vendor_and_product(vendor, product) -> list[str]:
    vendors = generate_candidates(vendor)
    products = generate_candidates(product)
    cpes = []

    if vendors and products:
        for v in vendors:
            for p in products:
                cpes.append(f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:*:*:*")

    return cpes
