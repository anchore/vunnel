def normalize_package_name(name: str, ecosystem: str | None) -> str:
    """normalize package name for consistent lookups"""
    normalized = name.strip()

    if ecosystem in ("pypi", "python"):
        # follow PEP 503 normalization for Python packages (https://peps.python.org/pep-0503/)
        # note: any casing normalization is handled by the database queries
        normalized = normalized.replace("_", "-").replace(".", "-")

    return normalized
