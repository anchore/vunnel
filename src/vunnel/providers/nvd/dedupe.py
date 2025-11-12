from __future__ import annotations

from typing import Any


def deduplicate_references(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate reference entries from a CVE record.

    References are considered duplicates if they have the same URL.
    When duplicates are found, keeps the first occurrence and discards subsequent ones.

    Args:
        references: List of reference dictionaries from NVD CVE data.
                   Each reference should have at minimum a 'url' field.

    Returns:
        Deduplicated list of references, preserving original order.
        Returns empty list if input is None or empty.

    Example:
        >>> refs = [
        ...     {"url": "https://example.com", "source": "cve@mitre.org"},
        ...     {"url": "https://example.com", "source": "cve@mitre.org"},
        ...     {"url": "https://other.com", "source": "nvd@nist.gov"},
        ... ]
        >>> deduplicate_references(refs)
        [
            {"url": "https://example.com", "source": "cve@mitre.org"},
            {"url": "https://other.com", "source": "nvd@nist.gov"},
        ]
    """
    if not references:
        return []

    seen_refs: set[tuple[str, str, tuple[str, ...]]] = set()
    deduplicated: list[dict[str, Any]] = []

    for ref in references:
        url = ref.get("url")
        if not url:
            # Skip references without a URL (malformed data)
            continue

        # Create a hashable key from the entire reference
        # References have: url (required), source (optional), tags (optional list)
        source = ref.get("source", "")
        tags = tuple(sorted(ref.get("tags", [])))  # Sort tags for consistent comparison

        ref_key = (url, source, tags)

        if ref_key not in seen_refs:
            seen_refs.add(ref_key)
            deduplicated.append(ref)

    return deduplicated
