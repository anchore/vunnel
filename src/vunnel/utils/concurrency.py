"""Utilities for managing concurrency in providers."""

from __future__ import annotations

import os
from math import ceil


def resolve_workers(
    config_value: int | str,
) -> int:
    """Resolve worker count from config value."""
    if isinstance(config_value, int):
        return config_value
    config_value = config_value.lower()
    if config_value.endswith("x") or config_value == "auto":
        available_cores = os.process_cpu_count() or os.cpu_count() or 4
        if config_value == "auto":
            return available_cores
        if config_value.endswith("x"):
            multiplier = float(config_value.removesuffix("x"))
            return ceil(multiplier * available_cores)
    # in case yaml parsing gave us something like "16"
    return int(config_value)
