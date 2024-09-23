#!/usr/bin/env python3
from __future__ import annotations

import click
from configure import Config, read_config_state


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


def validate_namespaces_in_db() -> list[str]:
    # open sqlite db at build/vulnerability.db and get a list of unique values in the namespace column
    import sqlite3

    # TODO: this is hardcoded, but should be configurable or key off of yardstick config
    conn = sqlite3.connect("build/vulnerability.db")
    c = conn.cursor()
    c.execute("SELECT DISTINCT namespace FROM vulnerability")
    actual_namespaces = [row[0] for row in c.fetchall()]

    # validate that the namespaces we got are 100% what we expect. If there are any missing or extra namespaces we should fail
    config = Config.load()
    state = read_config_state()
    providers = state.cached_providers + state.uncached_providers

    expected_namespaces = []
    for test in config.tests:
        if test.provider in providers:
            expected_namespaces.extend(test.expected_namespaces)

    extra = set(actual_namespaces) - set(expected_namespaces)
    missing = set(expected_namespaces) - set(actual_namespaces)
    if extra or missing:
        raise RuntimeError(f"mismatched namespaces:\nextra:   {extra}\nmissing: {missing}")

    return actual_namespaces


@click.command()
def main():
    print(f"{bcolors.HEADER}{bcolors.BOLD}Asserting that all and only expected namespaces are found:", bcolors.RESET)
    namespaces = validate_namespaces_in_db()
    print(f"Found the following namespaces:")
    for namespace in namespaces:
        print(f"   - {namespace}")
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}Success!{bcolors.RESET}")


if __name__ == "__main__":
    main()
