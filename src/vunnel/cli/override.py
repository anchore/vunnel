import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass

import click
import requests

from vunnel.cli import config


@click.group(name="override", help="create and manage overrides of upstream data")
@click.pass_obj
def group(_: config.Application):
    pass


def compute_sha256_of_json(json_data: any):
    # Serialize the JSON document with sorted keys to ensure determinism
    serialized_json = json.dumps(json_data, sort_keys=True)

    # Compute the SHA256 hash of the serialized JSON document
    hash_sha256 = hashlib.sha256(serialized_json.encode("utf-8")).hexdigest()

    return hash_sha256


@dataclass
class Package:
    identifier: str
    qualifiers: dict[str, str]


@dataclass
class VersionIdentifier:
    constraint: str
    patched: str
    type: str  # enum


@dataclass
class AdditionalEntry:
    package: Package
    affected: list[VersionIdentifier]


@dataclass
class OverrideRecord:
    vuln_id: str
    provider: str
    upstream_record_sha256: str
    addtional_entries: list[AdditionalEntry]


def create_blank_override_record(vuln_id: str, provider: str, upstream_record_sha256: str) -> OverrideRecord:
    return OverrideRecord(
        vuln_id=vuln_id,
        provider=provider,
        upstream_record_sha256=upstream_record_sha256,
        addtional_entries=[],
    )


@group.command(name="create", help="create an override")
@click.argument("provider_name")
@click.argument("vuln_id")
@click.pass_obj
def create_override(cfg: config.Application, provider_name: str, vuln_id: str) -> None:
    print(f"creating override for {provider_name} {vuln_id}", file=sys.stderr)
    # TODO:
    # download (or find!) the data and save it to the override location
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vuln_id}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()["vulnerabilities"][0]
    dir_path = os.path.join(cfg.root, provider_name, "overrides")
    os.makedirs(dir_path, exist_ok=True)
    override_path = os.path.join(dir_path, f"{vuln_id}.json")
    # TODO: report if path exists
    record = create_blank_override_record(vuln_id, provider_name, compute_sha256_of_json(data))
    with open(override_path, "w") as f:
        f.write(json.dumps(asdict(record), indent=2))
    print(override_path)
