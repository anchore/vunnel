from __future__ import annotations

import logging
import os
import json
from typing_extensions import Any, Generator, Iterator

from vunnel.workspace import Workspace
from vunnel.result import Store, Writer


class Overrides:
    def __init__(self, overrides_uri: str, provider_name: str, workspace: Workspace, logger: logging.Logger):
        self.overrides_uri = overrides_uri
        self.workspace = workspace
        self.provider_name = provider_name
        self.logger = logger

    # def apply_override(self, identifier: str, record: dict[str, Any]) -> None:
    #     # TODO: this is quite coupled to NVD; we should invert that control somehow
    #     cve_id = f"{identifier.split('/')[1]}.json"
    #     override_path = os.path.join(self.workspace.overrides_path, cve_id)
    #     if os.path.exists(override_path):
    #         self.logger.info("applying overrides for " + self.provider_name)
    #         with open(override_path, "r") as f:
    #             override = json.load(f)
    #             record["item"]["attitional_items"] = override["attitional_items"]

    def all_overrides_paths(self) -> Iterator[str]:
        for root, _, files in os.walk(self.workspace.overrides_path):
            for file in files:
                yield file

    def apply_all_overrides(self, writer: Writer):
        store = writer.get_store()
        for file in self.all_overrides_paths():
            name = os.path.basename(file).replace(".json", "")
            year = name.split("-")[1]
            identifier = f"{year}/{name}"
            with open(os.path.join(self.workspace.overrides_path, file), "r") as f:
                override = json.load(f)
                envelope = store.read(identifier)
                self.logger.info(f"applying overrides for {identifier}: {override} to {envelope}")
                envelope.item["additionalEntries"] = override["additional_entries"]
                store.store(identifier, envelope)
