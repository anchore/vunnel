from __future__ import annotations

import logging

from vunnel.workspace import Workspace


class Overrides:
    def __init__(self, overrides_uri: str, provider_name: str, workspace: Workspace, logger: logging.Logger):
        self.overrides_uri = overrides_uri
        self.workspace = Workspace
        self.provider_name = provider_name
        self.logger = logger

    def apply_overrides(self) -> None:
        self.logger.info("applying overrides for " + self.provider_name)
