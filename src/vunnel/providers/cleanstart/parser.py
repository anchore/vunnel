from __future__ import annotations

import json
import logging
import os
import subprocess

from vunnel import workspace

ADVISORIES_REPO = "https://github.com/cleanstart-dev/cleanstart-security-advisories.git"
ADVISORIES_DIR = "advisories"


class Parser:
    def __init__(self, ws: workspace.Workspace, logger: logging.Logger | None = None):
        self.workspace = ws
        self.urls = [ADVISORIES_REPO]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self):
        yield from self._fetch_and_parse()

    def _fetch_and_parse(self):
        clone_dir = os.path.join(self.workspace.input_path, "cleanstart-security-advisories")

        if os.path.exists(clone_dir):
            self.logger.info("updating existing advisory repo")
            subprocess.run(["git", "-C", clone_dir, "pull"], check=True, capture_output=True)
        else:
            self.logger.info(f"cloning advisory repo from {ADVISORIES_REPO}")
            subprocess.run(["git", "clone", "--depth=1", ADVISORIES_REPO, clone_dir], check=True, capture_output=True)

        advisories_path = os.path.join(clone_dir, ADVISORIES_DIR)

        # walk all subdirectories (e.g. 2025/, 2026/)
        json_files = []
        for root, dirs, files in os.walk(advisories_path):
            for filename in files:
                if filename.endswith(".json"):
                    json_files.append(os.path.join(root, filename))

        self.logger.info(f"found {len(json_files)} advisories")

        for filepath in json_files:
            try:
                with open(filepath, encoding="utf-8") as f:
                    record = json.load(f)
                vuln_id = record["id"]
                yield vuln_id, record
            except Exception as e:
                self.logger.warning(f"skipping {filepath}: {e}")