from __future__ import annotations

import logging
import os

import orjson
import requests
from vunnel import utils, workspace

from .git import GitWrapper

namespace = "bitnami"

class Parser:
    _git_src_url_ = "https://github.com/bitnami/vulndb.git"
    _git_src_branch_ = "main"

    def __init__(self, ws: workspace.Workspace, logger: logging.Logger | None = None):
        self.workspace = ws
        self.git_url = self._git_src_url_
        self.git_branch = self._git_src_branch_
        self.urls = [self.git_url]
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.git_wrapper = GitWrapper(source=self.git_url, branch=self.git_branch, checkout_dest=os.path.join(self.workspace.input_path, "vulndb"), logger=self.logger)
    
    def _load(self):
        self.logger.info(f"loading data from git repository")

        vuln_data_dir = os.path.join(self.workspace.input_path, "vulndb", "data")
        for root, dirs, files in os.walk(vuln_data_dir):
            dirs.sort()
            for file in sorted(files):
                full_path = os.path.join(root, file)
                with open(full_path, encoding="utf-8") as f:
                    yield orjson.loads(f.read())

    def _normalize(self, vuln_entry):
        self.logger.info(f"normalizing vulnerability data")
        
        vuln_id = vuln_entry["id"]
        if "aliases" in vuln_entry and len(vuln_entry["aliases"]) > 0:
            vuln_id = vuln_entry["aliases"][0]
        fixed_in = []
        if "affected" in vuln_entry:
            for affected in vuln_entry["affected"]:
                version = "None"
                if "ranges" in affected:
                    for r in affected["ranges"]:
                        if "events" in r:
                            for event in r["events"]:
                                # TODO: manage last_affected
                                # if events["last_affected"]:
                                #     version = events["last_affected"]
                                #     break
                                if "fixed" in event:
                                    version = event["fixed"]
                                    break
                        
                fixed_in.append({
                    "Name": affected["package"]["name"],
                    "VersionFormat": "semver",
                    "NamespaceName": namespace,
                    "Version": version,
                })
        link = "None"
        if "references" in vuln_entry and len(vuln_entry["references"]) > 0:
            link = vuln_entry["references"][0]
        
        return vuln_id, {
            "Vulnerability": {
                "Name": vuln_id,
                "NamespaceName": namespace,
                "Link": link,
                "Severity": vuln_entry["database_specific"]["severity"],
                "Description": vuln_entry["details"],
                "FixedIn": fixed_in,
            },
        }

    def get(self):
        # Initialize the git repository
        self.git_wrapper.delete_repo()
        self.git_wrapper.clone_repo()

        # Load the data from the git repository
        for vuln_entry in self._load():
            # Normalize the loaded data
            yield self._normalize(vuln_entry)
