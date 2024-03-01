from __future__ import annotations

import collections
import logging
import os
from typing import Any

import orjson

from vunnel.providers.nvd.git import Git


class CVEList:
    def __init__(self, destination: str, logger: logging.Logger | None = None, timeout: int = 30):
        self.timeout = timeout

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.git = Repo(
            destination=destination,
            logger=self.logger,
        )

    def urls(self) -> list[str]:
        return self.git.urls()

    def download(self) -> None:
        self.git.clone_or_update_repo()

    def cves(self) -> set[str]:
        return {f.lower().removesuffix(".json") for f in self.git.cve_files}

    def get(self, cve: str) -> dict[str, Any] | None:
        path = self.git.cve_file(cve=cve)

        if not path:
            self.logger.warning(f"no cvelist record for cve_id={cve!r}")
            return None

        self.logger.trace(f"found cvelist record for {cve!r} at {path!r}")

        with open(path) as fp:
            return orjson.loads(fp.read())


class Repo(Git):
    _git_url_ = "https://github.com/CVEProject/cvelistV5.git"
    _repo_name_ = "cvelistV5"
    _branch_ = "main"

    _ls_files_ = "git ls-files"

    def __init__(self, destination: str, logger: logging.Logger | None = None):
        super().__init__(
            source=self._git_url_,
            destination=os.path.join(destination, self._repo_name_),
            branch=self._branch_,
            logger=logger,
        )

    def _reset_cache(self):
        super()._reset_cache()
        self._ls_cache = None

    @classmethod
    def urls(cls) -> list[str]:
        return [cls._git_url_]

    def cve_file(self, cve: str) -> str | None:
        result_set = self.cve_files.get(cve.upper() + ".json", None)
        if result_set:
            return next(iter(result_set))
        return None

    @property
    def cve_files(self) -> dict[str, set[str]]:
        if not self._ls_cache:
            out = self._exec_cmd(self._ls_files_, cwd=self.destination)
            all_files = [os.path.join(self.destination, line) for line in out.decode().splitlines()]

            cache = collections.defaultdict(set)
            for f in all_files:
                basename = os.path.basename(f)
                if basename.startswith("CVE") and basename.endswith(".json"):
                    cache[basename].add(f)

            self._ls_cache = cache

        return self._ls_cache
