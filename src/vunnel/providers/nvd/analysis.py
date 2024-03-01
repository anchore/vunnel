from __future__ import annotations

import logging
import os

from vunnel.providers.nvd.git import Git


class Analysis:
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

    # todo: add helper functions


class Repo(Git):
    # TODO: finalize the git url... right now it's using ssh for auth reasons, switch to https before prod
    # _git_url_ = "https://github.com/anchore/nvd-analysis.git"
    _git_url_ = "git@github.com:anchore/nvd-analysis.git"
    _repo_name_ = "nvd-analysis"
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
        # TODO: will this be needed

    @classmethod
    def urls(cls) -> list[str]:
        return [cls._git_url_]

    # TODO: make helper functions to extract data from the repo in a more useful (not generic) way
