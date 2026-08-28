"""Git wrapper for cloning RapidFort security-advisories repo."""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from vunnel import utils


class GitWrapper:
    _check_cmd_ = "git --version"
    _clone_cmd_ = "git clone --depth=1 -b {branch} {src} {dest}"

    def __init__(
        self,
        source: str,
        branch: str,
        checkout_dest: str,
        logger: logging.Logger | None = None,
    ):
        self.src = source
        self.branch = branch
        self.dest = checkout_dest
        self.workspace = tempfile.gettempdir()

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        try:
            out = self._exec_cmd(self._check_cmd_)
            self.logger.trace("git executable verified using cmd: %s, output: %s", self._check_cmd_, out)  # type: ignore[attr-defined]
        except Exception:
            self.logger.exception('could not find required "git" executable. Please install git on host')
            raise

    def delete_repo(self) -> None:
        if os.path.exists(self.dest):
            self.logger.debug("deleting existing repository")
            shutil.rmtree(self.dest, ignore_errors=True)

    @utils.retry_with_backoff()
    def clone_repo(self) -> None:
        try:
            self.logger.info("cloning git repository %s branch %s to %s", self.src, self.branch, self.dest)
            cmd = self._clone_cmd_.format(src=self.src, dest=self.dest, branch=self.branch)
            out = self._exec_cmd(cmd)
            self.logger.debug("initialized git repo, cmd: %s, output: %s", cmd, out)
        except Exception:
            self.logger.exception("failed to clone git repository %s branch %s to %s", self.src, self.branch, self.dest)
            raise

    def _exec_cmd(self, cmd: str) -> str:
        try:
            self.logger.trace("running: %s", cmd)  # type: ignore[attr-defined]
            cmd_list = shlex.split(cmd)
            return subprocess.check_output(cmd_list, text=True, stderr=subprocess.PIPE)  # noqa: S603
        except Exception:
            self.logger.exception("error executing command: %s", cmd)
            raise
