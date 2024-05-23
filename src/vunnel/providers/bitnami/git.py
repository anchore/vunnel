from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from vunnel import utils

@dataclass
class GitRevision:
    sha: str
    file: str

class GitWrapper:
    _check_cmd_ = "git --version"
    _is_git_repo_cmd_ = "git rev-parse --is-inside-work-tree"
    _clone_cmd_ = "git clone -b {branch} {src} {dest}"
    _check_out_cmd_ = "git checkout {branch}"

    def __init__(
        self,
        source: str,
        branch: str,
        checkout_dest: str,
        workspace: str | None = None,
        logger: logging.Logger | None = None,
    ):
        self.src = source
        self.branch = branch
        self.dest = checkout_dest
        self.workspace = workspace if workspace else tempfile.gettempdir()
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        try:
            out = self._exec_cmd(self._check_cmd_)
            self.logger.trace(f"git executable verified using cmd: {self._check_cmd_}, output: {out.decode()}")
        except:
            self.logger.exception('could not find required "git" executable. Please install git on host')
            raise

    def _check(self, destination):
        try:
            if not os.path.exists(destination):
                self.logger.debug(f"git working tree not found at {destination}")
                return False

            cmd = self._is_git_repo_cmd_
            out = self._exec_cmd(cmd, cwd=destination)
            self.logger.debug(f"check for git repository, cmd: {cmd}, output: {out.decode()}")
        except Exception:
            self.logger.debug(f"git working tree not found at {destination}", exc_info=True)
            return False

        return True
    
    def delete_repo(self):
        if os.path.exists(self.dest):
            self.logger.debug("deleting existing repository")
            shutil.rmtree(self.dest, ignore_errors=True)


    @utils.retry_with_backoff()
    def clone_repo(self):
        try:
            self.logger.info(f"cloning git repository {self.src} branch {self.branch} to {self.dest}")
            cmd = self._clone_cmd_.format(src=self.src, dest=self.dest, branch=self.branch)
            out = self._exec_cmd(cmd)
            self.logger.debug(f"initialized git repo, cmd: {cmd}, output: {out.decode()}")
        except:
            self.logger.exception(f"failed to clone git repository {self.src} branch {self.branch} to {self.dest}")
            raise

    def _exec_cmd(self, cmd, *args, **kwargs) -> bytes:
        """
        Run a command with errors etc handled
        :param cmd: list of arguments (including command name, e.g. ['ls', '-l])
        :param args:
        :param kwargs:
        :return:
        """
        try:
            self.logger.trace(f"running: {cmd}")
            cmd_list = shlex.split(cmd)
            # S603 disable explanation: running git commands by design
            return subprocess.check_output(cmd_list, *args, **kwargs, stderr=subprocess.PIPE)  # noqa: S603
        except Exception as e:
            self.logger.exception(f"error executing command: {cmd}")
            raise e
