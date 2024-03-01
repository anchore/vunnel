from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess  # nosec

from vunnel import utils


class GitServer503Error(Exception):
    # TODO: refactor to be more generic
    def __init__(self):
        super().__init__(
            "The git server is unavailable, try again later or switch to the git protocol endpoint",
        )


class Git:
    _check_cmd_ = "git --version"
    _is_git_repo_cmd_ = "git rev-parse --is-inside-work-tree"
    _set_remote_cmd_ = "git remote set-url origin {src}"
    _clone_cmd_ = "git clone -b {branch} {src} {dest}"
    _check_out_cmd_ = "git checkout {branch}"
    _clean_cmd_ = "git clean --force -d"
    _reset_cmd_ = "git reset --hard HEAD"
    _pull_ff_only_cmd_ = "git pull --ff-only"
    # TODO: refactor to be more generic
    _503_message = "The requested URL returned error: 503"

    def __init__(  # noqa: PLR0913
        self,
        source: str,
        destination: str,
        branch: str,
        logger: logging.Logger | None = None,
    ):
        self.src = source
        self.branch = branch
        self.destination = destination
        self._reset_cache()

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

        try:
            out = self._exec_cmd(self._check_cmd_)
            self.logger.trace(f"git executable verified using cmd: {self._check_cmd_}, output: {out.decode().rstrip()}")
        except:
            self.logger.exception('could not find required "git" executable. Please install git on host')
            raise

    @utils.retry_with_backoff()
    def clone_or_update_repo(self, fresh=False):
        if fresh:
            self._delete_repo()

        if self._check(self.destination):
            self.logger.debug(f"found git repository at {self.destination}")
            self._sync_with_upstream()
            return

        self._clone_repo()

    def _check(self, destination):
        try:
            if not os.path.exists(destination):
                self.logger.debug(f"git working tree not found at {destination}")
                return False

            cmd = self._is_git_repo_cmd_
            out = self._exec_cmd(cmd, cwd=destination)
            self.logger.debug(f"check for git repository, cmd: {cmd}, output: {out.decode().rstrip()}")
        except Exception:
            self.logger.debug(f"git working tree not found at {destination}", exc_info=True)
            return False

        return True

    def _delete_repo(self):
        if os.path.exists(self.destination):
            self.logger.debug("deleting existing repository")
            shutil.rmtree(self.destination, ignore_errors=True)
            self._reset_cache()

    def _clone_repo(self):
        try:
            self.logger.info(f"cloning git repository {self.src} branch {self.branch} to {self.destination}")
            cmd = self._clone_cmd_.format(src=self.src, dest=self.destination, branch=self.branch)
            out = self._exec_cmd(cmd)
            self.logger.debug(f"initialized git repo, cmd: {cmd}, output: {out.decode().rstrip()}")
            self._reset_cache()
        except:
            self.logger.exception(f"failed to clone git repository {self.src} branch {self.branch} to {self.destination}")
            raise

    @utils.retry_with_backoff()
    def _sync_with_upstream(self):
        self._reset_cache()
        try:
            try:
                self._exec_cmd(self._set_remote_cmd_.format(src=self.src), cwd=self.destination)

                # Cleanup any untracked files which might be present and reset any changes on the current branch
                try:
                    self._exec_cmd(self._clean_cmd_, cwd=self.destination)
                    self._exec_cmd(self._reset_cmd_, cwd=self.destination)
                except Exception:
                    self.logger.info("failed to clean and reset", exc_info=True)

                self._exec_cmd(self._check_out_cmd_.format(branch=self.branch), cwd=self.destination)
            except Exception:
                self.logger.info(f"failed to run git checkout of {self.branch}", exc_info=True)

            try:
                out = self._exec_cmd(self._pull_ff_only_cmd_, cwd=self.destination)
                self.logger.debug(f"synced with upstream git repo, output: {out.decode().rstrip()}")
            except GitServer503Error:
                raise
            except Exception:
                # if something other than 503 occurred at this point just remove the repo and re-clone
                self.logger.exception("unexpected exception syncing with upstream; will delete and re-clone")
                self._delete_repo()
                self._clone_repo()

        except:
            self.logger.exception("failed to git pull")
            raise

    def _reset_cache(self):
        pass

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
            # S603 disable exaplanation: running git commands by design
            return subprocess.check_output(cmd_list, *args, **kwargs, stderr=subprocess.PIPE)  # noqa: S603
        except Exception as e:
            self.logger.exception(f"error executing command: {cmd}")

            if isinstance(e, subprocess.CalledProcessError) and e.stderr and self._503_message in e.stderr.decode():
                raise GitServer503Error from e

            raise e
