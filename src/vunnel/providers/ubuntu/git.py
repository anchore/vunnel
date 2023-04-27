# flake8: noqa
from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess  # nosec
import tempfile
from dataclasses import dataclass

from vunnel import utils


@dataclass
class GitCommitSummary:
    sha: str
    updated: dict[str, str]
    deleted: dict[str, str]


@dataclass
class GitRevision:
    sha: str
    file: str


class GitWrapper:
    __active_retired_filename_regex__ = re.compile(r"(active|retired)/CVE-\S+")
    __cve_id_regex__ = re.compile(r"CVE-\S+")
    _check_cmd_ = "git --version"
    _is_git_repo_cmd_ = "git rev-parse --is-inside-work-tree"
    _set_remote_cmd_ = "git remote set-url origin {src}"
    _clone_cmd_ = "git clone -b {branch} {src} {dest}"
    _check_out_cmd_ = "git checkout {branch}"
    _pull_cmd_ = "git pull -f"
    _fetch_cmd_ = "git fetch --all"
    _reset_cmd_ = "git reset --hard HEAD"
    _pull_ff_only_cmd_ = "git pull --ff-only"
    _write_graph_ = "git commit-graph write --reachable --changed-paths"
    _change_set_cmd_ = "git log --no-renames --no-merges --name-status --format=oneline {from_rev}..{to_rev}"
    _get_rev_content_cmd_ = "git show {sha}:{file}"
    _head_rev_cmd_ = "git rev-parse HEAD"

    def __init__(
        self, source: str, branch: str, checkout_dest: str, workspace: str | None = None, logger: logging.Logger | None = None
    ):
        self.src = source
        self.branch = branch
        self.dest = checkout_dest
        self.workspace = workspace if workspace else tempfile.gettempdir()

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.cve_rev_history: dict[str, list[GitRevision]] = {}

        try:
            out = self._exec_cmd(self._check_cmd_)
            self.logger.trace("git executable verified using cmd: {}, output: {}".format(self._check_cmd_, out.decode()))
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
            self.logger.debug("check for git repository, cmd: {}, output: {}".format(cmd, out.decode()))
        except:
            self.logger.debug(f"git working tree not found at {destination}")
            return False

        return True

    @utils.retry_with_backoff()
    def init_repo(self, force=False):
        if force:
            if os.path.exists(self.dest):
                self.logger.debug("deleting existing repository")
                shutil.rmtree(self.dest, ignore_errors=True)

        if self._check(self.dest):
            self.logger.debug("found git repository at {}".format(self.dest))
            self.sync_with_upstream()
            return

        try:
            self.logger.info(f"cloning git repository {self.src} branch {self.branch} to {self.dest}")

            cmd = self._clone_cmd_.format(src=self.src, dest=self.dest, branch=self.branch)
            out = self._exec_cmd(cmd)

            self.logger.debug("initialized git repo, cmd: {}, output: {}".format(cmd, out.decode()))
            self._write_graph()
        except:
            self.logger.exception(f"failed to clone git repository {self.src} branch {self.branch} to {self.dest}")
            raise

    def parse_full_cve_revision_history(self, git_log_output: str) -> dict[str, list[GitRevision]]:
        hist = {}
        entries = self._parse_log(git_log_output)

        for entry in entries:
            for cve, file in entry.updated.items():
                if cve not in hist:
                    hist[cve] = []

                hist[cve].append(GitRevision(entry.sha, file))

        return hist

    def prepare_cve_revision_history(self):
        self.logger.info("building full revision history for all CVEs.  This may take quite some time.")
        self.cve_rev_history = {}
        out = self._exec_cmd("git log --name-status --no-merges --format=oneline -- retired/ active/", cwd=self.dest)
        self.cve_rev_history = self.parse_full_cve_revision_history(out.decode())

    @utils.retry_with_backoff()
    def sync_with_upstream(self):
        try:
            try:
                self._exec_cmd(self._set_remote_cmd_.format(src=self.src), cwd=self.dest)
                self._exec_cmd(self._check_out_cmd_.format(branch=self.branch), cwd=self.dest)
                self._exec_cmd(self._reset_cmd_, cwd=self.dest)
            except:  # nosec
                pass
            out = self._exec_cmd(self._pull_ff_only_cmd_, cwd=self.dest)
            self.logger.debug("synced with upstream git repo, output: {}".format(out.decode()))
            self._write_graph()
        except:
            self.logger.exception("failed to git pull")
            raise

    def _write_graph(self):
        """
        writes out a binary representation of the commit graph as a git object, enabling
        huge performance gains when traversing the graph (e.g. git log)
        """
        try:
            self.logger.debug("writing commit graph")
            self._exec_cmd(self._write_graph_, cwd=self.dest)
        except:
            self.logger.exception("failed to write commit graph")
            raise

    def get_merged_change_set(self, from_rev: str, to_rev: str | None = None) -> tuple[dict[str, str], dict[str, str]]:
        try:
            self.logger.trace("fetching changes set between revisions {} - {}".format(from_rev, to_rev))
            cmd = self._change_set_cmd_.format(from_rev=from_rev, to_rev=to_rev if to_rev else "")
            out = self._exec_cmd(cmd, cwd=self.dest)
            commit_list = self._parse_log(out.decode())
            return self._compute_change_set(commit_list)
        except:
            self.logger.exception("failed to compute logically modified and removed CVEs between commits")
            raise

    def get_revision_history(self, cve_id: str, file_path: str, from_rev: str | None = None) -> list[GitRevision]:
        try:
            self.logger.trace("fetching revision history for {}".format(file_path))
            return self.cve_rev_history.get(cve_id, [])
        except:
            self.logger.exception("failed to fetch the revision history for {}".format(file_path))
            raise

    def get_content(self, git_rev: GitRevision) -> list[str]:
        if not isinstance(git_rev, GitRevision):
            raise ValueError("Input must be a GitRevision")

        try:
            cmd = self._get_rev_content_cmd_.format(sha=git_rev.sha, file=git_rev.file)
            out = self._exec_cmd(cmd, cwd=self.dest)
            return out.decode().splitlines()
        except:
            self.logger.exception("failed to get content for {} from git commit {}".format(git_rev.file, git_rev.sha))

    def get_current_rev(self) -> str:
        try:
            rev = self._exec_cmd(self._head_rev_cmd_, cwd=self.dest)
            return rev.decode().strip() if isinstance(rev, bytes) else rev
        except:
            self.logger.exception("unable to get current git revision")

    @staticmethod
    def _parse_revision(rev_raw: list[str]) -> GitRevision:
        """
        List containing two items
        [
            'eabaf525ae78eea3cd9f6063721afd1111efcd5c ran process_cves',
            'R100    active/CVE-2017-16011   ignored/CVE-2017-16011'
        ]
        :param rev_raw:
        :return:
        """
        commit_line_components = rev_raw[0].split()
        change_line_components = rev_raw[1].split()

        return GitRevision(
            sha=commit_line_components[0],
            status=change_line_components[0],
            file=change_line_components[2] if len(change_line_components) >= 3 else change_line_components[1],
        )

    @staticmethod
    def _compute_change_set(commit_list: list[GitCommitSummary]) -> tuple[dict[str, str], dict[str, str]]:
        """
        List of GitCommitSummary tuples in the log order (last commit first)
        [
            GitCommitSummary(sha='9d7608a304733e936771d53d66c17ea1ed81ca2a', updated={'CVE-2018-1108': 'active/CVE-2018-1108'}, deleted={})
            GitCommitSummary(sha='34cc8435c53610f4a0ca5ff355151eb5a6af0df9', updated={'CVE-2018-12714': 'active/CVE-2018-12714'}, deleted={})
        ]


        :param commit_list:
        :return:
        """
        # reverse the commit list and process commits in the order they were inserted
        commit_list.reverse()

        modified: dict[str, str] = {}
        removed: dict[str, str] = {}

        for commit in commit_list:
            # Overlay each commit on top of computed results

            # start logically deleted items in the commit and filter it out from from the overall modified result
            modified = {key: value for key, value in modified.items() if key not in commit.deleted}

            # merge updated items in the commit with the overall modified result
            modified.update(commit.updated)

            # merge deleted items in the commit with the overall removed result
            removed.update(commit.deleted)

        # filter out anything from the overall removed result to handle anything was logically removed and re-added
        removed = {key: value for key, value in removed.items() if key not in modified}

        return modified, removed

    def _parse_log(self, ordered_changes: str) -> list[GitCommitSummary]:
        """
        Input in the form

        f9cc163f61a86209ca955017c56c1eedd285bcee html-export: convert from BZR_COMMIT to GIT_COMMIT
        M       Makefile.include
        M       ignored/Makefile
        M       scripts/generate-pkgs-makefile.py
        M       scripts/html-report
        6571b3166f2a79799d3bff89b9eb319b720812ac generate-graph.py: fix chdir breakage when in $UCT
        M       scripts/generate-graphs.py
        66fdf2b24c2151e0d36a7e9a1aea9714ed7ad13e generate-graphs.py: parse git log as part of UCT git conversion
        M       scripts/generate-graphs.py
        53eeed7959e55da1854d3f9627b9652d93ef371f reports; convert from bzr to git
        M       scripts/monthly-report
        M       scripts/yearly-report
        2dfafda744cf2d7da70d1d0598c2fe1ede1955fd git conversion: move .bzrignore to .gitignore
        D       .bzrignore
        A       .gitignore

        :param ordered_changes:
        :return:
        """

        commits_list: list[GitCommitSummary] = []
        commit_lines: list[list[str]] = []
        # split lines and remove any empty string in between or at the end
        ordered_changes_iterator = (item.strip() for item in ordered_changes.splitlines() if item.strip())

        for line in ordered_changes_iterator:
            components = line.split()
            if components and len(components) > 1:
                if len(components[0]) > 5:  # indicates this is a commit sha since length greater than any change status
                    if commit_lines:  # encountered next commit, process the stored one first
                        c = self._parse_normalized_commit(commit_lines)
                        commits_list.append(c) if c else None
                        del commit_lines[:]
                    # else:  # encountered the first commit line, keep going
                    #     pass

                    commit_lines.append(components)
                else:
                    commit_lines.append(components)
            else:
                pass

        # process the last commit if any
        if commit_lines:
            c = self._parse_normalized_commit(commit_lines)
            commits_list.append(c) if c else None
            del commit_lines[:]

        return commits_list

    def _parse_normalized_commit(self, commit_lines: list[list[str]]) -> GitCommitSummary | None:
        """
        A list of lists where each inner list represents a line in the commit log
        [
            ['f1743ee4e985c0c3cf6dd8ccaa0fdfd801415f0d', 'Process', 'cves', 'run:', 'triaged', '8', 'CVEs,', '40', 'Ignored,', '4', 'Packages'],
            ['A', 'active/CVE-2018-1000201'],
            ['A', 'active/CVE-2018-12641'],
            ['A', 'active/CVE-2018-12689'],
            ['A', 'active/CVE-2018-12697'],
            ['A', 'active/CVE-2018-12698'],
            ['A', 'active/CVE-2018-12699'],
            ['A', 'active/CVE-2018-12700'],
            ['A', 'active/CVE-2018-12713'],
            ['M', 'check-cves.log'],
            ['M', 'ignored/not-for-us.txt']
        ]

        :param commit_lines:
        :return:
        """
        updated: dict[str, str] = {}
        deleted: dict[str, str] = {}

        for components in commit_lines[1:]:
            if re.match(self.__active_retired_filename_regex__, components[1]):
                cve_id = components[1].split("/", 1)[1]
                if components[0] == "A" or components[0] == "M":
                    # CVE added to or modified in active or retired directory
                    # A       retired/CVE-2018-7332
                    # M       retired/CVE-2018-7480
                    updated[cve_id] = components[1]
                elif components[0] == "D":
                    # CVE deleted from active or retired directory
                    # D       active/CVE-2009-1553
                    deleted[cve_id] = components[1]
                elif components[0].startswith("R"):
                    if components[0] != "R100" and len(components) > 2:
                        updated[cve_id] = components[2]
                else:
                    # either not a commit line or an irrelevant file, ignore it
                    self.logger.debug("skipping unknown change symbol {}".format(components[0]))
            else:
                # not a match
                pass

        if updated or deleted:
            deleted = {key: value for key, value in deleted.items() if key not in updated}
            return GitCommitSummary(sha=commit_lines[0][0], updated=updated, deleted=deleted)
        else:
            return None

    def _exec_cmd(self, cmd, *args, **kwargs) -> bytes:
        """
        Run a command with errors etc handled
        :param cmd: list of arguments (including command name, e.g. ['ls', '-l])
        :param args:
        :param kwargs:
        :return:
        """
        try:
            self.logger.trace("running: {}".format(cmd))
            cmd_list = shlex.split(cmd)
            return subprocess.check_output(cmd_list, *args, **kwargs)  # nosec
        except Exception as e:
            self.logger.exception("error executing command: {}".format(cmd))
            raise e
