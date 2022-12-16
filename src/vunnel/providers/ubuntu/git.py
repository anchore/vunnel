# pylint: skip-file

import copy
import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections import namedtuple

from vunnel import utils

GitCommitSummary = namedtuple("GitCommitSummary", ["sha", "updated", "deleted"])
GitRevision = namedtuple("GitRevision", ["sha", "status", "file"])

logger = logging.getLogger(__name__)


class GitWrapper(object):
    __active_retired_filename_regex__ = re.compile(r"(active|retired)/CVE-\S+")
    __cve_id_regex__ = re.compile(r"CVE-\S+")

    _check_cmd_ = ["git", "--version"]
    _is_git_repo_cmd_ = ["git", "rev-parse", "--is-inside-work-tree"]
    _clone_cmd_ = ["git", "clone", "-b", "master", "{src}", "{dest}"]
    _check_out_cmd_ = ["git", "checkout", "master"]
    _pull_cmd_ = ["git", "pull", "-f"]
    _fetch_cmd_ = ["git", "fetch", "--all"]
    _pull_ff_only_cmd_ = ["git", "pull", "--ff-only"]
    _reset_head_cmd_ = ["git", "reset", "--hard", "origin/master"]
    _change_set_cmd_ = [
        "git",
        "log",
        "--no-renames",
        "--no-merges",
        "--name-status",
        "--format=oneline",
        "{from_rev}..{to_rev}",
    ]
    _rev_history_cmd_ = [
        "git",
        "log",
        "--no-merges",
        "--follow",
        "--name-status",
        "--format=oneline",
        "{from_rev}..",
        "--",
        "{file}",
    ]
    _get_rev_content_cmd_ = ["git", "show", "{sha}:{file}"]
    _head_rev_cmd_ = ["git", "rev-parse", "HEAD"]

    def __init__(self, source, checkout_dest, workspace=None):
        self.src = source
        self.dest = checkout_dest
        self.workspace = workspace if workspace else tempfile.gettempdir()

    @classmethod
    def check(cls, destination):
        try:
            out = GitWrapper._exec_cmd(cls._check_cmd_)
            logger.debug("git executable verified using cmd: {}, output: {}".format(" ".join(cls._check_cmd_), out))
        except:
            logger.warn('Could not find required "git" executable. Please install git on host')
            return False

        try:
            cmd = copy.copy(cls._is_git_repo_cmd_)
            out = GitWrapper._exec_cmd(cmd, cwd=destination)
            logger.debug("Check for git repository, cmd: {}, output: {}".format(" ".join(cmd), out.decode()))
        except:
            logger.warn("git working tree not found at {}".format(destination))
            return False

        return True

    @utils.retry_with_backoff()
    def init_repo(self, force=False):
        if self.check(self.dest) and not force:
            logger.debug("Found git repository at {} Skipping init".format(self.dest))
        else:
            try:
                if os.path.exists(self.dest):
                    logger.debug("Found {}. Deleting it before cloning git repository")
                    shutil.rmtree(self.dest, ignore_errors=True)

                logger.info("Cloning git repository {} to {}".format(self.src, self.dest))

                cmd = copy.copy(self._clone_cmd_)
                cmd[4] = cmd[4].format(src=self.src)
                cmd[5] = cmd[5].format(dest=self.dest)

                out = GitWrapper._exec_cmd(cmd)
                logger.debug("Initialized git repo, cmd: {}, output: {}".format(" ".join(cmd), out.decode()))
            except:
                logger.exception("Failed to clone initialize git repository {} to {}".format(self.src, self.dest))
                raise

    @utils.retry_with_backoff()
    def sync_with_upstream(self):
        try:
            try:
                GitWrapper._exec_cmd(self._check_out_cmd_, cwd=self.dest)
            except:
                pass
            out = GitWrapper._exec_cmd(self._pull_ff_only_cmd_, cwd=self.dest)
            logger.debug("Synced with upstream git repo, output: {}".format(out.decode()))
        except:
            logger.exception("Failed to git pull")
            raise

    def get_merged_change_set(self, from_rev, to_rev=None):
        try:
            logger.debug("Fetching changes set between revisions {} - {}".format(from_rev, to_rev))

            cmd = copy.copy(self._change_set_cmd_)
            cmd[6] = cmd[6].format(from_rev=from_rev, to_rev=to_rev if to_rev else "")

            out = GitWrapper._exec_cmd(cmd, cwd=self.dest)

            commit_list = self._parse_log(out.decode())

            return self._compute_change_set(commit_list)
        except:
            logger.exception("Failed to compute logically modified and removed CVEs between commits")
            raise

    def get_revision_history(self, cve_id, file_path, from_rev=None):
        try:
            logger.debug("Fetching revision history for {}".format(file_path))

            cmd = copy.copy(self._rev_history_cmd_)
            cmd[8] = cmd[8].format(file=file_path)

            if from_rev:
                cmd[6] = cmd[6].format(from_rev=from_rev)
            else:
                del cmd[6]

            out = GitWrapper._exec_cmd(cmd, cwd=self.dest)

            return self._parse_revision_history(cve_id, out.decode())
        except:
            logger.exception("Failed to fetch the revision history for {}".format(file_path))
            raise

    def get_content(self, git_rev):
        if not isinstance(git_rev, GitRevision):
            raise ValueError("Input must be a GitRevision")

        try:
            logger.debug("Fetching content for {} from git commit {}".format(git_rev.file, git_rev.sha))

            cmd = copy.copy(self._get_rev_content_cmd_)
            cmd[2] = cmd[2].format(sha=git_rev.sha, file=git_rev.file)

            out = GitWrapper._exec_cmd(cmd, cwd=self.dest)

            return out.decode().splitlines()
        except:
            logger.exception("Failed to get content for {} from git commit {}".format(git_rev.file, git_rev.sha))

    def get_current_rev(self):
        try:
            rev = GitWrapper._exec_cmd(self._head_rev_cmd_, cwd=self.dest)
            return rev.decode().strip() if isinstance(rev, bytes) else rev
        except:
            logger.exception()

    @staticmethod
    def _parse_revision_history(cve_id, history):
        """
        eabaf525ae78eea3cd9f6063721afd1111efcd5c ran process_cves
        R100    active/CVE-2017-16011   ignored/CVE-2017-16011
        704e87cde2d217b0b806678f34d23e0c3a22a3d1 ran process_cves
        M       active/CVE-2017-16011
        e54645943d9a38c2065130b9a453bddbfbbf2b18 research jquery CVEs
        M       active/CVE-2017-16011

        :param cve_id:
        :param history:
        :return:
        """
        revs = []

        history_lines = [item.strip() for item in history.splitlines() if item.strip()]
        if not history_lines:
            return revs

        if len(history_lines) % 2 != 0:
            raise ValueError("Input must contain two lines per revision, input line count is {}".format(len(history_lines)))

        for x in range(0, len(history_lines), 2):
            # TODO check status is not D and file name matches CVE-*
            rev = GitWrapper._parse_revision(history_lines[x : x + 2])

            # don't include deleted revisions
            if rev.status.startswith("D"):
                continue

            # break the moment a different CVE ID is encountered
            if cve_id not in rev.file:
                break

            revs.append(rev)

        return revs

    @staticmethod
    def _parse_revision(rev_raw):
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
    def _compute_change_set(commit_list):
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

        modified = {}
        removed = {}

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

    @staticmethod
    def _parse_log(ordered_changes):
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

        commits_list = []
        commit_lines = []
        # split lines and remove any empty string in between or at the end
        ordered_changes_iterator = (item.strip() for item in ordered_changes.splitlines() if item.strip())

        for line in ordered_changes_iterator:
            components = line.split()
            if components and len(components) > 1:
                if len(components[0]) > 5:  # indicates this is a commit sha since length greater than any change status
                    if commit_lines:  # encountered next commit, process the stored one first
                        c = GitWrapper._parse_normalized_commit(commit_lines)
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
            c = GitWrapper._parse_normalized_commit(commit_lines)
            commits_list.append(c) if c else None
            del commit_lines[:]

        return commits_list

    @staticmethod
    def _parse_normalized_commit(commit_lines):
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
        updated = {}
        deleted = {}

        for components in commit_lines[1:]:
            if re.match(GitWrapper.__active_retired_filename_regex__, components[1]):
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
                else:
                    # either not a commit line or an irrelevant file, ignore it
                    logger.warn("Encountered unknown change symbol {}".format(components[0]))
            else:
                # not a match
                pass

        if updated or deleted:
            deleted = {key: value for key, value in deleted.items() if key not in updated}
            return GitCommitSummary(sha=commit_lines[0][0], updated=updated, deleted=deleted)
        else:
            return None

    @staticmethod
    def _exec_cmd(cmd, *args, **kwargs):
        """
        Run a command with errors etc handled
        :param cmd: list of arguments (including command name, e.g. ['ls', '-l])
        :param args:
        :param kwargs:
        :return:
        """
        try:
            logger.debug("Executing: {}".format(cmd))
            if "stdout" in kwargs:
                return subprocess.check_call(cmd, *args, **kwargs)
            else:
                return subprocess.check_output(cmd, *args, **kwargs)
        except Exception as e:
            logger.exception("Error executing command: {}".format(cmd))
            raise e
