# flake8: noqa

import concurrent.futures
import copy
import enum
import json
import logging
import os
import re
import time
from collections import namedtuple
from typing import Optional

from .git import GitWrapper

namespace = "ubuntu"
feedtype = "vulnerabilities"
purge_unreported = True

ubuntu_pkg_version_format = "dpkg"
ubuntu_cve_url = "http://people.ubuntu.com/~ubuntu-security/cve/{}"
DistroPkgTuple = namedtuple("DistroPkgTuple", ["distro", "pkg"])

_patches_header_regex = re.compile(r"Patches_(\S+)\s*")
_patches_regex = re.compile(r"\s*(.+)_(.+)\s*:\s+(.+)\s*")
_patch_state_regex = re.compile(r"\s*(\S+)(\s+.+)?\s*")
_indent_line_regex = re.compile(r"\s+\S+\s*")
_package_priority_regex = re.compile(r"\s*Priority_(\S+)\s*:\s+(\S+)\s*")
_cve_filename_regex = re.compile("CVE-[0-9]+-[0-9]+")

# Per the Ubuntu README in the security tracker BZR repo:
# Maps the state name to whether it indicates a package is vulnerable
patch_states = {
    "DNE": False,  # Does Not Exist, no fix
    "needs-triage": False,  # Not yet determined if CVE affects package, ignore in anchore until determination made
    "ignored": False,  # CVE does not affect the package or no updates (e.g. end-of-life) (NOTE: should still report?)
    "not-affected": False,  # The package is related to the issue, but not affected by it.
    "needed": True,  # Package is vuln and needs a fix. No version yet.
    "released": True,  # The package is affected and a fix has been released with the given version.
    "pending": True,
    # Indicates a vuln with release coming in the expected version. We ignore here for now assuming it will be in 'released' status shortly.
    "active": True,  # The package is affected, needs fixing and is being worked on.
    "deferred": True
    # The package is affected by work on fix is deferred for some reason. In this case, ignore any version info as it may be random (e.g. a date)
}

patch_merge_criteria = {
    "status": re.compile(r"ignored"),
    "version": re.compile(r"(^|.*\s+)end[\s-]of[\s-]life($|\s+.*)")
    # match 'end-of-life' or 'end of life' anywhere in the line
}

# Only releases present in this mapping will be output by the driver, so it must be maintained with new releases.
ubuntu_version_names = {
    "precise": "12.04",
    # 'precise/esm': '12.04',
    "quantal": "12.10",
    "raring": "13.04",
    "trusty": "14.04",
    "utopic": "14.10",
    "vivid": "15.04",
    "wily": "15.10",
    "xenial": "16.04",
    "yakkety": "16.10",
    "zesty": "17.04",
    "artful": "17.10",
    "bionic": "18.04",
    "cosmic": "18.10",
    "disco": "19.04",
    "eoan": "19.10",
    "focal": "20.04",
    "groovy": "20.10",
    "hirsute": "21.04",
    "impish": "21.10",
    "jammy": "22.04",
    "kinetic": "22.10",
}

# driver workspace
driver_workspace = None


class JsonifierMixin:
    def json(self):
        jsonified = {}
        for k, v in vars(self).items():
            if not k[0] == "_":
                if type(v) == list or type(v) == set:
                    jsonified[k] = [x.json() if hasattr(x, "json") and callable(x.json) else x for x in v]
                elif type(v) == dict:
                    jsonified[k] = {x: y.json() if hasattr(y, "json") and callable(y.json) else y for x, y in v.items()}
                else:
                    if hasattr(v, "json"):
                        jsonified[k] = v.json()
                    else:
                        jsonified[k] = v
        return jsonified


# Driver V2 Design Changes:
# Because the ubuntu data is removed when a release hits EOL (patch records changed from a state to 'ignored (reached end-of-life)'), the way to keep the actual
# state for all cves is to track the last update prior to EOL, which requires traversing revision history. The v2 driver does this to maintain an accurate state
# for each cve. It will be very slow on initial run but can be optimized by pre-populating the cache of merged state


class Vulnerability(JsonifierMixin):
    """
    Class representing the record to be returned. Uses strange capitalization
    to be backwards compatible in the json output with previous version of feed data.
    """

    def __init__(self):
        self.Name = None
        self.NamespaceName = None
        self.Description = ""
        self.Severity = None
        self.Metadata = None
        self.Link = None
        self.FixedIn = []


class FixedIn(JsonifierMixin):
    """
    Class representing a fix record for return back to the service from the driver. The semantics of the version are:
    "None" -> Package is vulnerable and no fix available yet
    ! "None" -> Version of package with a fix for a vulnerability. Assume all older versions of the package are vulnerable.

    """

    def __init__(self):
        self.Name = None
        self.NamespaceName = None
        self.VersionFormat = None
        self.Version = None


class Severity(enum.IntEnum):
    Unknown = 1
    Negligible = 2
    Low = 3
    Medium = 4
    High = 5
    Critical = 6

    def json(self):
        return self.name


def check_header(expected, lines):
    """
    Check that the first element of the lines list matches expected + ':'. And pop it off if found. Else raise exception.
    :param expected: The str value of the header prefix expected to be found on the first line
    :param lines: the list of lines, which will be modified on success by removing the first entry if it matches
    :return: None
    """

    # This is not a full match, only prefix to handle cases where the header isn't quite within spec (e.g. notes added etc).
    if not lines[0].strip().startswith(expected + ":"):
        raise ValueError("Expected header {}, found {}".format(expected, lines[0]))
    else:
        lines.pop(0)


def parse_list(header, lines):
    """
    Greedy parser that consumes lines if lines[0] is the header until the first empty line.

    :param header:
    :param lines:
    :return:
    """

    check_header(header, lines)

    refs = []
    while lines:
        if _indent_line_regex.match(lines[0]):
            refs.append(lines.pop(0).strip())
        else:
            break

    return refs


def parse_patch(header, lines):
    """
    Parse a patch spec of the form:
    Patches_<packagename>:
    [<Priority_<packagename>: <priority>] (these are optional)
    [debdiff: URL]
    [vendor: URL]
    [upstream: URL]
    [patch: URL]
    <distro1>_<packagename>: <status> <status details>
    <distro2>_<packagename>: <status> <status details>
    ...
    <distroN>_<packagename>: <status> <status details>
    <newline>

    :param header:
    :param lines:
    :return:
    """
    if lines[0].startswith("Patches"):
        check_header(header, lines)

    patches = []
    priority = None
    while lines:
        line = lines[0].strip()
        if not line:
            break

            # Check if this is a "Priority_<pkg>: <priority>" line
        pkg_priority = _package_priority_regex.match(line)
        if pkg_priority:
            pkg = pkg_priority.group(1)
            priority = pkg_priority.group(2)
            for patch in filter(lambda x: x["package"] == pkg, patches):
                patch["priority"] = priority
            lines.pop(0)
            continue
        else:
            match = _patches_regex.match(line)
            if match:
                version = None
                state = match.group(3)
                status_match = _patch_state_regex.match(match.group(3))
                if status_match and status_match.group(1):
                    state = status_match.group(1)
                    if state in patch_states:  # and patch_states[state]:
                        version = status_match.group(2)
                        if version:
                            version = version.strip()
                            if version[0] == "(" and version[-1] == ")":
                                version = version[1:-1]

                        p = {
                            "distro": match.group(1),
                            "package": match.group(2),
                            "status": state,
                            "version": version,
                        }
                        if priority:
                            p["priority"] = priority
                        patches.append(p)
                lines.pop(0)
            else:
                break

    return patches


def parse_simple_keyvalue(expected_key, lines):
    """
    Parse a <Header>: <value> line and any skip ahead any empty lines following

    :param header: expected key
    :param lines: lines of input
    :return: tuple (value, line count consumed)
    """

    tokens = lines[0].split(":", 1)
    if len(tokens) != 2:
        raise ValueError("Could not parse {} as key: value".format(lines[0]))

    key = tokens[0]
    value = tokens[1].strip()

    if key != expected_key:
        raise ValueError("Did not find expected key {}. Found {}".format(expected_key, key))

    lines.pop(0)

    return value


def parse_multiline_keyvalue(header, lines):
    """
    Parse a header plus multiple lines (to an empty line) into a single string, stripping newlines

    :param header:
    :param lines:
    :return:
    """
    check_header(header, lines)

    content = []
    while lines and _indent_line_regex.match(lines[0]):
        content.append(lines.pop(0).strip())

    return " ".join(content)


def get_patch_section(header_line):
    match = _patches_header_regex.match(header_line)
    if match:
        return match.group(1)
    else:
        return None


# Specify sections we care about and the parser for each section
sections_parsers = {
    "Candidate": parse_simple_keyvalue,
    "References": parse_list,
    "Description": parse_multiline_keyvalue,
    #    'Ubuntu-Description': parse_multiline_keyvalue,
    "Priority": parse_simple_keyvalue,
}

# These fields may be found in a Patch_<pkg> section but are not required
optional_patch_fields = {
    "debdiff": parse_simple_keyvalue,
    "patch": parse_simple_keyvalue,
    "vendor": parse_simple_keyvalue,
    "upstream": parse_simple_keyvalue,
}


def check_release(releasename):
    """
    Returns true if the releasename is one we care about.

    :param releasename: str name of the release
    :return: bool, True if release name is known, False if not
    """
    return releasename in ubuntu_version_names


def check_state(state):
    """
    Returns true if the state is one we should process.
    :param state:l
    :return: bool, True if state is valid, False if not
    """
    return state and patch_states.get(state)


def check_patch(patch_record):
    """
    Filtering test for a patch record to determine if this patch record indicates:
    * The release is affected
    * The release is one we are tracking

    :param patch_record: dict for a patch
    :return: True if record should be used, False if not
    """

    if not patch_record:
        return False

    # Distro filter step
    return check_release(patch_record.get("distro")) and check_state(patch_record.get("status"))


def check_merge(patch_record):
    """
    Test a patch record to see if it meets the merge criteria

    :param patch_record:
    :return:
    """

    if not patch_record:
        return False

    # perform regex match only if the value is non-null and non-empty
    return all(
        patch_record.get(key, None) and re.match(regex, patch_record.get(key)) for key, regex in patch_merge_criteria.items()
    )


def parse_cve_file(content_lines):
    """
    Parses a single CVE file into a dict representation suitable for further processing.

    :param lines:
    :return: dict version of the cve record
    """

    parsed = {"patches": []}
    len(content_lines)

    # Copy to avoid modifying the passed param directly since the parsing is greedy.
    lines = copy.deepcopy(content_lines)
    while lines:
        line = lines[0].strip()
        if not line or line.startswith("#"):
            # Skip empties and comments
            lines.pop(0)
        else:
            section = line.split(":", 1)[0]
            if section in sections_parsers:
                content = sections_parsers[section](section, lines)
                parsed[section] = content
                continue
            else:
                patch_name = get_patch_section(section)
                p_match = _patches_regex.match(line)
                if patch_name:
                    patches = parse_patch(section, lines)
                    parsed["patches"] += patches
                    continue
                elif p_match and map_namespace(p_match.group(1)):
                    patches = parse_patch(section, lines)
                    parsed["patches"] += patches
                    continue
                else:
                    # Consume the line. No match to parse.
                    lines.pop(0)

    return parsed


def map_namespace(release_name):
    """
    Returns a namespace name (ubuntu:<version>) where version is a numeric id instead of release name
    e.g. map_namespace('vivid') -> ubuntu:15.04
    :param release_name:
    :return:
    """

    dist = ubuntu_version_names.get(release_name)
    if dist:
        return ":".join([namespace, dist])

    return None


def map_parsed(parsed_cve, logger=None):
    """
    Maps a parsed CVE dict into a Vulnerability object.

    Each parsed CVE dict contains data for multiple distro releases and packages.
    The returned output is a set of Vulnerability objects.

    The overall approach is to emit a CVE record for each namespace that has an entry for a patch, even if that entry is a Does Not Effect.
    The output can be Vulnerability objects with no FixedIn records.

    :param parsed_cve:
    :return: set of Vulnerability objects
    """

    if not logger:
        logger = logging.getLogger(__name__)

    # Map keyed by namespace name
    vulns = {}
    if not (parsed_cve.get("Candidate") or parsed_cve.get("Name")):
        logger.error("could not find a Candidate or Name for parsed cve: {}".format(parsed_cve))
        return []

    for p in parsed_cve.get("patches"):
        namespace_name = map_namespace(p.get("distro"))

        # Build the CVE record even if no fixedIn record
        r = vulns.get(namespace_name)
        if not r:
            if not namespace_name:
                continue

            r = Vulnerability()
            try:
                r.Severity = getattr(Severity, parsed_cve.get("Priority", "").capitalize())
            except:
                r.Severity = Severity.Unknown

            r.Name = parsed_cve.get("Candidate", parsed_cve.get("Name"))
            r.Metadata = {}
            r.Link = ubuntu_cve_url.format(r.Name)
            r.FixedIn = []
            r.NamespaceName = namespace_name
            vulns[namespace_name] = r

        # If the patch status is one we care about, make the FixedIn record, else skip it but create CVE records
        if check_state(p.get("status")):
            pkg = FixedIn()
            pkg.Name = p["package"]

            # If there is a version indicating a fix use it, else 'None' is special keyword for no-fix-available
            if p.get("status") == "released":
                # Can do version format check here, but requires code from anchore-engine
                # anchore_engine.services.policy_engine.engine.util.deb.DpkgVersion.from_string(p.get('status'))
                pkg.Version = p.get("version")
                if pkg.Version is None:
                    logger.warn(
                        'found CVE {} in ubuntu version {} with "released" status for pkg {} but no version for release. Released patches should have version info, but missing in source data. Marking package as not vulnerable'.format(
                            r.Name, r.NamespaceName, pkg.Name
                        )
                    )
                    continue
                    # Strange condition where a release was done but no version found. In this case, we'll omit the FixedIn record.

            else:
                pkg.Version = "None"

            pkg.VersionFormat = "dpkg"
            pkg.NamespaceName = namespace_name
            r.FixedIn.append(pkg)

            # Check for max priority of all packages with it set
            if p.get("priority"):
                pkg_sev = getattr(Severity, p.get("priority", "").capitalize())
                if pkg_sev > r.Severity:
                    r.Severity = pkg_sev

    s = set(vulns.values())
    return s


def filter_resolved_patches(cve_dict, dpt_list):
    """
    Filter patch records from the cve dictionary that match the package and distribution of the items in the list but don't satisfy merge criteria

    :param cve_dict: dict version of a cve record, like the return value of parse_cve_file()
    :param dpt_list: list of DistroPkgTuple objects
    :return:
    """
    filtered_map = dict()
    for dpt in dpt_list:
        matched_p = next(
            (
                p
                for p in cve_dict.get("patches")
                if dpt.distro == p.get("distro") and dpt.pkg == p.get("package") and not check_merge(p)
            ),
            None,
        )
        if matched_p:
            filtered_map[dpt] = matched_p

    return filtered_map


def filter_merged_patches(cve_dict, dpt_list):
    """
    Filter patch records from the cve dictionary that match the package and distribution of the items in the list

    :param cve_dict: dict version of a cve record, like the return value of parse_cve_file()
    :param dpt_list: list of DistroPkgTuple objects
    :return:
    """
    filtered_map = dict()
    for dpt in dpt_list:
        matched_p = next(
            (p for p in cve_dict.get("patches") if dpt.distro == p.get("distro") and dpt.pkg == p.get("package")),
            None,
        )
        if matched_p:
            filtered_map[dpt] = matched_p

    return filtered_map


class UbuntuCVEState:
    """
    CVE state is a on-disk representation of the entire state and history of the cves from the bzr repo in a canonical form.
    Specifically: a json document of the data and a revision history tracking which revisions from the bzr repo have been processed.

    """

    _data_file = "anchore_ubuntu_cve_state"

    def __init__(self, base_path):
        self.base_path = base_path
        self.data_path = os.path.join(base_path, self._data_file)
        self.last_revision = None
        self.cve_state = None

    def load_cve_state(self):
        if not os.path.exists(self.data_path):
            self.cve_state = {}
            self.last_revision = 0
        else:
            with open(self.data_path) as f:
                json.load(f)

    def merge(self, cve_entry):
        """
        Merge a parsed CVE entry into the state model
        :param cve_entry: A dictionary of namespace -> Vulnerability mappings with each CVE containing FixedIn objects as appropriate
        :return: None
        """

        for namespace, vuln in cve_entry.items():
            # Do conditional merge here. If existing record has FixedIn data, don't remove anything that was non-ignored and is now ignored.
            self.cve_state[namespace][vuln.Name] = vuln


class Parser:
    __payload__ = Vulnerability

    _bzr_src = "https://launchpad.net/ubuntu-cve-tracker"
    _git_https = "https://git.launchpad.net/ubuntu-cve-tracker"
    _git_src = "git://git.launchpad.net/ubuntu-cve-tracker"
    _bzr_to_git_transition_commit = "dc3f64a0dfe6b1780240ff115d8a0a1b23fd00b4"

    _active_cve_dir = "active"
    _retired_cve_dir = "retired"
    _ignored_cve_dir = "ignored"  # May need to use this later if CVEs transition from one to another
    _vc_working_dir = "ubuntu-cve-tracker"
    _normalized_cve_dir = "normalized-cve-data"
    _last_processed_rev_file = "bzr-last-processed-rev"
    _last_processed_rev_key = "bzr_last_processed_rev"
    _last_processed_rev_file_git = "git-last-processed-rev"
    _last_processed_rev_key_git = "git_last_processed_rev"

    data_filename_regex = re.compile(r"(active|retired|ignored)/CVE-[0-9]{4}-[0-9]+")

    # Revision 9000 on the sec bzr repo before trusty eol. revno 9000 on 2015-01-27.

    def __init__(
        self,
        workspace,
        logger: Optional[logging.Logger] = None,
        additional_versions: Optional[dict[str, str]] = None,
        enable_rev_history: bool = True,
        max_workers: int = 5,
    ):
        self.vc_workspace = os.path.join(workspace.input_path, self._vc_working_dir)
        # TODO: tech debt: this should use the results workspace with the correct schema-aware envelope
        self.norm_workspace = os.path.join(workspace.input_path, self._normalized_cve_dir)
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.urls = [self._git_https]

        self.git_wrapper = GitWrapper(source=self._git_src, checkout_dest=self.vc_workspace, logger=logger)

        if additional_versions:
            ubuntu_version_names.update(additional_versions)
        self.enable_rev_history = enable_rev_history
        self._max_workers = max_workers

    def fetch(self, skip_if_exists=False):
        # setup merged workspace
        if not os.path.exists(self.norm_workspace):
            os.makedirs(self.norm_workspace)

        # sync git repo
        self.git_wrapper.init_repo()

        # get the last processed revision if available and the current latest revision
        last_rev = self._load_last_processed_rev()
        current_rev = self.git_wrapper.get_current_rev()

        # process all the updates between last processed and current revisions
        self._process_data(self.vc_workspace, from_rev=last_rev, to_rev=current_rev)
        # save last processed revision to disk
        self._save_last_processed_rev(current_rev)

        # load merged state and map it to vulnerabilities
        self.logger.debug("loading processed CVE content and transforming into to vulnerabilities")

        for merged_cve in self._merged_cve_iterator():
            yield from map_parsed(merged_cve, self.logger)

    def _process_data(self, vc_dir, to_rev, from_rev=None):
        self.logger.debug(
            "processing data from git repository: {}, from revision: {}, to revision: {}".format(vc_dir, from_rev, to_rev)
        )

        # gather a list of changed files if the last repo revision processed is available
        updated_paths = []
        deleted_ids = []
        if from_rev and to_rev and from_rev != to_rev:
            self.logger.debug("fetching changes to CVEs between revisions {} and {}".format(from_rev, to_rev))
            modified, removed = self.git_wrapper.get_merged_change_set(from_rev=from_rev, to_rev=to_rev)
            updated_paths = list(modified.values()) if modified else []
            deleted_ids = list(removed.keys()) if removed else []
            self.logger.debug("detected {} CVE updates (add/modify/rename)".format(len(updated_paths)))
            self.logger.debug("detected {} CVE deletions".format(len(deleted_ids)))

        # Load cves from active and retired directories and spool merged state to disk
        # note: this is an IO bound operation, so a thread pool will suffice for now
        # but look to a process pool if this becomes a bottleneck
        proc_exception = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:

            def worker(fn, cve_id, *args, **kwargs):
                try:
                    return fn(cve_id, *args, **kwargs)
                except:
                    self.logger.exception("error processing {}".format(cve_id))
                    raise

            futures = []

            for d in [self._active_cve_dir, self._retired_cve_dir]:
                cve_dir = os.path.join(vc_dir, d)
                for cve_id in sorted(filter(lambda x: _cve_filename_regex.match(x), os.listdir(cve_dir))):
                    f = os.path.join(cve_dir, cve_id)
                    cve_rel_path = "/".join([d, cve_id])

                    future = executor.submit(worker, self._process_cve, cve_id, cve_rel_path, f, to_rev, updated_paths)
                    futures.append(future)

            # wait for all the futures to complete
            done, not_done = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)

            if len(done) > 0 and len(done) != len(futures):
                future = done.pop()
                proc_exception = future.exception()
                if proc_exception:
                    self.logger.error(f"one task failed with: {proc_exception} (shutting down)")

                    # cancel any scheduled tasks
                    for future in futures:
                        future.cancel()

        if proc_exception:
            raise proc_exception

        # Remove merged state of deleted cves
        for cve_id in deleted_ids:
            self.logger.debug("{} is no longer relevant, deleting merged CVE state if any".format(cve_id))
            self._delete_merged_cve(cve_id)

    def _process_cve(self, cve_id, cve_rel_path, f, to_rev, updated_paths):
        if cve_rel_path in updated_paths:
            # merge cves updated since last revision or all if the last processed revision is not available
            # self.logger.debug("CVE updated since last run, processing {}".format(cve_rel_path))

            return self._merge_cve(cve_id, cve_rel_path, f, to_rev)

        if not self._merged_cve_exists(cve_id):
            # merge may be required since the saved state is not found
            # self.logger.debug("CVE merged state not found, processing {}".format(cve_rel_path))

            return self._merge_cve(cve_id, cve_rel_path, f, to_rev)

        # merge may be required if new distros were added
        # self.logger.debug("reprocessing merged CVE {}".format(cve_rel_path))

        return self._reprocess_merged_cve(cve_id, cve_rel_path)

    def _load_last_processed_rev(self):
        last_processed_rev_path = os.path.join(self.norm_workspace, self._last_processed_rev_file_git)

        if os.path.exists(last_processed_rev_path):
            with open(last_processed_rev_path) as fp:
                return fp.readline().strip()
        else:
            last_processed_rev_path = os.path.join(self.norm_workspace, self._last_processed_rev_file)
            if os.path.exists(last_processed_rev_path):
                return self._bzr_to_git_transition_commit
            else:
                return None

    def _save_last_processed_rev(self, revno):
        last_processed_rev_path = os.path.join(self.norm_workspace, self._last_processed_rev_file_git)

        with open(last_processed_rev_path, "w") as f:
            f.write("{}".format(revno))

    def _load_merged_cve(self, cve_id):
        if os.path.exists(os.path.join(self.norm_workspace, cve_id)):
            with open(os.path.join(self.norm_workspace, cve_id)) as fp:
                cve = json.load(fp)
                return cve

        return None

    def _save_merged_cve(self, cve_id, merged_cve):
        with open(os.path.join(self.norm_workspace, cve_id), "w") as fp:
            json.dump(merged_cve, fp)

    def _delete_merged_cve(self, cve_id):
        if os.path.exists(os.path.join(self.norm_workspace, cve_id)):
            os.remove(os.path.join(self.norm_workspace, cve_id))

    def _merged_cve_iterator(self):
        for cve_id in filter(lambda x: _cve_filename_regex.match(x), os.listdir(self.norm_workspace)):
            with open(os.path.join(self.norm_workspace, cve_id)) as fp:
                cve = json.load(fp)
                yield cve

    def _merged_cve_exists(self, cve_id):
        return os.path.exists(os.path.join(self.norm_workspace, cve_id))

    def _reprocess_merged_cve(self, cve_id, cve_rel_path):
        """
        Assumes that a normalized state exists for cve and processes only ignored patches, mainly for handling new distros

        :param cve_id:
        :param cve_rel_path:
        :return:
        """
        self.logger.debug("reprocessing merged CVE {}".format(cve_rel_path))

        saved_state = self._load_merged_cve(cve_id)

        if not saved_state:
            self.logger.warning("no saved state fround for {}".format(cve_id))
            return

        # reprocess only ignored patches
        merged_patches, ignored_patches, to_be_merged_map = self._categorize_patches(saved_state.get("ignored_patches"))

        # Found patches that can be merged and or can't be resolved from the saved state, could be a new namespace
        if merged_patches or to_be_merged_map:
            self.logger.debug("found unresolved patches in previously merged state, could be a new distro")
            # Process revision history for eol-ed packages that need to be merged
            if to_be_merged_map:
                if self.enable_rev_history:
                    self.logger.debug("attempting to resolve patches using revision history for {}".format(cve_rel_path))
                    (resolved_patches, pending_dpt_list, cve_latest_rev,) = self._resolve_patches_using_history(
                        cve_id=cve_id,
                        cve_rel_path=cve_rel_path,
                        to_be_merged_dpt_list=list(to_be_merged_map.keys()),
                        priority=saved_state.get("Priority", "Unknown"),
                    )
                    merged_patches.extend(resolved_patches)
                    if pending_dpt_list:
                        self.logger.debug(
                            "exhausted all revisions for {} but could not resolve patches: {}".format(
                                cve_rel_path,
                                [to_be_merged_map[x] for x in pending_dpt_list],
                            )
                        )
                        merged_patches.extend([to_be_merged_map[x] for x in pending_dpt_list])

                    del resolved_patches[:]
                    del pending_dpt_list[:]

                    if cve_latest_rev:
                        saved_state[self._last_processed_rev_key_git] = cve_latest_rev
                else:
                    self.logger.debug("revision history processing is disabled. Merging unresolved patches as they are")
                    merged_patches.extend(to_be_merged_map.values())

            # pulling this outside of the revision history block for fixing ENTERPRISE-195. saved state should be updated if there are mergeable or to-be-merged packages
            # there might already be resolved patches, extend it with merged patches, don't overwrite it
            if saved_state["patches"]:
                saved_state["patches"].extend(merged_patches)
            else:
                saved_state["patches"] = merged_patches

            # overwrite ignored patches since its the final list
            saved_state["ignored_patches"] = ignored_patches

            # save the merged cve state to disk before returning
            self._save_merged_cve(cve_id, saved_state)

        else:  # No patches that require resolution
            pass

        return saved_state

    @staticmethod
    def _categorize_patches(patch_list):
        """
        Takes in a list of patches and splits them into merged and ignored lists and a dictionary of patches that need further resolution
        :param patch_list:
        :return:
        """

        to_be_merged_map = {}
        merged_patches = []
        ignored_patches = []

        for p in patch_list:
            namespace_name = map_namespace(p.get("distro"))

            if not namespace_name:
                ignored_patches.append(p)
            elif namespace_name and check_merge(p):
                to_be_merged_map[DistroPkgTuple(distro=p.get("distro"), pkg=p["package"])] = p
            else:
                # Patch does not meet criteria for resolution - either its not eol-ed or in a namespace we care about
                merged_patches.append(p)

        return merged_patches, ignored_patches, to_be_merged_map

    def _merge_cve(self, cve_id, cve_rel_path, cve_abs_path, repo_current_rev):
        """
        Parses the contents of an ubuntu security tracker CVE file and returns the normalized data as a dictionary.
        If the CVE has any patches/fixes that meet the merge criteria, the revision history of the CVE is traversed
        in the most recent to least recent order to compute the last known state of the patch.

        :param cve_abs_path:
        :param repo_current_rev:
        :return:
        """
        self.logger.debug("merging CVE {}".format(cve_rel_path))

        with open(cve_abs_path) as cve_file:
            raw_content = cve_file.readlines()
            parsed_cve = parse_cve_file(raw_content)
            parsed_cve["Name"] = cve_id

        cve_latest_rev = None
        # merged_cve_path = os.path.join(self.norm_workspace, vuln_name)

        merged_patches, ignored_patches, to_be_merged_map = self._categorize_patches(parsed_cve.get("patches"))

        # Found patches that can't be resolved from the input data, could be the first time the driver is running
        if to_be_merged_map:
            # lookup saved state
            saved_cve = self._load_merged_cve(cve_id)

            if self.enable_rev_history:
                (resolved_patches, pending_dpt_list, cve_latest_rev,) = self._resolve_patches_using_history(
                    cve_id=cve_id,
                    cve_rel_path=cve_rel_path,
                    to_be_merged_dpt_list=list(to_be_merged_map.keys()),
                    priority=parsed_cve.get("Priority", "Unknown"),
                    saved_state=saved_cve,
                )
                merged_patches.extend(resolved_patches)
                if pending_dpt_list:
                    self.logger.debug(
                        "exhausted all revisions for {} but could not resolve patches: {}".format(
                            cve_rel_path,
                            [to_be_merged_map[x] for x in pending_dpt_list],
                        )
                    )
                    merged_patches.extend([to_be_merged_map[x] for x in pending_dpt_list])

                del resolved_patches[:]
                del pending_dpt_list[:]

            else:  # merge with saved state if any
                if saved_cve:
                    self.logger.debug("revision history processing is disabled. Resolving patches using saved cve state")
                    rev_matched_map = filter_merged_patches(saved_cve, list(to_be_merged_map.keys()))
                    # merge resolved and unresolved patches
                    merged_patches.extend(list(rev_matched_map.values()))
                    merged_patches.extend([to_be_merged_map[x] for x in to_be_merged_map if x not in rev_matched_map])

                    rev_matched_map.clear()
                else:
                    self.logger.debug(
                        "revision history processing is disabled and no saved state found. Skipping patch resolution"
                    )
                    merged_patches.extend(list(to_be_merged_map.values()))

        else:  # No patches that require resolution
            pass

        parsed_cve["patches"] = merged_patches
        parsed_cve["ignored_patches"] = ignored_patches
        parsed_cve[self._last_processed_rev_key_git] = cve_latest_rev if cve_latest_rev else repo_current_rev

        # save the merged cve state to disk before returning
        self._save_merged_cve(cve_id, parsed_cve)

        return parsed_cve

    def _resolve_patches_using_history(
        self,
        cve_id,
        cve_rel_path,
        to_be_merged_dpt_list,
        priority=None,
        saved_state=None,
    ):
        t = time.time()
        self.logger.debug("processing CVE revision history for: {}".format(cve_rel_path))

        # setup metrics
        metrics = {
            "revs_processed": 0,
            "previous_state_counter": {},
            "time_elapsed": 0,
            "severity": priority,
        }

        # initialize
        resolved_patches = []

        # copy the keys so the original ds is not modified
        pending_dpt_list = copy.deepcopy(to_be_merged_dpt_list)

        # last processed commit
        if saved_state and self._last_processed_rev_key_git in saved_state:
            saved_cve_last_processed_rev = saved_state[self._last_processed_rev_key_git]
        elif saved_state and self._last_processed_rev_key in saved_state:
            saved_cve_last_processed_rev = self._bzr_to_git_transition_commit
        else:
            saved_cve_last_processed_rev = None

        # fetch log of revision history for this file, its in the most recent - least recent order
        since_revs = self.git_wrapper.get_revision_history(cve_id, cve_rel_path, saved_cve_last_processed_rev)

        # make note of the first revision, its the latest revision and one we already processed
        cve_latest_rev = since_revs[0].sha if since_revs and since_revs[0] else None

        # first process all revisions before last processed revision
        if since_revs and len(since_revs) > 1:
            # process only previous revisions, not current
            for rev in since_revs[1:]:
                # getting revision content is expensive, so check things to merge first
                if not pending_dpt_list:
                    break  # No more merging required, stop processing revs!

                # process revision: fetch content, parse, filter patches that need to be merged and so on
                rev_raw_content = self.git_wrapper.get_content(rev)

                # parse the cve and filter based on merge criteria
                rev_cve = parse_cve_file(rev_raw_content)
                rev_matched_map = filter_resolved_patches(rev_cve, pending_dpt_list)
                resolved_patches.extend(list(rev_matched_map.values()))
                pending_dpt_list = [x for x in pending_dpt_list if x not in rev_matched_map]

                # metrics for processed revision
                metrics["revs_processed"] += 1
                for rev_p in rev_matched_map.values():
                    rev_p_ns = map_namespace(rev_p.get("distro"))
                    if rev_p.get("status", "Unknown") not in metrics["previous_state_counter"]:
                        metrics["previous_state_counter"][rev_p.get("status", "Unknown")] = {rev_p_ns: 0}
                    if rev_p.get("distro", "Unknown") not in metrics["previous_state_counter"][rev_p.get("status", "Unknown")]:
                        metrics["previous_state_counter"][rev_p.get("status", "Unknown")][rev_p_ns] = 0

                    metrics["previous_state_counter"][rev_p.get("status", "Unknown")][rev_p_ns] += 1

                # free up after processing
                rev_matched_map.clear()
                rev_cve.clear()
                del rev_raw_content[:]
        else:
            # no revs for processing
            self.logger.debug("no previous revisions found")

        # then merge with saved state if there are things that still need to be merged. This is a one time thing to short circuit fetching revs
        if pending_dpt_list and saved_state:
            self.logger.debug("resolving patches using saved cve state before processing any more revisions")
            rev_matched_map = filter_merged_patches(saved_state, pending_dpt_list)
            resolved_patches.extend(list(rev_matched_map.values()))
            pending_dpt_list = [x for x in pending_dpt_list if x not in rev_matched_map]

            # free up after processing
            rev_matched_map.clear()

            # Last, merging with saved state may or may not resolve patch state.
            # If a new namespace is introduced, its possible the saved cve is not fully resolved.
            # So continue with process revision: fetch content, parse, filter patches that need to be merged and so on
            if pending_dpt_list:
                # fetch the entire revision history for this file, needed for computing the merge
                self.logger.debug("unresolved patches found even after merge with saved state, walking entire revision history")
                all_revs = self.git_wrapper.get_revision_history(cve_id, cve_rel_path, None)
                before_revs = all_revs[len(since_revs) :] if since_revs else all_revs

                for rev in before_revs:
                    # getting revision content is expensive, so check things to merge first
                    if not pending_dpt_list:
                        break  # No more merging required, stop processing revs!

                    # process revision: fetch content, parse, filter patches that need to be merged and so on
                    rev_raw_content = self.git_wrapper.get_content(rev)

                    # parse the cve and filter based on merge criteria
                    rev_cve = parse_cve_file(rev_raw_content)
                    rev_matched_map = filter_resolved_patches(rev_cve, pending_dpt_list)
                    resolved_patches.extend(list(rev_matched_map.values()))
                    pending_dpt_list = [x for x in pending_dpt_list if x not in rev_matched_map]

                    # metrics for processed revision
                    metrics["revs_processed"] += 1
                    for rev_p in rev_matched_map.values():
                        rev_p_ns = map_namespace(rev_p.get("distro"))
                        if rev_p.get("status", "Unknown") not in metrics["previous_state_counter"]:
                            metrics["previous_state_counter"][rev_p.get("status", "Unknown")] = {rev_p_ns: 0}
                        if (
                            rev_p.get("distro", "Unknown")
                            not in metrics["previous_state_counter"][rev_p.get("status", "Unknown")]
                        ):
                            metrics["previous_state_counter"][rev_p.get("status", "Unknown")][rev_p_ns] = 0

                        metrics["previous_state_counter"][rev_p.get("status", "Unknown")][rev_p_ns] += 1

                    # free up after processing
                    rev_matched_map.clear()
                    rev_cve.clear()
                    del rev_raw_content[:]
            else:
                self.logger.debug("Merge with saved state resolved all relevant patches")

        metrics["time_elapsed"] = int((time.time() - t) * 1000) / float(1000)
        self.logger.trace("metrics from processing revision history for {}: {}".format(cve_rel_path, metrics))

        return resolved_patches, pending_dpt_list, cve_latest_rev

    def get(self, skip_if_exists=False):
        for i in self.fetch(skip_if_exists=skip_if_exists):
            yield i.NamespaceName, i.Name, i.json()
