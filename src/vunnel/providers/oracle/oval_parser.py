from __future__ import annotations

import bz2
import copy
import gzip
import logging
import os
import re
from collections import defaultdict
from typing import TYPE_CHECKING

import defusedxml.ElementTree as ET

from vunnel.utils import date
from vunnel.utils.vulnerability import vulnerability_element

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("oval-parser")


class Config:
    """
    Capture regular expressions, xpath queries and other driver specific configuration
    in an instance of this class

    """

    # regexes
    tag_pattern: re.Pattern | None = None
    ns_pattern: re.Pattern | None = None
    is_installed_pattern: re.Pattern | None = None
    pkg_version_pattern: re.Pattern | None = None
    pkg_module_pattern: re.Pattern | None = None
    signed_with_pattern: re.Pattern | None = None
    platform_version_pattern: re.Pattern | None = None
    # arch_pattern is optional: when set, a criterion comment matching it (e.g. "Oracle Linux
    # arch is x86_64") tags the package-version tests gated by that branch with the architecture,
    # so a single advisory that ships different fixes per arch is not flattened together.
    arch_pattern: re.Pattern | None = None

    # xpath queries
    title_xpath_query: str | None = None
    severity_xpath_query: str | None = None
    platform_xpath_query: str | None = None
    date_issued_xpath_query: str | None = None
    date_updated_xpath_query: str | None = None
    description_xpath_query: str | None = None
    sa_ref_xpath_query: str | None = None
    cve_xpath_query: str | None = None
    criteria_xpath_query: str | None = None
    criterion_xpath_query: str | None = None

    # maps
    severity_dict: dict[str, str] | None = None

    # string formats
    ns_format: str | None = None


def get_opener(filename: str) -> Callable:
    if filename.endswith(".gz"):
        return gzip.open
    if filename.endswith(".bz2"):
        return bz2.open
    return open


def parse(dest_file: str, config: Config, vuln_dict: dict | None = None):
    """
    Parse the oval file and return a dictionary with tuple (ID, namespace) as the key
    and tuple (version, vulnerability-dictionary) as the value
    :param dest_file: path object to oval file to be parsed
    :param config: configuration for parsing oval file
    :return:
    """
    if not isinstance(config, Config):
        logger.warning("Invalid config found, expected an instance of Config class")
        raise TypeError("Invalid config")

    logger.debug("Parsing {}".format(dest_file))  # noqa: UP032, G001

    if not vuln_dict:
        vuln_dict = {}

    if os.path.exists(dest_file):
        processing = False
        opener = get_opener(dest_file)

        with opener(dest_file, "rb") as f:  # noqa: F841
            for event, element in ET.iterparse(dest_file, events=("start", "end")):
                # gather definition
                if event == "start" and re.search(config.tag_pattern, element.tag).group(1) == "definition":
                    processing = True
                elif event == "end" and re.search(config.tag_pattern, element.tag).group(1) == "definition":
                    try:
                        _process_definition(element, vuln_dict, config)
                    except Exception:
                        logger.exception("Error parsing oval record. Logging error and continuing")
                    finally:
                        processing = False

                if not processing and event == "end":
                    # print('Clearing element: {} post event: {}'.format(re.search(tag_pattern, element.tag).group(1), event))
                    element.clear()

                # bail after definitions
                if event == "end" and re.search(config.tag_pattern, element.tag).group(1) == "definitions":
                    # print('Stopped parsing')
                    break
    else:
        logger.warning(f"{dest_file} not found, returning empty results")

    return vuln_dict


def _parse_description(def_element, oval_ns, config: Config) -> str:
    try:
        description = def_element.find(config.description_xpath_query.format(oval_ns)).text.strip()
    except (AttributeError, ET.ParseError):
        description = ""
    return description


def _parse_severity(def_element, oval_ns, vuln_id: str, config: Config) -> str:
    try:
        severity = config.severity_dict.get(def_element.find(config.severity_xpath_query.format(oval_ns)).text.lower())
    except (AttributeError, ET.ParseError):
        logger.debug(f"Unable to parse severity for {vuln_id}, defaulting to Unknown")
        severity = "Unknown"
    return severity


def _process_definition(def_element, vuln_dict, config: Config):  # noqa: PLR0912
    oval_ns = re.search(config.ns_pattern, def_element.tag).group(1)

    def_version = def_element.attrib["version"]
    title = def_element.find(config.title_xpath_query.format(oval_ns)).text
    name = title[: title.index(": ")].strip()
    description = _parse_description(def_element, oval_ns, config)
    severity = _parse_severity(def_element, oval_ns, name, config)
    issued = def_element.find(config.date_issued_xpath_query.format(oval_ns)).attrib["date"]
    # check for xpath query first since oracle does not provide this and its not initialized in the config
    if config.date_updated_xpath_query:  # noqa: SIM108
        updated = def_element.find(config.date_updated_xpath_query.format(oval_ns)).attrib["date"]
    else:
        updated = None
    rhsa_ref = def_element.find(config.sa_ref_xpath_query.format(oval_ns))
    ref_id = rhsa_ref.attrib["ref_id"]
    link = rhsa_ref.attrib["ref_url"]

    cves = []
    for cve in def_element.iterfind(config.cve_xpath_query.format(oval_ns)):
        if "cvss2" in cve.attrib:
            cves.append(
                {
                    "Name": cve.text,
                    "Link": cve.attrib["href"],
                    "cvss2": cve.attrib["cvss2"],
                },
            )
        else:
            cves.append({"Name": cve.text, "Link": cve.attrib["href"]})

    ns_pkgs_dict = _process_criteria(def_element, oval_ns, config)

    for platform_element in def_element.iterfind(config.platform_xpath_query.format(oval_ns)):
        v = copy.deepcopy(vulnerability_element)
        ns_name = config.ns_format.format(re.search(config.platform_version_pattern, platform_element.text).group(1))

        v["Vulnerability"]["NamespaceName"] = ns_name
        v["Vulnerability"]["Severity"] = severity or ""
        v["Vulnerability"]["Metadata"] = {"Issued": issued, "Updated": updated, "RefId": ref_id} if updated else {"Issued": issued, "RefId": ref_id}
        v["Vulnerability"]["Name"] = name
        v["Vulnerability"]["Link"] = link
        v["Vulnerability"]["Description"] = description

        if cves:
            v["Vulnerability"]["Metadata"]["CVE"] = cves

        if ns_pkgs_dict and ns_name in ns_pkgs_dict:
            v["Vulnerability"]["FixedIn"] = _build_fixed_in(ns_pkgs_dict[ns_name], ns_name, issued)
        else:
            logger.warning(f"No affected packages found for {name}, this is unusual")

        # handle duplicates using version version attribute of definition element
        if (name, ns_name) in vuln_dict:
            existing_version, _ = vuln_dict[(name, ns_name)]
            logger.debug(
                "Found an existing record for {} under {}. Version attribute of definition oval element: existing: {}, new: {}".format(  # noqa: UP032, G001
                    name,
                    ns_name,
                    existing_version,
                    def_version,
                ),
            )
            # lexicographic comparison of versions to choose which vulnerability record wins
            if def_version > existing_version:
                # Replacing existing record with new one'
                vuln_dict[(name, ns_name)] = (def_version, v)
            else:
                # Existing record stays
                pass
        else:
            vuln_dict[(name, ns_name)] = (def_version, v)


def _process_criteria(element_a, oval_ns, config: Config):
    """
    Parse and return a dict mapping namespace -> set of (package, version, module, arch) tuples.

    The outermost criteria of a definition is either a single platform group (operator AND) or an
    OR of per-platform groups (a definition that covers multiple OS releases). Each group is walked
    recursively so a package-version test inherits the module and architecture of the branch that
    gates it (see _collect_affected). arch is None unless config.arch_pattern is set and the branch
    carried an arch criterion.
    """
    criteria_element = element_a.find(config.criteria_xpath_query.format(oval_ns))
    ns_pkgs_dict: dict = {}
    if criteria_element is None:
        return ns_pkgs_dict

    groups = list(criteria_element.findall(f"{oval_ns}criteria")) if criteria_element.attrib["operator"].lower() == "or" else [criteria_element]

    for group in groups:
        ns_name, affected = _collect_affected(group, oval_ns, config)
        if ns_name and affected:
            ns_pkgs_dict.setdefault(ns_name, set()).update(affected)

    return ns_pkgs_dict


def _collect_affected(criteria_element, oval_ns, config: Config, arch=None, module=None):
    """
    Recursively walk a criteria subtree and return (ns_name, [(package, version, module, arch), ...]).

    module and arch are inherited from the nearest enclosing criterion that sets them, so a
    "PKG is earlier than V" test picks up the module and architecture of the branch gating it. This
    keeps a per-arch fix (e.g. an advisory whose x86_64 and aarch64 builds were respun at different
    revisions) attributed to the right architecture instead of being flattened together.
    """
    ns_name = None
    local_arch = arch
    local_module = module
    versions = []

    for criterion in criteria_element.findall(f"{oval_ns}criterion"):
        comment = criterion.attrib["comment"]
        m = re.search(config.pkg_version_pattern, comment)
        if m:
            versions.append((m.group(1), m.group(2)))
            continue
        m = re.search(config.is_installed_pattern, comment)
        if m:
            ns_name = config.ns_format.format(m.group(1))
            continue
        if config.pkg_module_pattern:
            m = re.search(config.pkg_module_pattern, comment)
            if m:
                local_module = m.group(1)
                continue
        if config.arch_pattern:
            m = re.search(config.arch_pattern, comment)
            if m:
                local_arch = m.group(1)
                continue

    affected = [(pkg, version, local_module, local_arch) for pkg, version in versions]

    for child in criteria_element.findall(f"{oval_ns}criteria"):
        child_ns, child_affected = _collect_affected(child, oval_ns, config, local_arch, local_module)
        if child_ns:
            ns_name = child_ns
        affected.extend(child_affected)

    return ns_name, affected


def _build_fixed_in(pkg_tuples, ns_name, issued):
    """
    Build the FixedIn list from (package, version, module, arch) tuples, emitting an architecture
    only when it actually differentiates a fix.

    For a given (package, module) we look at which architectures each fixed version covers:

    - If every version covers the same set of architectures, architecture is not a differentiator,
      so we emit one arch-less FixedIn per distinct version (matching the historical shape and saving
      database space). This covers the common "one version on all arches" gate as well as "two module
      rebuilds, each present on every arch" - where splitting by arch would only create redundant
      duplicate rows.
    - If different versions cover different architecture sets (e.g. an advisory whose x86_64 and
      aarch64 builds were respun at different revisions), architecture does differentiate, so we emit
      one FixedIn per (version, arch) with Arch set, so a fix for one arch never over-matches another.
    """
    grouped: dict = defaultdict(set)  # (name, module) -> {(version, arch), ...}
    for pkg, version, module, arch in pkg_tuples:
        grouped[(pkg, module)].add((version, arch))

    fixed_in_list = []
    for (pkg, module), version_arches in grouped.items():
        arches_by_version: dict = defaultdict(set)
        for version, arch in version_arches:
            arches_by_version[version].add(arch)

        # architecture only matters when different versions cover different arch sets
        arch_discriminates = len({frozenset(arches) for arches in arches_by_version.values()}) > 1
        entries = sorted(version_arches) if arch_discriminates else [(version, None) for version in sorted(arches_by_version)]

        for version, arch in entries:
            fixed_el = {
                "Name": pkg,
                "Version": version,
                "Module": module,
                "VersionFormat": "rpm",  # hard code version format for now
                "NamespaceName": ns_name,
            }
            if arch:
                fixed_el["Arch"] = arch
            # add Available object if fix version exists and issued date is available
            if version != "None" and issued:
                fixed_el["Available"] = {"Date": date.normalize_date(issued), "Kind": "advisory"}
            fixed_in_list.append(fixed_el)

    # stable ordering for reproducible output
    fixed_in_list.sort(key=lambda f: (f["Name"], f.get("Arch") or "", f["Version"]))
    return fixed_in_list
