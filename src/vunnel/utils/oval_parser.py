from __future__ import annotations

import copy
import gzip
import logging
import os
import re

import defusedxml.ElementTree as ET

from vunnel.utils.vulnerability import vulnerability_element

logger = logging.getLogger("oval-parser")


class Config:
    """
    Capture regular expressions, xpath queries and other driver specific configuration
    in an instance of this class

    """

    # regexes
    tag_pattern = None
    ns_pattern = None
    is_installed_pattern = None
    pkg_version_pattern = None
    pkg_module_pattern = None
    signed_with_pattern = None
    platform_version_pattern = None

    # xpath queries
    title_xpath_query = None
    severity_xpath_query = None
    platform_xpath_query = None
    date_issued_xpath_query = None
    date_updated_xpath_query = None
    description_xpath_query = None
    sa_ref_xpath_query = None
    cve_xpath_query = None
    criteria_xpath_query = None
    criterion_xpath_query = None

    # maps
    severity_dict = None

    # string formats
    ns_format = None


def parse(dest_file: str, config: Config, vuln_dict: dict | None = None):  # noqa: C901
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
        opener = open

        if dest_file.endswith(".gz"):
            opener = gzip.open

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
        v["Vulnerability"]["Metadata"] = (
            {"Issued": issued, "Updated": updated, "RefId": ref_id} if updated else {"Issued": issued, "RefId": ref_id}
        )
        v["Vulnerability"]["Name"] = name
        v["Vulnerability"]["Link"] = link
        v["Vulnerability"]["Description"] = description

        if cves:
            v["Vulnerability"]["Metadata"]["CVE"] = cves

        if ns_pkgs_dict and ns_name in ns_pkgs_dict:
            v["Vulnerability"]["FixedIn"] = [
                {
                    "Name": x[0],
                    "Version": x[1],
                    "Module": x[2],
                    "VersionFormat": "rpm",  # hard code version format for now
                    "NamespaceName": ns_name,
                }
                for x in ns_pkgs_dict[ns_name]
            ]
        else:
            logger.warning(f"No affected packages found for {name}, this is unusual")

        # handle duplicates using version version attribute of definition element
        if (name, ns_name) in vuln_dict:
            existing_version, _ = vuln_dict[(name, ns_name)]
            logger.debug(
                "Found an existing record for {} under {}. Version attribute of definition oval element: existing: {}, new: {}".format(  # noqa: G001
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
    Parse and return a dict containing namespace mapped to a set of (package, version) tuples
    :param element_a: outermost criteria element within a definition element
    :param oval_ns: namespace URL of the oval
    :return:
    """
    criteria_element = element_a.find(config.criteria_xpath_query.format(oval_ns))
    groups = []
    ns_pkgs_dict = {}

    if criteria_element.attrib["operator"].lower() == "or":
        for child in list(criteria_element):
            groups.append(_get_all_criterion(child, oval_ns, config))
    else:
        groups.append(_get_all_criterion(criteria_element, oval_ns, config))

    for group in groups:
        if not group:
            # logger.debug('Parsed group for one or more criterion is empty, skipping')
            continue  # bail out of processing the group if its empty

        # Find the first platform version string in the returned list
        ns_name, ns_module = next((x for x in group if not isinstance(x, tuple)), None)

        if ns_name:  # proceed only if a platform is found
            # Filter out duplicate (package, version) tuples
            ns_pkgs_dict[ns_name] = {tuple(list(x) + [ns_module]) for x in group if isinstance(x, tuple)}  # noqa: RUF005
        else:
            # logger.debug('Namespace for the criteria not found, ignoring criteria')
            continue  # ignore this group of conditions if namespace is not found

    return ns_pkgs_dict


def _get_all_criterion(element_b, oval_ns, config: Config):
    """
    Search for all the criterion elements under the given criteria element and
    parse contents into a list. Returned list may contain tuples and or simple strings.
    Package name and version found in the comment of a criterion element is represented by a tuple.
    Platform version found in the comment of a criterion element is represented by a simple string.
    :param element_b: criteria element
    :param oval_ns: namespace URL of the oval
    :return:
    """
    collectibles = []
    final_ns_name = None
    final_module_name = None
    ns_name = None
    module_name = None
    for criterion in element_b.iterfind(config.criterion_xpath_query.format(oval_ns)):
        if re.search(config.pkg_version_pattern, criterion.attrib["comment"]):
            pkg, version = re.search(config.pkg_version_pattern, criterion.attrib["comment"]).groups()
            collectibles.append((pkg, version))
        elif re.search(config.is_installed_pattern, criterion.attrib["comment"]):
            ns_name = config.ns_format.format(re.search(config.is_installed_pattern, criterion.attrib["comment"]).group(1))
        elif re.search(config.pkg_module_pattern, criterion.attrib["comment"]):
            module_name = re.search(config.pkg_module_pattern, criterion.attrib["comment"]).group(1)
        if ns_name:
            final_ns_name = ns_name
        if module_name:
            final_module_name = module_name
    if final_ns_name:
        collectibles.append([final_ns_name, final_module_name])
    return collectibles
