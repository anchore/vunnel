from __future__ import annotations

import copy
import logging
import os
import re
from collections import namedtuple
from typing import Any

import orjson

from vunnel.utils import http, vulnerability

DSAFixedInTuple = namedtuple("DSAFixedInTuple", ["dsa", "link", "distro", "pkg", "ver"])
DSACollection = namedtuple("DSACollection", ["cves", "nocves"])


# Only releases presenting this mapping will be output by the driver, maintain it with new releases.
# Can also be extended via configuration.
debian_distro_map = {
    "trixie": "13",
    "bookworm": "12",
    "bullseye": "11",
    "buster": "10",
    "stretch": "9",
    "jessie": "8",
    "wheezy": "7",
    "sid": "unstable",
}


class Parser:
    _json_url_ = "https://security-tracker.debian.org/tracker/data/json"
    _dsa_url_ = "https://salsa.debian.org/security-tracker-team/security-tracker/raw/master/data/DSA/list"
    _json_file_ = "debian.json"
    _dsa_file_ = "DSA"

    _dsa_start_regex_ = re.compile(r"^\S+.*")
    _dsa_info_regex_ = re.compile(r"^\[(.*)\]\s+(DSA-[^\s]+)\s+([^\s]+)[-\s]+(.*)")
    _cve_list_regex_ = re.compile(r"^\s+\{(.*)\}")
    _fixed_in_regex_ = re.compile(r"^\s+\[(.*)\][-\s]+([^\s]*)(.*)")
    _fixed_in_note_regex_ = re.compile(r"^\s+NOTE:\s+\[(.*)\][-\s]+([^\s]*)(.*)")
    _base_dsa_id_regex_ = re.compile(r"(DSA-[^-]+).*")

    def __init__(self, workspace, download_timeout=125, logger=None, distro_map=None):
        self.workspace = workspace
        self.download_timeout = download_timeout
        if not distro_map:
            distro_map = debian_distro_map
        self.debian_distro_map = distro_map
        self.json_file_path = os.path.join(workspace.input_path, self._json_file_)
        self.dsa_file_path = os.path.join(workspace.input_path, self._dsa_file_)
        self.legacy_records_path = os.path.join(self.workspace.input_path, "legacy")
        self.urls = [self._json_url_, self._dsa_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download_json(self):
        """
        Downloads debian json file
        :return:
        """
        try:
            r = http.get(self._json_url_, self.logger, timeout=self.download_timeout)
            orjson.loads(r.text)  # quick check if json is valid
            with open(self.json_file_path, "w", encoding="utf-8") as OFH:
                OFH.write(r.text)

        except Exception:
            self.logger.exception("Error downloading debian json file")
            raise

    def _download_dsa(self):
        """
        Downloads debian dsa file
        :return:
        """
        try:
            r = http.get(self._dsa_url_, self.logger, timeout=self.download_timeout)
            with open(self.dsa_file_path, "w", encoding="utf-8") as OFH:
                OFH.write(r.text)

        except Exception:
            self.logger.exception("error downloading debian DSA file")
            raise

    def _get_cve_to_dsalist(self, dsa):
        """

        :param dsa:
        :return:
        """
        ns_cve_dsalist = {}
        if dsa["cves"]:
            for fixedin in dsa["fixed_in"]:
                for cve in dsa["cves"]:
                    ns = fixedin["distro"]
                    if ns not in ns_cve_dsalist:
                        ns_cve_dsalist[ns] = {cve: []}
                    if cve not in ns_cve_dsalist[ns]:
                        ns_cve_dsalist[ns][cve] = []
                    ns_cve_dsalist[ns][cve].append(
                        DSAFixedInTuple(
                            dsa=dsa["id"],
                            link=dsa["link"],
                            distro=fixedin["distro"],
                            pkg=fixedin["pkg"],
                            ver=fixedin["ver"],
                        ),
                    )
        else:
            self.logger.debug(f"no CVEs found for {dsa['id']}")

        return ns_cve_dsalist

    def _parse_dsa_record(self, dsa_lines):  # noqa: C901
        """

        :param dsa_lines:
        :return:
        """
        try:
            dsa = {
                "cves": [],
                "fixed_in": [],
            }
            dsa_info_matched = False
            cve_list_matched = False

            for line in dsa_lines:
                if not dsa_info_matched:
                    dsa_info_match = re.match(self._dsa_info_regex_, line)
                    if dsa_info_match:
                        date, vuln_id, package, summary = dsa_info_match.groups()
                        summary = summary.strip() if summary else None
                        dsa["date"] = date
                        dsa["id"] = vuln_id
                        dsa["package"] = package
                        dsa["summary"] = summary
                        dsa["link"] = f"https://security-tracker.debian.org/tracker/{vuln_id}"
                        dsa_info_matched = True
                        continue

                if not cve_list_matched:
                    cve_list_match = re.match(self._cve_list_regex_, line)
                    if cve_list_match:
                        cves = cve_list_match.group(1).split()
                        dsa["cves"] = cves
                        cve_list_matched = True
                        continue

                fixed_in_match = re.match(self._fixed_in_regex_, line)
                if fixed_in_match:
                    distro, pkg, version = fixed_in_match.groups()
                    version = version.strip() if version else None
                    if not version:
                        self.logger.debug(
                            f"release version not included dsa: {dsa.get('id', None)}, distro: {distro}, pkg: {pkg}",
                        )
                    dsa["fixed_in"].append({"distro": distro, "pkg": pkg, "ver": version})
                    continue

                fixed_in_note_match = re.match(self._fixed_in_note_regex_, line)
                if fixed_in_note_match:
                    distro, pkg, version = fixed_in_note_match.groups()
                    version = version.strip() if version else None
                    if not version:
                        self.logger.debug(
                            f"release version not included dsa: {dsa.get('id', None)}, distro: {distro}, pkg: {pkg}",
                        )
                    dsa["fixed_in"].append({"distro": distro, "pkg": pkg, "ver": version})
                    continue

            return dsa
        except Exception:
            self.logger.exception("failed to parse dsa record")

    def _get_dsa_map(self):
        """

        :return:
        """

        if os.path.exists(self.dsa_file_path):
            dsa_map = {}

            with open(self.dsa_file_path, encoding="utf-8") as fp:
                dsa_rec = []
                line = fp.readline()
                while line:
                    if re.match(self._dsa_start_regex_, line) and dsa_rec:
                        # process bunch
                        dsa = self._parse_dsa_record(dsa_lines=dsa_rec)

                        # gather all DSAs with the same base DSA ID so the missing CVEs on some DSAs can be filled in
                        base_dsa_id_match = re.match(self._base_dsa_id_regex_, dsa["id"])
                        base_dsa_id = base_dsa_id_match.group(1) if base_dsa_id_match else dsa["id"]

                        if base_dsa_id not in dsa_map:
                            dsa_map[base_dsa_id] = DSACollection(cves=[], nocves=[])

                        if dsa["cves"]:
                            dsa_map[base_dsa_id].cves.append(dsa)
                        else:
                            dsa_map[base_dsa_id].nocves.append(dsa)
                        del dsa_rec[:]

                    dsa_rec.append(line)
                    line = fp.readline()

            return dsa_map

        raise Exception(f"debian DSA source not found under {self.dsa_file_path}")

    def _normalize_dsa_list(self):
        ns_cve_dsalist = {}
        dsa_map = self._get_dsa_map()

        for dsa_collection in dsa_map.values():
            dsas_with_cves = dsa_collection.cves

            # Fill in the missing CVEs for some incremental DSAs if you can.
            # This also filters out DSAs that don't have neither CVEs nor fixed_in records
            if dsa_collection.nocves and dsas_with_cves:
                # get the cves from any dsa in the list
                cve_list = dsas_with_cves[0]["cves"]
                for dsa in dsa_collection.nocves:
                    dsa.update({"cves": copy.deepcopy(cve_list)})

                dsas_with_cves.extend(dsa_collection.nocves)

            # Invert the data and map DSAs to CVEs to namespaces
            for dsa in dsas_with_cves:
                for ns, cve_dsalist in self._get_cve_to_dsalist(dsa).items():
                    if ns not in ns_cve_dsalist:
                        ns_cve_dsalist[ns] = {}
                    for cve, dsalist in cve_dsalist.items():
                        if cve not in ns_cve_dsalist[ns]:
                            ns_cve_dsalist[ns][cve] = []
                        ns_cve_dsalist[ns][cve].extend(dsalist)

        dsa_map.clear()

        return ns_cve_dsalist

    def _normalize_json(self, ns_cve_dsalist=None):  # noqa: PLR0912,PLR0915,C901
        adv_mets = {}
        # all_matched_dsas = set()
        # all_dsas = set()

        # normalize DSA list
        # ns_cve_dsalist = normalize_dsa_list(dsaloc)

        # # metrics colleciton
        # for ns, cve_dsalist in ns_cve_dsalist.iteritems():
        #     if common.debian_distro_map.get(ns, None):
        #         all_dsas |= set([dsa_tup.dsa for dsalist in cve_dsalist.values() for dsa_tup in dsalist])

        if os.path.exists(self.json_file_path):
            with open(self.json_file_path, encoding="utf-8") as FH:
                data = orjson.loads(FH.read())
        else:
            raise Exception(f"debian json source not found under {self.json_file_path}")

        if ns_cve_dsalist is None:
            ns_cve_dsalist = {}

        vuln_records = {}

        for pkg in data:
            for vid in data[pkg]:
                # skip non CVE vids
                if not re.match("^CVE.*", vid):
                    continue

                # gather NVD data for this CVE. Pulling this logic out of the for loop as NVD data remains the same
                # regardless of the debian release.
                nvd_severity = None
                # if session:
                #     try:
                #         nvd_severity = nvd.get_severity(vid, session=session)
                #     except Exception:
                #         self.logger.exception("ignoring error processing nvdv2 record")

                vulnerability_data = data[pkg][vid]
                release_data = vulnerability_data.get("releases")
                if not isinstance(release_data, dict) or not release_data:
                    continue

                for rel, distro_record in release_data.items():
                    try:
                        relno = self.debian_distro_map.get(rel)
                        if not relno:
                            continue

                        # if relno not in retlists:
                        #    retlists[relno] = []

                        if relno not in vuln_records:
                            vuln_records[relno] = {}

                        complete = True
                        if distro_record.get("status", "") == "undetermined":
                            complete = False

                        if complete:
                            if vid not in vuln_records[relno]:
                                # create a new record
                                vuln_records[relno][vid] = copy.deepcopy(vulnerability.vulnerability_element)
                                vuln_record = vuln_records[relno][vid]

                                # populate the static information about the new vuln record
                                vuln_record["Vulnerability"]["Description"] = vulnerability_data.get("description", "")
                                vuln_record["Vulnerability"]["Name"] = str(vid)
                                vuln_record["Vulnerability"]["NamespaceName"] = "debian:" + str(relno)
                                vuln_record["Vulnerability"]["Link"] = "https://security-tracker.debian.org/tracker/" + str(vid)
                                vuln_record["Vulnerability"]["Severity"] = "Unknown"
                            else:
                                vuln_record = vuln_records[relno][vid]

                            # set severity
                            # from https://anonscm.debian.org/viewvc/secure-testing/bin/tracker_service.py
                            sev = None
                            if "urgency" in distro_record:
                                if distro_record["urgency"] in ["low", "low**"]:
                                    sev = "Low"
                                elif distro_record["urgency"] in ["medium", "medium**"]:
                                    sev = "Medium"
                                elif distro_record["urgency"] in ["high", "high**"]:
                                    sev = "High"
                                elif distro_record["urgency"] in [
                                    "unimportant",
                                    "end-of-life",
                                ]:
                                    sev = "Negligible"
                                elif nvd_severity:  # no match to urgency found
                                    sev = nvd_severity  # fallback to nvd severity
                                else:
                                    sev = "Unknown"
                            elif nvd_severity:  # urgency element is not present
                                sev = nvd_severity  # fallback to nvd severity
                            else:
                                sev = "Unknown"

                            if (
                                sev
                                and vulnerability.severity_order[sev]
                                > vulnerability.severity_order[vuln_record["Vulnerability"]["Severity"]]
                            ):
                                vuln_record["Vulnerability"]["Severity"] = sev

                            # HACK: when we can represent per-package severity or have a good mechanism
                            # for overriding upstream data, we should take this out.
                            if vid == "CVE-2023-44487":
                                self.logger.info(
                                    "clearing severity on CVE-2023-44487, see https://github.com/anchore/grype-db/issues/108#issuecomment-1796301073",
                                )
                                vuln_record["Vulnerability"]["Severity"] = "Unknown"

                            # add fixedIn
                            skip_fixedin = False
                            fixed_el = {
                                "Name": pkg,
                                "NamespaceName": "debian:" + str(relno),
                                "VersionFormat": "dpkg",
                            }

                            if "fixed_version" in distro_record:
                                fixed_el["Version"] = distro_record["fixed_version"]
                                if distro_record["fixed_version"] == "0":
                                    # version == 0 should mean that the
                                    # package was determined to not be
                                    # vulnerable in the distro namespace
                                    # (from reviewing
                                    # https://security-tracker.debian.org/tracker/)
                                    skip_fixedin = True
                            else:
                                fixed_el["Version"] = "None"

                            if not skip_fixedin:
                                # collect metrics for vendor advisory
                                met_ns = vuln_record["Vulnerability"]["NamespaceName"]
                                met_sev = vuln_record["Vulnerability"]["Severity"]

                                if met_ns not in adv_mets:
                                    adv_mets[met_ns] = {
                                        met_sev: {
                                            "dsa": {"fixed": 0, "notfixed": 0},
                                            "nodsa": {"fixed": 0, "notfixed": 0},
                                            "neither": {"fixed": 0, "notfixed": 0},
                                        },
                                    }

                                if met_sev not in adv_mets[met_ns]:
                                    adv_mets[met_ns][met_sev] = {
                                        "dsa": {"fixed": 0, "notfixed": 0},
                                        "nodsa": {"fixed": 0, "notfixed": 0},
                                        "neither": {"fixed": 0, "notfixed": 0},
                                    }

                                # find DSAs associated with the CVE and package in the namespace
                                matched_dsas = [dsa for dsa in ns_cve_dsalist.get(rel, {}).get(vid, []) if dsa.pkg == pkg]

                                # add vendor advisory information to the fixed in record
                                if matched_dsas:
                                    fixed_el["VendorAdvisory"] = {
                                        "NoAdvisory": False,
                                        "AdvisorySummary": [{"ID": x.dsa, "Link": x.link} for x in matched_dsas],
                                    }
                                    # all_matched_dsas |= set([x.dsa for x in matched_dsas])
                                    adv_mets[met_ns][met_sev]["dsa"][
                                        "notfixed" if fixed_el["Version"] == "None" else "fixed"
                                    ] += 1
                                elif "nodsa" in distro_record:
                                    fixed_el["VendorAdvisory"] = {"NoAdvisory": True}
                                    adv_mets[met_ns][met_sev]["nodsa"][
                                        "notfixed" if fixed_el["Version"] == "None" else "fixed"
                                    ] += 1
                                else:
                                    fixed_el["VendorAdvisory"] = {
                                        "NoAdvisory": False,
                                        "AdvisorySummary": [],
                                    }
                                    adv_mets[met_ns][met_sev]["neither"][
                                        "notfixed" if fixed_el["Version"] == "None" else "fixed"
                                    ] += 1

                                # append fixed in record to vulnerability
                                vuln_record["Vulnerability"]["FixedIn"].append(fixed_el)

                            # strip out any top level that is not set
                            final_record = {"Vulnerability": {}}
                            for k in vuln_record["Vulnerability"]:
                                if vuln_record["Vulnerability"][k]:
                                    final_record["Vulnerability"][k] = copy.deepcopy(vuln_record["Vulnerability"][k])

                            # retlists[relno].append(final_record)

                    except Exception:
                        self.logger.exception(f"ignoring error parsing vuln: {vid}, pkg: {pkg}, rel: {rel}")

        self.logger.debug(f"metrics for advisory information: {orjson.dumps(adv_mets).decode('utf-8')}")

        adv_mets.clear()
        # all_dsas.clear()
        # all_matched_dsas.clear()

        return vuln_records

    def _get_legacy_records(self):
        legacy_records = {}

        def process_file(contents: list[dict[str, Any]]) -> None:
            for record in contents:
                relno = record["Vulnerability"]["NamespaceName"].split(":")[-1]
                vid = record["Vulnerability"]["Name"]
                if relno not in legacy_records:
                    legacy_records[relno] = {}

                # ensure results are compliant with the current schema
                cvss_metadata = record["Vulnerability"].get("Metadata", {}).get("NVD", {}).get("CVSSv2", {})
                if cvss_metadata:
                    if cvss_metadata["Vectors"] is None:
                        del cvss_metadata["Vectors"]
                    record["Vulnerability"]["Metadata"]["NVD"]["CVSSv2"] = cvss_metadata

                # write the record back
                legacy_records[relno][vid] = record

        # read every json file in the legacy directory
        for root, _dirs, files in os.walk(self.legacy_records_path):
            for file in files:
                if file.endswith(".json") and file.startswith("vulnerabilities"):
                    with open(os.path.join(root, file)) as f:
                        process_file(orjson.loads(f.read()))

        if legacy_records:
            self.logger.info(f"found existing legacy data for the following releases: {list(legacy_records.keys())}")
        else:
            self.logger.info("no existing legacy data found")

        return legacy_records

    def get(self):
        # download the files
        self._download_json()
        self._download_dsa()

        # normalize dsa list first
        ns_cve_dsalist = self._normalize_dsa_list()

        # normalize json file
        vuln_records = self._normalize_json(ns_cve_dsalist=ns_cve_dsalist)

        # fetch records from legacy (if they exist)
        legacy_records = self._get_legacy_records()
        vuln_records.update(legacy_records)

        if vuln_records:
            for relno, vuln_dict in vuln_records.items():
                for vid, vuln_record in vuln_dict.items():
                    yield relno, vid, vuln_record
        else:
            yield from ()
