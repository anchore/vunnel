# pylint: skip-file

import re
import time
import xml.etree.ElementTree as ET
import zlib
from collections import namedtuple

import requests
from anchore_engine.db import session_scope
from anchore_engine.subsys import logger
from anchore_enterprise.db.entities.feeds import DataRecord

CPETuple = namedtuple("CPETuple", ["cpe22_uri", "cpe23_fs", "cpe_obj"])


def get_severity(cve, session=None):
    """
    Looks up the nvdv2 database record for input cve and returns the severity
    """
    if not session:
        with session_scope() as session:
            payload = db_lookup(cve, session)
    else:
        payload = db_lookup(cve, session)

    return _get_payload_severity(payload)


def _get_payload_severity(payload):
    """
    Returns the severity from input nvdv2 payload. If severity is not available, falls back to CVSS v3 and CVSS v2 severity in that order
    """
    severity = None

    if not payload or not isinstance(payload, dict):
        return severity

    severity = payload.get("severity")
    if not severity:
        severity = _get_cvss_v3_severity(payload)
        if not severity:
            severity = _get_cvss_v2_severity(payload)

    return severity


def _get_cvss_v3_severity(payload):
    severity = None

    if not payload or not isinstance(payload, dict):
        return severity

    cvss_v3 = payload.get("cvss_v3")
    if cvss_v3:
        severity = cvss_v3.get("base_metrics", {}).get("base_severity")

    return severity


def _get_cvss_v2_severity(payload):
    severity = None

    if not payload or not isinstance(payload, dict):
        return severity

    cvss_v2 = payload.get("cvss_v2")
    if cvss_v2:
        severity = cvss_v2.get("severity")

    return severity


def db_lookup(cve, session, feed_id="nvdv2", group_id="nvdv2:cves"):
    payload = None
    try:
        nvd_record = (
            session.query(DataRecord)
            .filter(DataRecord.feed_id == feed_id)
            .filter(DataRecord.group_id == group_id)
            .filter(DataRecord.record_id == cve)
            .one_or_none()
        )

        payload = nvd_record.payload if nvd_record else None
    except:
        logger.exception("Database error looking up nvdv2 record for {}".format(cve))

    return payload


encode_dict = {
    "!": "%21",
    '"': "%22",
    "#": "%23",
    "$": "%24",
    "%": "%25",
    "&": "%26",
    "'": "%27",
    "(": "%28",
    ")": "%29",
    "*": "%2a",
    "+": "%2b",
    ",": "%2c",
    # '-': '-',  # not affected by transformation between formatted string and uri, only impacts wfn
    # '.': '.',  # not affected by transformation between formatted string and uri, only impacts wfn
    "/": "%2f",
    ":": "%3a",
    ";": "%3b",
    "<": "%3c",
    "=": "%3d",
    ">": "%3e",
    "?": "%3f",
    "@": "%40",
    "[": "%5b",
    "\\": "%5c",
    "]": "%5d",
    "^": "%5e",
    "`": "%60",
    "{": "%7b",
    "|": "%7c",
    "}": "%7d",
    "~": "%7e",
}


class CPE(object):
    """
    A helper class for converting CPE 2.3 formatted string into CPE 2.2 URI and matching CPE 2.3 formatted strings
    """

    def __init__(
        self,
        part=None,
        vendor=None,
        product=None,
        version=None,
        update=None,
        edition=None,
        language=None,
        sw_edition=None,
        target_sw=None,
        target_hw=None,
        other=None,
    ):
        self.part = part
        self.vendor = vendor
        self.product = product
        self.version = version
        self.update = update
        self.edition = edition
        self.language = language
        self.sw_edition = sw_edition
        self.target_sw = target_sw
        self.target_hw = target_hw
        self.other = other

    def __hash__(self):
        return hash(
            (
                self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                self.edition,
                self.language,
                self.sw_edition,
                self.target_sw,
                self.target_hw,
                self.other,
            )
        )

    def __eq__(self, other):
        return other and self == other

    def __repr__(self):
        return "CPE: part={}, vendor={}, product={}, version={}, update={}, edition={}, language={}, sw_edition={}, target_sw={}, target_hw={}, other={}".format(
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other,
        )

    def copy(self):
        return CPE(
            part=self.part,
            vendor=self.vendor,
            product=self.product,
            version=self.version,
            update=self.update,
            edition=self.edition,
            language=self.language,
            sw_edition=self.sw_edition,
            target_sw=self.target_sw,
            target_hw=self.target_hw,
            other=self.other,
        )

    @staticmethod
    def from_cpe23_fs(cpe23_fs):
        """
        Takes a CPE 2.3 formatted string and returns a CpeWfn object. This is the only supported method to create this CPE object

        This is not entirely true to the spec, it does not unbind all the elements as wfn representation is not used.
        Instead all of unbinding logic is concentrated in the conversion from wfn to uri format

        :param cpe23_fs: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        :return:
        """

        cpe_parts = cpe23_fs.split(":")

        if cpe_parts and len(cpe_parts) == 13:
            return CPE(
                part=cpe_parts[2],
                vendor=cpe_parts[3],
                product=cpe_parts[4],
                version=cpe_parts[5],
                update=cpe_parts[6],
                edition=cpe_parts[7],
                language=cpe_parts[8],
                sw_edition=cpe_parts[9],
                target_sw=cpe_parts[10],
                target_hw=cpe_parts[11],
                other=cpe_parts[12],
            )
        elif len(cpe_parts) > 13:
            # logger.debug('{} did not split nicely into 13 parts'.format(cpe23_fs))

            adjusted_cpe_parts = []
            counter = 1

            # start from the third element in the list and iterate through the last element
            while counter < len(cpe_parts) - 1:
                counter += 1
                part = cpe_parts[counter]

                # if the element ends with a '\', good chance its an escape for ':', concatenate the elements together
                if part.endswith("\\"):
                    new_part = part

                    while counter < len(cpe_parts) - 1:
                        counter += 1
                        part = cpe_parts[counter]
                        new_part += ":" + part

                        if part.endswith("\\"):
                            continue
                        else:
                            break

                    adjusted_cpe_parts.append(new_part)
                else:
                    adjusted_cpe_parts.append(part)

            if len(adjusted_cpe_parts) == 11:
                # logger.debug('Adjusted cpe components: {}'.format(adjusted_cpe_parts))
                return CPE(
                    part=adjusted_cpe_parts[0],
                    vendor=adjusted_cpe_parts[1],
                    product=adjusted_cpe_parts[2],
                    version=adjusted_cpe_parts[3],
                    update=adjusted_cpe_parts[4],
                    edition=adjusted_cpe_parts[5],
                    language=adjusted_cpe_parts[6],
                    sw_edition=adjusted_cpe_parts[7],
                    target_sw=adjusted_cpe_parts[8],
                    target_hw=adjusted_cpe_parts[9],
                    other=adjusted_cpe_parts[10],
                )
            else:
                raise Exception("Cannot convert cpe 2.3 formatted string {} into wfn".format(cpe23_fs))
        else:
            raise Exception(
                "Invalid cpe 2.3 formatted string {} Splitting with : delimiter resulted in less than 13 elements".format(
                    cpe23_fs
                )
            )

    def as_cpe23_fs(self):
        return "cpe:2.3:{}".format(
            ":".join(
                [
                    self.part,
                    self.vendor,
                    self.product,
                    self.version,
                    self.update,
                    self.edition,
                    self.language,
                    self.sw_edition,
                    self.target_sw,
                    self.target_hw,
                    self.other,
                ]
            )
        )

    def update_version(self, version):
        """
        Helper method for escaping the
        Ensures that resulting version is CPE 2.3 formatted string compliant, this is necessary for as_cpe22_uri() to do its thing
        affected version data in nvd json data which is usually unescaped. Converts the supplied version

        :param version:
        :return:
        """
        self.version = CPE.escape_for_cpe23_fs(version)

    @staticmethod
    def escape_for_cpe23_fs(element):
        """
        Helper method for escaping special characters as per the CPE 2.3 formatted string spec

        :param element:
        :return: escaped element string as per CPE 2.3 formatted string spec
        """

        if not isinstance(element, str):
            raise Exception("Value to be escaped is not a string")

        if element in ["*", "-", ""]:  # let these pass through as they are
            return element
        elif any(char in encode_dict for char in element):
            new_element = str()
            pos = 0
            while pos < len(element):
                char = element[pos]

                if char == "\\":  # this might be an escape character, check to see if the next character requires escape
                    pos += 1
                    if pos < len(element):
                        n_char = element[pos]
                        if n_char in encode_dict:  # definitely an escaped sequence, preserve it as it is
                            new_element += char + n_char
                        else:  # just a \ that needs to be escaped
                            new_element += "\\" + char + n_char
                    else:  # last char is unescaped \, just add an escape
                        new_element += "\\" + char
                elif char in encode_dict:
                    new_element += "\\" + char
                else:
                    new_element += char

                pos += 1

            return new_element
        else:
            return element

    @staticmethod
    def bind_for_cpe22_uri(element):
        if not isinstance(element, str):
            raise Exception("Value to be bound in URI format is not a string")

        if element == "*":
            return ""
        elif element in ["-", ""]:
            return element
        else:
            result = str()
            pos = -1
            while pos < (len(element) - 1):
                pos += 1
                char = element[pos]
                if char == "\\":  # an escaped character, percent encode it if possible
                    if pos != (len(element) - 1):  # check the next character and transform into percent encoded string
                        pos += 1
                        n_char = element[pos]
                        encoded = encode_dict.get(n_char, None)
                        if encoded:
                            result += encoded
                        else:  # no encoding found, let it go through as it is
                            logger.warn("No encoding found for {}{}".format(char, n_char))
                            result += char + n_char
                    else:  # this is the last char, nothing to percent encode
                        logger.warn("{} is the last char, skipping percent encoded transformation".format(char))
                        result += char
                elif char == "?":  # bind the unescaped ? to %01
                    result += "%01"
                elif char == "*":  # bind the unescaped * to %02
                    result += "%02"
                else:
                    result += char

            return result

    def as_cpe22_uri(self):
        """
        Transforms this CPE object into a CPE 2.2 URI. Based on the specification in https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf

        :return: CPE 2.2 URI string
        """

        # part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        # 0    1      2       3       4      5       6        7          8         9         10
        # |-------------cpe 2.2 attributes-----------        |------------new in cpe 2.3----------|

        e = CPE.bind_for_cpe22_uri(self.edition)
        sw_e = CPE.bind_for_cpe22_uri(self.sw_edition)
        t_sw = CPE.bind_for_cpe22_uri(self.target_sw)
        t_hw = CPE.bind_for_cpe22_uri(self.target_hw)
        o = CPE.bind_for_cpe22_uri(self.other)

        if sw_e or t_sw or t_hw or o:
            edition = "~{}~{}~{}~{}~{}".format(e, sw_e, t_sw, t_hw, o)
        else:
            edition = e

        uri_parts = [
            "cpe",
            "/" + self.part,
            CPE.bind_for_cpe22_uri(self.vendor),
            CPE.bind_for_cpe22_uri(self.product),
            CPE.bind_for_cpe22_uri(self.version),
            CPE.bind_for_cpe22_uri(self.update),
            edition,
            CPE.bind_for_cpe22_uri(self.language),
        ]

        uri = ":".join(uri_parts)
        uri = uri.strip(":")  # remove any trailing :

        return uri

    def is_match(self, other_cpe):
        """
        This is a very limited implementation of cpe matching. other_cpe is a wildcard ridden base cpe used by range descriptors
        other_cpe checked against this cpe for an exact match of part and vendor.
        For all the remaining components a match is positive if the other cpe is an exact match or contains the wild char

        :param other_cpe:
        :return:
        """
        if not isinstance(other_cpe, CPE):
            return False

        if self.part == other_cpe.part and self.vendor == other_cpe.vendor:

            if other_cpe.product not in ["*", self.product]:
                return False
            if other_cpe.version not in ["*", self.version]:
                return False
            if other_cpe.update not in ["*", self.update]:
                return False
            if other_cpe.edition not in ["*", self.edition]:
                return False
            if other_cpe.language not in ["*", self.language]:
                return False
            if other_cpe.sw_edition not in ["*", self.sw_edition]:
                return False
            if other_cpe.target_sw not in ["*", self.target_sw]:
                return False
            if other_cpe.target_hw not in ["*", self.target_hw]:
                return False
            if other_cpe.other not in ["*", self.other]:
                return False

            return True
        else:
            return False


class NVDCPEDictionaryUtils(object):
    _tag_pattern_ = re.compile(r"\{.*\}(.*)")
    _cpe_url_ = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

    @staticmethod
    def download_v23(xml_file_path, download_timeout=125):
        """
        Downloads the official CPE v2.3 dictionary to a file

        :param xml_file_path: path object to downloaded file
        :param download_timeout:
        :return:
        """
        try:
            decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
            logger.info("Downloading cpe dictionary from {}".format(NVDCPEDictionaryUtils._cpe_url_))
            r = requests.get(NVDCPEDictionaryUtils._cpe_url_, stream=True, timeout=download_timeout)
            if r.status_code == 200:
                logger.debug("Saving content to: {}".format(xml_file_path))
                with open(xml_file_path, "wb") as fp:
                    for chunk in r.iter_content(chunk_size=1024):
                        ungzbuf = decompressor.decompress(chunk)
                        fp.write(ungzbuf)
            else:
                raise Exception("Downloading {} failed with {} HTTP error".format(NVDCPEDictionaryUtils._cpe_url_, r.status_code))

            return xml_file_path
        except:
            logger.exception("Error downloading NVD CPE v2.3 dictionary")
            raise

    @staticmethod
    def load_to_map(file_path):
        """
        Load cpe dictionary xml file into map in the format vendor -> product -> CPETuple list

        :param file_path: path object to cpe dictionary xml file
        :return:
        """
        logger.debug("Loading cpe dictionary from {}".format(file_path))
        st = time.time()
        hmap = dict()

        cpe22_uri = None
        cpe23_fs = None
        for event, element in ET.iterparse(file_path, events=("start", "end")):
            if event == "start" and re.search(NVDCPEDictionaryUtils._tag_pattern_, element.tag).group(1) == "cpe-item":
                if "deprecated" in element.attrib and element.attrib.get("deprecated").lower() == "true":
                    continue
                else:
                    cpe22_uri = element.attrib.get("name", None)
            elif (
                cpe22_uri
                and event == "start"
                and re.search(NVDCPEDictionaryUtils._tag_pattern_, element.tag).group(1) == "cpe23-item"
            ):
                try:
                    cpe23_fs = element.attrib.get("name", None)
                    cpe23_obj = CPE.from_cpe23_fs(cpe23_fs)

                    if not cpe23_fs or not cpe23_obj:
                        logger.warn("valid cpe23 not found for {}".format(cpe22_uri))
                        continue

                    if cpe23_obj.vendor not in hmap:
                        hmap[cpe23_obj.vendor] = {}

                    if cpe23_obj.product not in hmap[cpe23_obj.vendor]:
                        hmap[cpe23_obj.vendor][cpe23_obj.product] = []

                    hmap[cpe23_obj.vendor][cpe23_obj.product].append(
                        CPETuple(cpe22_uri=cpe22_uri, cpe23_fs=cpe23_fs, cpe_obj=cpe23_obj)
                    )
                except:
                    pass
                finally:
                    cpe22_uri = None
                    cpe23_fs = None

        logger.debug("cpe dictionary contains {} vendor keys. load took {} seconds".format(len(hmap), (time.time() - st)))
        return hmap

    @staticmethod
    def expand_versions(cpe_dict, base_cpe_obj, hmap):
        """
        Expand the range specified in cpe_dict by finding matches for base_cpe_obj from cpe dictionary loaded into hmap

        :param cpe_dict: version range element
            {
                 "vulnerable" : true,
                 "cpe23Uri" : "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
                 "versionStartIncluding" : "7.0.0",
                 "versionEndIncluding" : "7.0.93"
            }
        :param base_cpe_obj: CPE object
        :param hmap: cpe dictionary loaded into a map in the format vendor -> product -> CPETuple list
        :return: list of strings where in each represents CPE 2.3 formatted string
        """
        cpe_list = list()
        potential_tuples = list()

        start_ver = end_ver = include_start = include_end = None
        start_found = beginning_of_end = base_matched = False

        if "versionStartIncluding" in cpe_dict:
            start_ver = cpe_dict["versionStartIncluding"]
            include_start = True
        elif "versionStartExcluding" in cpe_dict:
            start_ver = cpe_dict["versionStartExcluding"]
            include_start = False
        else:
            include_start = True  # include the beginning as no start version supplied

        if "versionEndIncluding" in cpe_dict:
            end_ver = cpe_dict["versionEndIncluding"]
            include_end = True
        elif "versionEndExcluding" in cpe_dict:
            end_ver = cpe_dict["versionEndExcluding"]
            include_end = False
        else:
            include_end = True  # include the ending as no end version supplied

        if not start_ver and not end_ver:  # bail out if both start and end are invalid
            logger.warn("Start and end versions are invalid, skipping cpe dictionary lookup for {}".format(cpe_dict))
            return cpe_list

        # start and end versions are the same but at least one is excluded
        if start_ver == end_ver and (not include_start or not include_end):
            logger.warn(
                "Start and end versions are the same but at least one of them is excluded. Skipping cpe dictionary lookup"
            )
            return cpe_list  # bail out without any matches

        if start_ver:
            # escape the version as per CPE 2.3 formatted string spec, necessary for lookups in cpe dict later
            start_ver = CPE.escape_for_cpe23_fs(start_ver)

        if end_ver:
            # escape the version as per CPE 2.3 formatted string spec, necessary for lookups in cpe dict later
            end_ver = CPE.escape_for_cpe23_fs(end_ver)

        if base_cpe_obj.vendor in hmap:
            if base_cpe_obj.product != "*" and base_cpe_obj.product in hmap[base_cpe_obj.vendor]:
                potential_tuples = hmap[base_cpe_obj.vendor][base_cpe_obj.product]
            else:
                # logger.warn('No exact match for product {} found under vendor {}, skipping cpe dictionary lookup for {}'
                #             .format(base_cpe_obj.product, base_cpe_obj.vendor, cpe_dict))
                pass
        else:  # nothing to match against if vendor is not in the cpe dictionary
            # logger.warn('vendor {} not found in cpe dictionary, nothing to lookup for {}'.format(base_cpe_obj.vendor, cpe_dict))
            pass

        for cpe_tup in potential_tuples:
            cpe23_fs = cpe_tup.cpe23_fs
            cpe_obj = cpe_tup.cpe_obj

            if cpe_obj.is_match(base_cpe_obj):
                base_matched = True  # for a quick exit when the cpes stop matching

                if not start_found:  # find the beginning of the range
                    if not start_ver:  # no start version supplied, this is the beginning!
                        start_found = True
                    elif start_ver == cpe_obj.version:  # start version was supplied, compare the versions
                        start_found = True
                    elif end_ver and end_ver == cpe_obj.version:  # check if its the end version before moving on
                        beginning_of_end = True
                        # logger.warn('Found end before the beginning')
                        break  # end found before start, quick exit without evaluating the remaining matches
                    else:  # keep going with the search
                        continue

                    if start_found:  # after start is found, check if end is the same as start
                        if (
                            end_ver and end_ver == cpe_obj.version
                        ):  # end version was supplied, compare the versions to check if start and end are the same
                            beginning_of_end = True  # beginning of the end has been spotted
                            if (
                                not include_end
                            ):  # begin and end versions are the same and end is excluded, so the result is empty. This happens when there is only one version and it is explicitly excluded
                                break

                        if include_start:  # survived through
                            cpe_list.append(cpe23_fs)
                else:  # find the middle and end of the range
                    if start_ver and start_ver == cpe_obj.version:  # may be middle but version continues to match with start
                        if include_start:  # include only if necessary
                            cpe_list.append(cpe23_fs)
                        continue
                    elif not end_ver:  # no end version supplied and not a match with the start, this is probably the middle
                        cpe_list.append(cpe23_fs)
                        continue
                    else:  # end version is supplied
                        if end_ver == cpe_obj.version:  # end version is an exact match
                            beginning_of_end = True  # beginning of the end has been spotted

                            if not include_end:  # if the range excludes end, this is definitely the end
                                break
                            else:  # this may be the beginning of end, keep going
                                cpe_list.append(cpe23_fs)
                                continue
                        else:  # end version was supplied and is not exact match
                            if (
                                beginning_of_end
                            ):  # beginning of end version spotted, which means this version is past the end. Do not include this
                                break
                            else:  # end version was supplied but it didn't match, also beggining of end has not been encountered. this is probably the middle
                                cpe_list.append(cpe23_fs)
                                continue
            else:  # this cpe is not match for base
                if base_matched:  # cpes stopped matching base, this is the end
                    break
                else:  # base cpe match not found yet, keep going
                    continue

        # start was not found or end was specified and not found
        if cpe_list and (not start_found or (end_ver and not beginning_of_end)):
            cpe_list.clear()  # matches are a bust, drop them all

        if not cpe_list:  # cpe lookups didn't yield anything, add the boundaries at least
            if start_ver and include_start:
                start_cpe_obj = base_cpe_obj.copy()
                start_cpe_obj.version = start_ver  # version already escaped correctly, no need to call update_version
                cpe_list.append(start_cpe_obj.as_cpe23_fs())

            if end_ver and include_end:
                end_cpe_obj = base_cpe_obj.copy()
                end_cpe_obj.version = end_ver  # version already escaped correctly, no need to call update_version
                cpe_list.append(end_cpe_obj.as_cpe23_fs())

        return cpe_list

    @staticmethod
    def expand_versions_cpe22(cpe_dict, base_cpe_obj, hmap):
        """
        Expand the range specified in cpe_dict by finding matches for base_cpe_obj from cpe dictionary loaded into hmap
        This is almost an exact copy of the expand_versions(). Keeping this separate to avoid checks on every match
        to be evaluated. Only the previous nvd driver should use this function and will be deprecated soon.

        :param cpe_dict: version range element
            {
                 "vulnerable" : true,
                 "cpe23Uri" : "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
                 "versionStartIncluding" : "7.0.0",
                 "versionEndIncluding" : "7.0.93"
            }
        :param base_cpe_obj: CPE object
        :param hmap: cpe dictionary loaded into a map in the format vendor -> product -> CPETuple list
        :return: list of strings where in each represents CPE 2.2 URI
        """
        cpe_list = list()
        potential_tuples = list()

        start_ver = end_ver = include_start = include_end = None
        start_found = beginning_of_end = base_matched = False

        if "versionStartIncluding" in cpe_dict:
            start_ver = cpe_dict["versionStartIncluding"]
            include_start = True
        elif "versionStartExcluding" in cpe_dict:
            start_ver = cpe_dict["versionStartExcluding"]
            include_start = False
        else:
            include_start = True  # include the beginning as no start version supplied

        if "versionEndIncluding" in cpe_dict:
            end_ver = cpe_dict["versionEndIncluding"]
            include_end = True
        elif "versionEndExcluding" in cpe_dict:
            end_ver = cpe_dict["versionEndExcluding"]
            include_end = False
        else:
            include_end = True  # include the ending as no end version supplied

        if not start_ver and not end_ver:  # bail out if both start and end are invalid
            logger.warn("Start and end versions are invalid, skipping cpe dictionary lookup for {}".format(cpe_dict))
            return cpe_list

        # start and end versions are the same but at least one is excluded
        if start_ver == end_ver and (not include_start or not include_end):
            logger.warn(
                "Start and end versions are the same but at least one of them is excluded. Skipping cpe dictionary lookup"
            )
            return cpe_list  # bail out without any matches

        if start_ver:
            # escape the version as per CPE 2.3 formatted string spec, necessary for lookups in cpe dict later
            start_ver = CPE.escape_for_cpe23_fs(start_ver)

        if end_ver:
            # escape the version as per CPE 2.3 formatted string spec, necessary for lookups in cpe dict later
            end_ver = CPE.escape_for_cpe23_fs(end_ver)

        if base_cpe_obj.vendor in hmap:
            if base_cpe_obj.product != "*" and base_cpe_obj.product in hmap[base_cpe_obj.vendor]:
                potential_tuples = hmap[base_cpe_obj.vendor][base_cpe_obj.product]
            else:
                # logger.warn('No exact match for product {} found under vendor {}, skipping cpe dictionary lookup for {}'
                #             .format(base_cpe_obj.product, base_cpe_obj.vendor, cpe_dict))
                pass
        else:  # nothing to match against if vendor is not in the cpe dictionary
            # logger.warn('vendor {} not found in cpe dictionary, nothing to lookup for {}'.format(base_cpe_obj.vendor, cpe_dict))
            pass

        for cpe_tup in potential_tuples:
            cpe22_uri = cpe_tup.cpe22_uri
            cpe_obj = cpe_tup.cpe_obj

            if cpe_obj.is_match(base_cpe_obj):
                base_matched = True  # for a quick exit when the cpes stop matching

                if not start_found:  # find the beginning of the range
                    if not start_ver:  # no start version supplied, this is the beginning!
                        start_found = True
                    elif start_ver == cpe_obj.version:  # start version was supplied, compare the versions
                        start_found = True
                    elif end_ver and end_ver == cpe_obj.version:  # check if its the end version before moving on
                        beginning_of_end = True
                        # logger.warn('Found end before the beginning')
                        break  # end found before start, quick exit without evaluating the remaining matches
                    else:  # keep going with the search
                        continue

                    if start_found:  # after start is found, check if end is the same as start
                        if (
                            end_ver and end_ver == cpe_obj.version
                        ):  # end version was supplied, compare the versions to check if start and end are the same
                            beginning_of_end = True  # beginning of the end has been spotted
                            if (
                                not include_end
                            ):  # begin and end versions are the same and end is excluded, so the result is empty. This happens when there is only one version and it is explicitly excluded
                                break

                        if include_start:  # survived through
                            cpe_list.append(cpe22_uri)
                else:  # find the middle and end of the range
                    if start_ver and start_ver == cpe_obj.version:  # may be middle but version continues to match with start
                        if include_start:  # include only if necessary
                            cpe_list.append(cpe22_uri)
                        continue
                    elif not end_ver:  # no end version supplied and not a match with the start, this is probably the middle
                        cpe_list.append(cpe22_uri)
                        continue
                    else:  # end version is supplied
                        if end_ver == cpe_obj.version:  # end version is an exact match
                            beginning_of_end = True  # beginning of the end has been spotted

                            if not include_end:  # if the range excludes end, this is definitely the end
                                break
                            else:  # this may be the beginning of end, keep going
                                cpe_list.append(cpe22_uri)
                                continue
                        else:  # end version was supplied and is not exact match
                            if (
                                beginning_of_end
                            ):  # beginning of end version spotted, which means this version is past the end. Do not include this
                                break
                            else:  # end version was supplied but it didn't match, also beggining of end has not been encountered. this is probably the middle
                                cpe_list.append(cpe22_uri)
                                continue
            else:  # this cpe is not match for base
                if base_matched:  # cpes stopped matching base, this is the end
                    break
                else:  # base cpe match not found yet, keep going
                    continue

        # start was not found or end was specified and not found
        if cpe_list and (not start_found or (end_ver and not beginning_of_end)):
            cpe_list.clear()  # matches are a bust, drop them all

        if not cpe_list:  # cpe lookups didn't yield anything, add the boundaries at least
            if start_ver and include_start:
                start_cpe_obj = base_cpe_obj.copy()
                start_cpe_obj.version = start_ver  # version already escaped correctly, no need to call update_version
                cpe_list.append(start_cpe_obj.as_cpe22_uri())

            if end_ver and include_end:
                end_cpe_obj = base_cpe_obj.copy()
                end_cpe_obj.version = end_ver  # version already escaped correctly, no need to call update_version
                cpe_list.append(end_cpe_obj.as_cpe22_uri())

        return cpe_list
