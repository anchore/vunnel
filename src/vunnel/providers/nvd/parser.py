# flake8: noqa

import datetime
import hashlib
import json
import logging
import os
import re
import time
import zlib
from collections import namedtuple
from decimal import Decimal
from typing import List

import defusedxml.ElementTree as ET
import requests
from ijson import common as ijcommon
from ijson.backends import python as ijpython

CPETuple = namedtuple("CPETuple", ["cpe22_uri", "cpe23_fs", "cpe_obj"])

namespace = "nvdv2"
feedtype = "nvdv2"
purge_unreported = False

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


class CPE:
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
        # noqa
        return f"CPE: part={self.part}, vendor={self.vendor}, product={self.product}, version={self.version}, update={self.update}, edition={self.edition}, language={self.language}, sw_edition={self.sw_edition}, target_sw={self.target_sw}, target_hw={self.target_hw}, other={self.other}"

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
        raise Exception(
            "Invalid cpe 2.3 formatted string {} Splitting with : delimiter resulted in less than 13 elements".format(cpe23_fs)
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
        return element

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

        return False


class NVDCPEDictionaryUtils:
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
            logging.info("downloading CPE dictionary from {}".format(NVDCPEDictionaryUtils._cpe_url_))
            r = requests.get(NVDCPEDictionaryUtils._cpe_url_, stream=True, timeout=download_timeout)
            if r.status_code == 200:
                logging.debug("saving content to: {}".format(xml_file_path))
                with open(xml_file_path, "wb") as fp:
                    for chunk in r.iter_content(chunk_size=1024):
                        ungzbuf = decompressor.decompress(chunk)
                        fp.write(ungzbuf)
            else:
                raise Exception("Downloading {} failed with {} HTTP error".format(NVDCPEDictionaryUtils._cpe_url_, r.status_code))

            return xml_file_path
        except:
            logging.exception("error downloading NVD CPE v2.3 dictionary")
            raise

    @staticmethod
    def load_to_map(file_path):
        """
        Load cpe dictionary xml file into map in the format vendor -> product -> CPETuple list

        :param file_path: path object to cpe dictionary xml file
        :return:
        """
        logging.debug("loading CPE dictionary from {}".format(file_path))
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
                        logging.warning("valid cpe23 not found for {}".format(cpe22_uri))
                        continue

                    if cpe23_obj.vendor not in hmap:
                        hmap[cpe23_obj.vendor] = {}

                    if cpe23_obj.product not in hmap[cpe23_obj.vendor]:
                        hmap[cpe23_obj.vendor][cpe23_obj.product] = []

                    hmap[cpe23_obj.vendor][cpe23_obj.product].append(
                        CPETuple(cpe22_uri=cpe22_uri, cpe23_fs=cpe23_fs, cpe_obj=cpe23_obj)
                    )
                except:  # nosec
                    pass
                finally:
                    cpe22_uri = None
                    cpe23_fs = None

        logging.debug("CPE dictionary contains {} vendor keys (load took {} seconds)".format(len(hmap), (time.time() - st)))
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
            logging.warning("start and end versions are invalid, skipping CPE dictionary lookup for {}".format(cpe_dict))
            return cpe_list

        # start and end versions are the same but at least one is excluded
        if start_ver == end_ver and (not include_start or not include_end):
            logging.warning(
                "start and end versions are the same but at least one of them is excluded. Skipping CPE dictionary lookup"
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
                            if not include_end:
                                # begin and end versions are the same and end is excluded, so the result is empty. This
                                # happens when there is only one version and it is explicitly excluded
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
                            ):  # beginning of end version spotted, which means this version is past the end. Do not
                                # include this
                                break
                            else:  # end version was supplied but it didn't match, also beggining of end has not been
                                # encountered. this is probably the middle
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


class Parser:
    _url_format_ = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz"
    _meta_url_format_ = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.meta"
    _download_timeout_ = 125
    _data_file_name_format_ = "nvd-{}.json"
    _csum_file_name_format_ = "nvd-{}.json.sha256sum"
    _cpe_file_ = "official-cpe-dictionary_v2.3.xml"
    _start_year_ = 2002
    _sha_regex_ = re.compile(r"^sha256:.*")
    _tag_pattern_ = re.compile(r"\{.*\}(.*)")
    _normalized_dir_ = "normalized"

    def __init__(self, workspace, logger, download_timeout=None, start_year=None, end_year=None):
        self.workspace = workspace
        self.download_timeout = download_timeout if download_timeout else self._download_timeout_
        self.start_year = start_year if start_year and isinstance(start_year, int) else self._start_year_
        self.end_year = end_year if end_year and isinstance(end_year, int) else datetime.datetime.now().year
        self.hmap = None
        self.logger = logger
        self._urls = set()

    @property
    def urls(self) -> List[str]:
        return list(self._urls)

    def _download_cpe_dict(self):
        xml_file_path = os.path.join(self.workspace, self._cpe_file_)
        return NVDCPEDictionaryUtils.download_v23(xml_file_path, self.download_timeout)

    def _download(self, year, skip_if_exists=False):
        json_file_path = os.path.join(self.workspace, self._data_file_name_format_.format(year))
        csum_file_path = os.path.join(self.workspace, self._csum_file_name_format_.format(year))

        url = self._url_format_.format(year)
        meta_url = self._meta_url_format_.format(year)

        self._urls.add(url)
        self._urls.add(meta_url)

        if skip_if_exists and os.path.exists(json_file_path) and os.path.exists(csum_file_path):
            self.logger.warning(
                "'skip_if_exists' flag enabled and found source under {}. Skipping download".format(json_file_path)
            )
        else:
            do_fetch = True

            # compare checksums of downloaded content with latest data
            if os.path.exists(csum_file_path):
                stored_csum = None
                server_csum = None

                with open(csum_file_path, "r") as f:
                    stored_csum = f.readline()

                self.logger.debug("downloading content checksum from: {}".format(url))
                r = requests.get(meta_url, timeout=self.download_timeout)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if self._sha_regex_.match(line):
                            server_csum = line
                            break
                else:
                    self.logger.warn(
                        "ignoring checksum comparison due to {} HTTP error downloading metadata from {}".format(
                            meta_url, r.status_code
                        )
                    )

                if stored_csum and server_csum and stored_csum.upper() == server_csum.upper():
                    self.logger.debug("stored csum matches server csum, skip downloading: " + str(url))
                    do_fetch = False

            # download latest content if necessary
            if do_fetch:
                try:
                    sha256csum = hashlib.sha256()
                    decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
                    self.logger.info("downloading NVD content from {}".format(url))
                    r = requests.get(url, stream=True, timeout=self.download_timeout)
                    if r.status_code == 200:
                        self.logger.debug("saving content to: {}".format(json_file_path))
                        with open(json_file_path, "wb") as fp:
                            for chunk in r.iter_content(chunk_size=1024):
                                ungzbuf = decompressor.decompress(chunk)
                                fp.write(ungzbuf)
                                sha256csum.update(ungzbuf)

                        self.logger.debug("saving checksum to: {}".format(csum_file_path))
                        check_sum = str(sha256csum.hexdigest()).upper()
                        with open(csum_file_path, "w") as fp:
                            fp.write("sha256:{}".format(check_sum))
                    else:
                        raise Exception("downloading {} failed with {} HTTP error".format(url, r.status_code))
                except:
                    self.logger.exception("error downloading NVD data")
                    raise

        return json_file_path, csum_file_path

    @staticmethod
    def _floater(event):
        if event[1] == "number" and isinstance(event[2], Decimal):
            return event[0], event[1], float(event[2])
        else:
            return event

    @staticmethod
    def _get_affected_versions(vendor_data, vendor_name, product_name):
        """
        Returns affected versions from vendor data which is in the following format:

        :param vendor_data:
        :param vendor_name:
        :param product_name:
        :return:
        """

        affected_versions = {}
        # is_complete = False

        vd_item = next(
            (vd for vd in vendor_data if vd.get("vendor_name", None) == vendor_name),
            None,
        )
        if not vd_item:
            # logger.warn('No vendor data element found for {}'.format(vendor_name))
            return affected_versions

        pd_item = next(
            (pd for pd in vd_item.get("product", {}).get("product_data", []) if pd.get("product_name") == product_name),
            None,
        )
        if not pd_item:
            # logger.warn('No product data found for {}'.format(product_name))
            return affected_versions

        vd_items = pd_item.get("version", {}).get("version_data", [])
        if not vd_items or not isinstance(vd_items, list):
            return affected_versions

        affected_versions = {vd_item.get("version_value") for vd_item in vd_items if vd_item.get("version_affected", None) == "="}

        return affected_versions

    def _get_cpes_from_node(self, node, vendor_data, cpe_set, affected_tuple_set, hmap):
        for child in node.get("children", []):
            self._get_cpes_from_node(child, vendor_data, cpe_set, affected_tuple_set, hmap)

        # "cpe_match" : [
        #   {
        #     "vulnerable" : true,
        #     "cpe23Uri" : "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
        #     "versionStartIncluding" : "7.0.0",
        #     "versionEndIncluding" : "7.0.93"
        #   },
        #   {
        #     "vulnerable" : true,
        #     "cpe23Uri" : "cpe:2.3:a:apache:tomcat:9.0.0:m1:*:*:*:*:*:*"
        #   },
        #   ...
        # ]

        if vendor_data is None:
            vendor_data = {}

        for cpe_obj in node.get("cpe_match", []):
            try:
                if cpe_obj.get("vulnerable", None):
                    if cpe_obj.get("cpe23Uri", None):  # hacky translation to 2.2
                        cpe23_fs = cpe_obj["cpe23Uri"]

                        if any(
                            range_str in cpe_obj
                            for range_str in [
                                "versionStartIncluding",
                                "versionStartExcluding",
                                "versionEndIncluding",
                                "versionEndExcluding",
                            ]
                        ):
                            # get a base CPE object first
                            base_cpe = CPE.from_cpe23_fs(cpe23_fs)

                            if not (base_cpe.vendor, base_cpe.product) in affected_tuple_set:
                                affected_versions = self._get_affected_versions(vendor_data, base_cpe.vendor, base_cpe.product)

                                for aver in affected_versions:
                                    aver_cpe = base_cpe.copy()
                                    aver_cpe.update_version(aver)
                                    cpe_set.add(aver_cpe.as_cpe23_fs())

                                affected_tuple_set.add((base_cpe.vendor, base_cpe.product))

                            cpe_set.update(NVDCPEDictionaryUtils.expand_versions(cpe_obj, base_cpe, hmap))
                        else:
                            cpe_set.add(cpe23_fs)

                    elif cpe_obj.get("cpe22Uri", None):
                        self.logger.warn("found a cpe22uri {}".format(cpe_obj))
                        # cpe_set.add(cpe_obj['cpe22Uri'])
                    else:
                        self.logger.warn("no CPE string in {}".format(cpe_obj))

                else:
                    # logger.warn('Found a not-vulnerable cpe, ignoring')
                    pass
            except:
                self.logger.exception("failed to process cpe_match object: {}".format(cpe_obj))

    def _parse_cvss_v3(self, baseMetricV3):
        """
        Input format
          {
            "cvssV3": {
              "version": "",
              "vectorString": "",
              "attackVector": "",
              "attackComplexity": "",
              "privilegesRequired": "",
              "userInteraction": "",
              "scope": "",
              "confidentialityImpact": "",
              "integrityImpact": "",
              "availabilityImpact": "",
              "baseScore": "",
              "baseSeverity": "",
              "exploitCodeMaturity": "",
              "remediationLevel": "",
              "reportConfidence": "",
              "temporalScore": "",
              "temporalSeverity": "",
              "confidentialityRequirement": "",
              "integrityRequirement": "",
              "availabilityRequirement": "",
              "modifiedAttackVector": "",
              "modifiedAttackComplexity": "",
              "modifiedPrivilegesRequired": "",
              "modifiedUserInteraction": "",
              "modifiedScope": "",
              "modifiedConfidentialityImpact": "",
              "modifiedIntegrityImpact": "",
              "modifiedAvailabilityImpact": "",
              "environmentalScore": "",
              "environmentalSeverity": ""
            },
            "exploitabilityScore": "",
            "impactScore": ""
          }

        :param baseMetricV3:
        :return:
        """
        if not baseMetricV3:
            return None

        new_cvss_v3 = None
        cvssV3 = baseMetricV3.get("cvssV3", {})

        if baseMetricV3 and cvssV3:
            new_cvss_v3 = {
                "version": cvssV3.get("version", "3.0"),
                "vector_string": cvssV3.get("vectorString", None),
                "base_metrics": {
                    "attack_vector": cvssV3.get("attackVector", None),
                    "attack_complexity": cvssV3.get("attackComplexity", None),
                    "privileges_required": cvssV3.get("privilegesRequired", None),
                    "user_interaction": cvssV3.get("userInteraction", None),
                    "scope": cvssV3.get("scope", None),
                    "confidentiality_impact": cvssV3.get("confidentialityImpact", None),
                    "integrity_impact": cvssV3.get("integrityImpact", None),
                    "availability_impact": cvssV3.get("availabilityImpact", None),
                    "base_score": cvssV3.get("baseScore", None),
                    "exploitability_score": baseMetricV3.get("exploitabilityScore", None),
                    "impact_score": baseMetricV3.get("impactScore", None),
                    "base_severity": cvssV3.get("baseSeverity").lower().capitalize()
                    if cvssV3.get("baseSeverity", None)
                    else None,
                },
            }

            if any(
                cvssV3.get(item, None)
                for item in [
                    "exploitCodeMaturity",
                    "remediationLevel",
                    "reportConfidence",
                    "temporalScore",
                    "temporalSeverity",
                ]
            ):
                new_cvss_v3["temporal_metrics"] = {
                    "exploit_code_maturity": cvssV3.get("exploitCodeMaturity", None),
                    "remediation_level": cvssV3.get("remediationLevel", None),
                    "report_confidence": cvssV3.get("reportConfidence", None),
                    "temporal_score": cvssV3("temporalScore", None),
                    "temporal_severity": cvssV3("temporalSeverity").lower().capitalize()
                    if cvssV3("temporalSeverity", None)
                    else None,
                }

            if any(
                cvssV3.get(item, None)
                for item in [
                    "confidentialityRequirement",
                    "integrityRequirement",
                    "availabilityRequirement",
                    "modifiedAttackVector",
                    "modifiedAttackComplexity",
                    "modifiedPrivilegesRequired",
                    "modifiedUserInteraction",
                    "modifiedScope",
                    "modifiedConfidentialityImpact",
                    "modifiedIntegrityImpact",
                    "modifiedAvailabilityImpact",
                    "environmentalScore",
                    "environmentalSeverity",
                ]
            ):
                new_cvss_v3["environmental_metrics"] = {
                    "confidentiality_requirement": cvssV3("confidentialityRequirement", None),
                    "integrity_requirement": cvssV3("integrityRequirement", None),
                    "availability_requirement": cvssV3("availabilityRequirement", None),
                    "modified_attack_vector": cvssV3("modifiedAttackVector", None),
                    "modified_attack_complexity": cvssV3("modifiedAttackComplexity", None),
                    "modified_privileges_required": cvssV3("modifiedPrivilegesRequired", None),
                    "modified_user_interaction": cvssV3("modifiedUserInteraction", None),
                    "modified_scope": cvssV3("modifiedScope", None),
                    "modified_confidentiality_impact": cvssV3("modifiedConfidentialityImpact", None),
                    "modified_integrity_impact": cvssV3("modifiedIntegrityImpact", None),
                    "modified_availability_impact": cvssV3("modifiedAvailabilityImpact", None),
                    "environmental_score": cvssV3("environmentalScore", None),
                    "environmental_severity": cvssV3("environmentalSeverity").lower().capitalize()
                    if cvssV3("environmentalSeverity", None)
                    else None,
                }

        return new_cvss_v3

    def _parse_cvss_v2(self, baseMetricV2):
        """
        Input format
          {
            "cvssV2": {
              "version": "",
              "vectorString": "",
              "accessVector": "",
              "accessComplexity": "",
              "authentication": "",
              "confidentialityImpact": "",
              "integrityImpact": "",
              "availabilityImpact": "",
              "baseScore": "",
              "exploitability": "",
              "remediationLevel": "",
              "reportConfidence": "",
              "temporalScore": "",
              "collateralDamagePotential": "",
              "targetDistribution": "",
              "confidentialityRequirement": "",
              "integrityRequirement": "",
              "availabilityRequirement": "",
              "environmentalScore": ""
            },
            "severity": "",
            "exploitabilityScore": "",
            "impactScore": "",
            "acInsufInfo": "",
            "obtainAllPrivilege": "",
            "obtainUserPrivilege": "",
            "obtainOtherPrivilege": "",
            "userInteractionRequired": ""
          }
        :return:
        """
        if not baseMetricV2:
            return None

        cvssV2 = baseMetricV2.get("cvssV2", {})
        new_cvss_v2 = None

        if baseMetricV2 and cvssV2:
            new_cvss_v2 = {
                "version": cvssV2.get("version", "1.0"),
                "vector_string": cvssV2.get("vectorString", None),
                "severity": baseMetricV2.get("severity").lower().capitalize() if baseMetricV2.get("severity", None) else None,
                "base_metrics": {
                    "access_vector": cvssV2.get("accessVector", None),
                    "access_complexity": cvssV2.get("accessComplexity", None),
                    "authentication": cvssV2.get("authentication", None),
                    "confidentiality_impact": cvssV2.get("confidentialityImpact", None),
                    "integrity_impact": cvssV2.get("integrityImpact", None),
                    "availability_impact": cvssV2.get("availabilityImpact", None),
                    "base_score": cvssV2.get("baseScore", None),
                    "exploitability_score": baseMetricV2.get("exploitabilityScore", None),
                    "impact_score": baseMetricV2.get("impactScore", None),
                },
            }

            if any(cvssV2.get(item, None) for item in ["exploitability" "remediationLevel" "reportConfidence" "temporalScore"]):
                new_cvss_v2["temporal_metrics"] = {
                    "exploitability": cvssV2.get("exploitability"),
                    "remediation_level": cvssV2.get("remediationLevel"),
                    "report_confidence": cvssV2.get("reportConfidence"),
                    "temporal_score": cvssV2.get("temporalScore"),
                }

            if any(
                cvssV2.get(item, None)
                for item in [
                    "collateralDamagePotential",
                    "targetDistribution",
                    "confidentialityRequirement",
                    "integrityRequirement",
                    "availabilityRequirement",
                    "environmentalScore",
                ]
            ):
                new_cvss_v2["environmental_metrics"] = {
                    "collateral_damage_potential": cvssV2.get("collateralDamagePotential"),
                    "target_distribution": cvssV2.get("targetDistribution"),
                    "confidentiality_requirement": cvssV2.get("confidentialityRequirement"),
                    "integrity_requirement": cvssV2.get("integrityRequirement"),
                    "availability_requirement": cvssV2.get("availabilityRequirement"),
                    "environmental_score": cvssV2.get("environmentalScore"),
                }

            if any(
                item in baseMetricV2
                for item in [
                    "acInsufInfo",
                    "obtainAllPrivilege",
                    "obtainUserPrivilege",
                    "obtainOtherPrivilege",
                    "userInteractionRequired",
                ]
            ):
                new_cvss_v2["additional_information"] = {
                    "ac_insuf_info": baseMetricV2.get("acInsufInfo", None),
                    "obtain_all_privilege": baseMetricV2.get("obtainAllPrivilege", None),
                    "obtain_user_privilege": baseMetricV2.get("obtainUserPrivilege", None),
                    "obtain_other_privilege": baseMetricV2.get("obtainOtherPrivilege", None),
                    "user_interaction_required": baseMetricV2.get("userInteractionRequired", None),
                }

        return new_cvss_v2

    def _parse_references(self, refs):
        """
        Input format
          [
            {
              "url": "http://www.securityfocus.com/bid/106669",
              "name": "106669",
              "refsource": "BID",
              "tags": [
                "Third Party Advisory"
              ]
            },
            {
              "url": "https://kb.juniper.net/JSA10901",
              "name": "https://kb.juniper.net/JSA10901",
              "refsource": "CONFIRM",
              "tags": [
                "Vendor Advisory"
              ]
            },
            ...
          ]
        :param refs:
        :return:
        """
        if refs is None:
            refs = []

        mod_refs = [
            {
                "url": ref.get("url", None),
                "source": ref.get("refsource", None),
                "tags": ref.get("tags", []),
            }
            for ref in refs
        ]

        return mod_refs

    def _process_cve_item(self, item, hmap):
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", None)
        self.logger.trace(f"processing {cve_id}")

        vendor_data = item.get("cve", {}).get("affects", {}).get("vendor", {}).get("vendor_data", [])
        cpe_set = set()
        affected_tuple_set = set()
        # cvss2 = {}
        # # configs = []
        # summary = None

        # make up the vulnerable-software-list
        # for node in item.get("configurations", {}).get("nodes", []):
        #     self._get_cpes_from_node(node, vendor_data, cpe_set, affected_tuple_set, hmap)

        # free the memory occupied by affected tuple set0
        affected_tuple_set.clear()

        cpe_list = list(cpe_set)
        cpe_list.sort()
        item.update({"vulnerable_cpes": cpe_list})

        # process references
        refs = item.get("cve", {}).pop("references", {})
        item.update({"external_references": self._parse_references(refs.get("reference_data", []))})

        # process cvss v2 and v3 dictionaries
        impact = item.pop("impact", {})
        baseMetricV3 = impact.pop("baseMetricV3", {}) if impact else {}  # pop the metric and overhaul it
        baseMetricV2 = impact.pop("baseMetricV2", {}) if impact else {}  # pop the metric and overhaul it
        cvss_v3 = self._parse_cvss_v3(baseMetricV3)
        cvss_v2 = self._parse_cvss_v2(baseMetricV2)

        item.update({"cvss_v2": cvss_v2, "cvss_v3": cvss_v3})

        # update severity
        sev = None
        if cvss_v3:
            sev = cvss_v3.get("base_metrics", {}).get("base_severity", None)
        elif cvss_v2:
            sev = cvss_v2.get("severity", None)

        item.update({"severity": sev if sev else "Unknown"})

        return cve_id, item

    def _normalize(self, file_path, hmap):
        """
        :param file_path: string representing path to json file
        :return:
        """
        self.logger.debug("normalizing data from: {}".format(file_path))

        with open(file_path, "rb") as f:
            events = map(self._floater, ijpython.parse(f))
            for item in ijcommon.items(events, "CVE_Items.item"):
                try:
                    yield self._process_cve_item(item, hmap)
                except:
                    self.logger.exception("failed to process CVE_Items.item")
                    continue

    def _load_from_cache(self, year, skip_if_exists=False):
        ts = datetime.datetime.utcnow().isoformat()
        normalized_dir_path = os.path.join(self.workspace, self._normalized_dir_)
        if not os.path.exists(normalized_dir_path):
            self.logger.debug(
                "initializing normalized workspace directory for {}/{} driver at {}".format(
                    feedtype, namespace, normalized_dir_path
                )
            )
            os.makedirs(normalized_dir_path)

        use_cache = False

        # Download data
        d_json_file_path, d_csum_file_path = self._download(year, skip_if_exists)

        n_json_file_path = os.path.join(normalized_dir_path, self._data_file_name_format_.format(year))
        n_csum_file_path = os.path.join(normalized_dir_path, self._csum_file_name_format_.format(year))

        # check for normalized data and if csums match
        if os.path.exists(n_json_file_path) and os.path.exists(n_csum_file_path) and os.path.exists(d_csum_file_path):
            with open(d_csum_file_path, "r") as dp, open(n_csum_file_path, "r") as np:
                d_csum = dp.readline()
                n_csum = np.readline()

            use_cache = d_csum == n_csum

        if use_cache:
            self.logger.debug("cache hit for normalized data, loading from: {}".format(n_json_file_path))
            with open(n_json_file_path, "rb") as f:
                events = map(self._floater, ijpython.parse(f))
                for item in ijcommon.items(events, "normalized_data.item"):
                    try:
                        cve_id = item["id"]
                        self.logger.trace(f"read cached entry for {cve_id}")
                        yield cve_id, item["payload"]
                    except:
                        self.logger.exception("failed to process normalized_data.item")
                        continue
        else:
            self.logger.debug("cache missed for normalized data")
            hmap = self._get_cpe_dictionary()

            n_data = []

            # normalize data and hold it in memory to cache
            for cve_id, cve in self._normalize(d_json_file_path, hmap):
                n_data.append({"id": cve_id, "payload": cve})
                yield cve_id, cve

            self.logger.debug("caching normalized data to: {}".format(n_json_file_path))
            with open(n_json_file_path, "w") as np:
                json.dump({"generated_at": ts, "normalized_data": n_data}, np)
            del n_data[:]  # clear it

            self.logger.debug("writing normalized data checksum to: {}".format(n_csum_file_path))
            with open(d_csum_file_path, "r") as dp, open(n_csum_file_path, "w") as np:
                d_csum = dp.readline()
                np.write(d_csum)

    def _get_cpe_dictionary(self):

        if not self.hmap:
            # Download and normalize the cpe dictionary
            xml_file_path = self._download_cpe_dict()
            self.hmap = NVDCPEDictionaryUtils.load_to_map(xml_file_path)

        return self.hmap

    def _free_cpe_dictionary(self):
        # free up the memory held by this giant dictionary
        self.logger.debug("freeing cpe dictionary")
        if self.hmap:
            self.hmap.clear()
            del self.hmap

    def get(self, skip_if_exists=False):
        try:
            for year in range(self.start_year, self.end_year + 1):
                for cve_id, cve in self._load_from_cache(year, skip_if_exists):
                    yield cve_id, cve
        finally:
            try:
                self._free_cpe_dictionary()
            except Exception as e:
                self.logger.debug("ignoring error clearing cpe dictionary. {}".format(e))
