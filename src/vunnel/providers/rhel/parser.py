from __future__ import annotations

import concurrent.futures
import copy
import logging
import os
import re
from collections import namedtuple
from datetime import datetime as dt
from decimal import Decimal as D
from typing import TYPE_CHECKING

import orjson
from cvss import CVSS3
from dateutil import parser as dt_parser

from vunnel import utils
from vunnel.providers.rhel.rhsa_provider import AffectedRelease, CSAFRHSAProvider, OVALRHSAProvider
from vunnel.utils import http_wrapper as http
from vunnel.utils import rpm
from vunnel.utils.vulnerability import vulnerability_element

if TYPE_CHECKING:
    import requests

    from .rhsa_provider import RHSAProvider

namespace = "rhel"


FixedIn = namedtuple("FixedIn", ["package", "platform", "version", "module", "advisory"])
RHSAFixedIn = namedtuple("RHSAFixedIn", ["package", "version"])
Advisory = namedtuple("Advisory", ["wont_fix", "rhsa_id", "link", "severity"])
NamespacePayload = namedtuple("NamespacePayload", ["namespace", "payload"])


class Parser:
    __cve_rhel_product_name_base__ = "Red Hat Enterprise Linux"
    __rhel_release_pattern__ = re.compile(__cve_rhel_product_name_base__ + r"\s*(\d+)$")
    __rhel_eus_pattern__ = re.compile(r"Red Hat Enterprise Linux (\d+\.\d+) Extended Update Support")
    __summary_url__ = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    __rhsa_url__ = "https://access.redhat.com/hydra/rest/securitydata/oval/{}.json"
    __last_synced_filename__ = "last_synced"
    __cve_download_error_filename__ = "failed_cves"
    __cve_filename_regex__ = re.compile("CVE-[0-9]+-[0-9]+")
    __source_dir_name__ = "source"
    __rhsa_dir_name__ = "rhsa"
    __cve_dir_name__ = "cve"
    __min_dir_name__ = "min"
    __min_pages_dir_name__ = "min_pages"
    __full_dir_name__ = "full"
    __last_full_sync_filename__ = "last_full_sync"

    def __init__(  # noqa: PLR0913
        self,
        workspace,
        download_timeout=None,
        max_workers=None,
        full_sync_interval=None,
        skip_namespaces=None,
        rhsa_provider_type=None,
        logger=None,
        skip_download: bool = False,
    ):
        self.workspace = workspace
        self.cve_dir_path = os.path.join(workspace.input_path, self.__cve_dir_name__)
        self.rhsa_dir_path = os.path.join(workspace.input_path, self.__rhsa_dir_name__)
        self.download_timeout = download_timeout if isinstance(download_timeout, int) else 125
        self.max_workers = max_workers if isinstance(max_workers, int) else 4
        self.full_sync_interval = full_sync_interval if isinstance(full_sync_interval, int) else 2
        self.skip_namespaces = skip_namespaces if isinstance(skip_namespaces, list) else ["rhel:3", "rhel:4"]
        self.rhsa_dict = None
        self.rhsa_provider: RHSAProvider | None = None
        self.rhsa_provider_type: str | None = rhsa_provider_type
        self.skip_download = skip_download

        self.urls = [self.__summary_url__]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download_minimal_cves(self, page, limit=1000):
        path_params = {"per_page": str(limit), "page": page, "product": self.__cve_rhel_product_name_base__}

        self.logger.info(
            f"downloading CVE list from url={self.__summary_url__} count={path_params['per_page']} page={path_params['page']}, product={path_params['product']}",  # noqa: E501
        )
        r = http.get(
            self.__summary_url__,
            self.logger,
            params=path_params,
            timeout=self.download_timeout,
        )

        return r.json()

    def _process_minimal_cve(self, min_cve_api, do_full_sync, min_cve_dir, full_cve_dir):
        """
        worker that checks if a download is necessary and then does it

        :param min_cve_api: api result describing a CVE, including the URLfor a full download
        :param do_full_sync: bool: assume cache is stale and re-download everything
        :param min_cve_dir: directory to save minimal cve API results
        :param full_cve_dir: directory to save full cve data
        :return:
        """
        cve_id = min_cve_api.get("CVE")
        if not cve_id:
            raise ValueError("Invalid CVE ID")

        url = min_cve_api.get("resource_url")
        if not url:
            raise ValueError("Invalid CVE url")

        download = True  # always download the cve unless its absolutely unnecessary
        min_cve_file = os.path.join(min_cve_dir, cve_id)
        full_cve_file = os.path.join(full_cve_dir, cve_id)

        try:
            if not do_full_sync and os.path.exists(min_cve_file) and os.path.exists(full_cve_file):
                with open(min_cve_file, encoding="utf-8") as fp:  # load minimal cve from disk
                    min_cve_fs = orjson.loads(fp.read())
                if min_cve_fs == min_cve_api:  # only case where a download is not necessary
                    download = False
                else:
                    self.logger.debug(f"detected an update for {cve_id}")
                    download = True

            if download:
                # download the full CVE
                self._download_entity(url, full_cve_file)

                # save minimal to disk
                with open(min_cve_file, "wb") as fp:
                    fp.write(orjson.dumps(min_cve_api))

            return download
        except Exception as e:
            self.logger.error(f"error downloading and saving {cve_id} to fs: {e}")
            # self.logger.debug(f"reset fs state for {cve_id}")
            utils.silent_remove(min_cve_file)
            utils.silent_remove(full_cve_file)
            raise  # raise the original exception

    def _download_minimal_cve_pages(self) -> int:
        dir_path = os.path.join(self.cve_dir_path, self.__min_pages_dir_name__)

        # clear all existing records
        utils.silent_remove(dir_path, tree=True)
        os.makedirs(dir_path)

        page = 0
        count = 0
        while True:
            page += 1
            results = self._download_minimal_cves(page)

            if not isinstance(results, list) or not results:
                break

            min_cve_file = os.path.join(dir_path, f"{page}.json")

            count += len(results)

            with open(min_cve_file, "wb") as fp:
                fp.write(orjson.dumps(results))

        return count

    def enumerate_minimal_cve_pages(self):
        dir_path = os.path.join(self.cve_dir_path, self.__min_pages_dir_name__)

        for file in os.listdir(dir_path):
            if file.endswith(".json"):
                with open(os.path.join(dir_path, file), encoding="utf-8") as fp:
                    yield orjson.loads(fp.read())

    # TODO: ALEX, should skip_if_exists be hooked up here? (currently unused)
    def _sync_cves(self, skip_if_exists=False, do_full_sync=True):  # noqa: PLR0915, PLR0912, C901
        """
        Download minimal or summary cve and compare it to persisted state on disk. If no persisted state is found or a
        a change is detected, full cve is downloaded

        Minimal CVE summary captures high level information such as advisories and fixed packages.
        But its not complete (affected packages missing). So it *might* work for a quick check to find out if
        a full download of the cve is necessary. This is the only way to avoid downloading every CVE, which adds up
        way too many network round trips
        :return:
        """

        now = dt.utcnow()  # noqa: DTZ003

        # setup workspace for full cves
        full_cve_dir = os.path.join(self.cve_dir_path, self.__full_dir_name__)
        if not os.path.exists(full_cve_dir):
            self.logger.debug(f"creating workspace for cve source data at {full_cve_dir}")
            os.makedirs(full_cve_dir)

        # setup workspace for min cves
        min_cve_dir = os.path.join(self.cve_dir_path, self.__min_dir_name__)
        if not os.path.exists(min_cve_dir):
            self.logger.debug(f"creating workspace for cve source data at {min_cve_dir}")
            os.makedirs(min_cve_dir)

        # check if a full sync is necessary, default to always doing it
        last_full_sync_file = os.path.join(self.cve_dir_path, self.__last_full_sync_filename__)
        try:
            if os.path.exists(last_full_sync_file):
                with open(last_full_sync_file, encoding="utf-8") as fp:
                    last_full_sync = dt_parser.parse(fp.read())
                if (now - last_full_sync).days < self.full_sync_interval:
                    do_full_sync = False
        except Exception:
            self.logger.debug("ignoring error loading last_full_sync timestamp from disk", exc_info=True)
            do_full_sync = True

        if do_full_sync:
            self.logger.info("full sync triggered, downloading all CVEs.  This may take quite some time.")
        else:
            self.logger.info("incremental sync triggered, computing and downloading updated CVEs")

        # clean up old source dir if its around
        utils.silent_remove(
            os.path.join(self.cve_dir_path, self.__source_dir_name__),
            tree=True,
        )
        utils.silent_remove(os.path.join(self.cve_dir_path, self.__last_synced_filename__))
        utils.silent_remove(os.path.join(self.cve_dir_path, self.__cve_download_error_filename__))

        count = self._download_minimal_cve_pages()

        self.logger.info(f"downloading and processing {count} CVEs")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            download_count = 0
            api_cve_set = set()  # definitive set of cves
            error = False

            for results in self.enumerate_minimal_cve_pages():
                future_cve_dict = {
                    executor.submit(
                        self._process_minimal_cve,
                        min_cve_api=result,
                        do_full_sync=do_full_sync,
                        min_cve_dir=min_cve_dir,
                        full_cve_dir=full_cve_dir,
                    ): result.get("CVE")
                    for result in results
                }

                for future in concurrent.futures.as_completed(future_cve_dict):
                    cve_id = future_cve_dict[future]

                    before = len(api_cve_set)

                    api_cve_set.add(cve_id)  # add to api set

                    if len(api_cve_set) == before:  # duplicate cve id
                        self.logger.warning(
                            f"duplicate cve id {cve_id} found from api response (this is a known issue with the upstream API)",
                        )

                    try:
                        download = future.result()
                    except Exception:
                        self.logger.exception(f"ignoring error processing minimal {cve_id}. May retry on next iteration")
                    else:
                        if download:
                            download_count += 1

        self.logger.info(f"total number of cves listed by api: {len(api_cve_set)}, downloaded this iteration: {download_count}")

        # save full sync timestamp
        if do_full_sync:
            try:
                with open(last_full_sync_file, "w", encoding="utf-8") as fp:
                    fp.write(now.isoformat())
            except Exception:
                self.logger.debug("ignoring error saving last_full_sync timestamp to disk", exc_info=True)

        # reconcile cves after processing only if there were no errors, remove any that are no longer listed
        if not error:
            try:
                self.logger.debug("attempting to reconcile api cves with fs")

                fs_min_cve_set = set(os.listdir(min_cve_dir))
                for item in fs_min_cve_set.difference(api_cve_set):
                    file = os.path.join(min_cve_dir, item)
                    self.logger.debug(f"{item!r} no longer reported by api, deleting min content {file}")
                    os.remove(file)

                fs_full_cve_set = set(os.listdir(full_cve_dir))
                for item in fs_full_cve_set.difference(api_cve_set):
                    file = os.path.join(full_cve_dir, item)
                    self.logger.debug(f"{item!r} no longer reported by api, deleting full content {file}")
                    os.remove(file)

                if api_cve_set.difference(fs_min_cve_set):
                    self.logger.warning(
                        f"CVEs reported by api missing min content on fs: {api_cve_set.difference(fs_min_cve_set)}",
                    )

                if api_cve_set.difference(fs_full_cve_set):
                    self.logger.warning(
                        f"CVEs reported by api missing full content on fs: {api_cve_set.difference(fs_min_cve_set)}",
                    )
            except Exception:
                self.logger.debug("ignoring errors reconciling api cves with fs content", exc_info=True)

        return full_cve_dir

    def _download_entity(self, url, destination):
        def status_handler(r: requests.Response):
            if r.status_code not in [200, 404]:
                r.raise_for_status()

        r = http.get(url, self.logger, status_handler=status_handler, timeout=self.download_timeout)

        if r.status_code == 200:
            with open(destination, "w", encoding="utf-8") as fp:
                fp.write(r.text)
        elif r.status_code == 404:
            self.logger.warning(f"GET {url} returned 404 not found error")

    def _fetch_rhsa_fix_version(self, cve_id: str, ar_obj: AffectedRelease, override_package_name: str | None = None):
        """Fetch RHSA information, either from OVAL parsing or CSAF parsing depending
        on configuration."""
        # TODO: this needs to call one of the two RHSA providers, but they want slighly different things
        # get_fixed_version_and_module shuold just take an AffectedRelease object and a package name

        return self.rhsa_provider.get_fixed_version_and_module(cve_id, ar_obj, override_package_name)

    def _fetch_rhsa(self, rhsa_id, platform):
        if self.rhsa_dict is not None:  # explicit check to allow for easy testing without actually initializing it
            _, p = self.rhsa_dict.get((rhsa_id, platform), (None, None))
        else:
            raise Exception("RHSA data not initialized")
        return p

    def _init_rhsa_data(self, skip_if_exists=False):
        self.logger.info(f"instantiating RHSA provider of type {self.rhsa_provider_type}")
        if self.rhsa_provider_type.lower() == "oval":
            if self.skip_download:
                self.logger.warning("skip download requested, but OVAL RHSA provider does not support skipping download")
            self.rhsa_provider = OVALRHSAProvider(self.workspace, self.download_timeout, self.logger, self.rhsa_dir_path)
        elif self.rhsa_provider_type.lower() == "csaf":
            self.rhsa_provider = CSAFRHSAProvider(self.workspace, self.download_timeout, self.logger, self.skip_download)

    @staticmethod
    def _get_name_version(package):
        """
        A best effort to parse name and version from package string

        Package strings in cve data come in a wide variety of formats and not standardized in the least
        - app streams versions such as foo-bar:rhel8-12345
        - newer package versions as per rpm spec with epoch stuck in the middle foo-bar-1:2.3.4-5.el6_7.8
        - older cves with epoch in the beginning 1:foo-bar-2.3.4-5.el6_7.8 or no epoch foo-bar-2.3.4-5.el6_7.8

        Official rpm filename convention:
        name-version-release.architecture.rpm

        """
        name = None
        version = None

        if not package or not isinstance(package, str):
            return name, version

        if ":" in package:  # tread very carefully, epoch or app streams ahead
            colon_comps = package.split(":", 1)

            if colon_comps[0].isdigit():  # epoch in the beginning 1:foo-bar-2.3.4-5.el6_7.8
                name_other_comps = colon_comps[1].rsplit("-", 2)  # split name-version-release.arch.rpm into max 3 chunks
                name = name_other_comps[0]  # only the name matters
                if len(name_other_comps) > 1:  # defaults to rhsa lookup otherwise
                    version = colon_comps[0] + ":" + "-".join(name_other_comps[1:])  # join the rest
            else:
                name_comps = colon_comps[0].rsplit("-", 1)
                if len(name_comps) > 1 and name_comps[1].isdigit():  # epoch in the middle foo-bar-1:2.3.4-5.el6_7.8
                    name = name_comps[0]
                    version = name_comps[1] + ":" + colon_comps[1]
                else:  # not compliant with rpm filename spec, could be an app stream
                    name = colon_comps[0]  # best guess for name, fall back to rhsa for version lookup

        else:  # no epoch foo-bar-2.3.4-5.el6_7.8 or something else totally different  # noqa: PLR5501
            if package.count("-") >= 2:
                name_other_comps = package.rsplit("-", 2)  # split name-version-release.arch.rpm into max 3 chunks
                name = name_other_comps[0]  # only the name matters
                version = "-".join(name_other_comps[1:])  # join the rest
            else:
                name = package  # best guess for name, fall back to rhsa for version lookup

        return name, version

    def _parse_affected_release(self, cve_id: str, content) -> list[FixedIn]:  # noqa: C901, PLR0912, PLR0915
        """_parse_affected_release handles the affected_release section of the hydra API JSON CVE
        data. If applicable it will ask the parsed OVAL data for the fixed version and module.
        param: cve_id: str: The CVE ID.
        param: content: dict: The JSON data for the CVE."""
        fixed_ins = []
        ars = content.get("affected_release", [])

        # to deal with affected releases missing package-version strings
        platform_packages = {}  # dictionary of platform -> set of package names
        all_ar_objs = []
        # to deal with multiple affected releases for the same platform and package
        final_ar_objs = {}  # dictionary of (package, platform, module) -> AffectedRelease object

        try:
            # first pass to just parse affected releases and construct a list of objects
            for item in ars:
                try:
                    platform = self._parse_platform(item.get("product_name", None))
                    if not platform:
                        continue

                    ar_obj = AffectedRelease(platform=platform)
                    if ar_obj.platform not in platform_packages:
                        platform_packages[ar_obj.platform] = set()
                    ar_obj.platform_cpe = item.get("cpe", None)
                    package = item.get("package", None)
                    if package:
                        ar_obj.package = package
                        ar_obj.name, ar_obj.version = self._get_name_version(package)
                        platform_packages[ar_obj.platform].add(ar_obj.name)
                    else:
                        ar_obj.name = None
                        ar_obj.version = None

                    ar_obj.rhsa_id = item.get("advisory", None)
                    ar_obj.module = None

                    all_ar_objs.append(ar_obj)
                except Exception:
                    self.logger.exception(f"error parsing {cve_id} affected release entity: {item}")

            # second pass to lookup version and guess missing packages using rhsa data
            for ar_obj in all_ar_objs:
                try:
                    if f"{namespace}:{ar_obj.platform}" in self.skip_namespaces:  # no need to process deny-listed platforms
                        continue

                    if ar_obj.name:
                        if ar_obj.rhsa_id:  # rhsa lookup for version information tends to make version consistent
                            rhsa_version, rhsa_module = self._fetch_rhsa_fix_version(cve_id, ar_obj)
                            if rhsa_version:
                                final_v = rhsa_version
                                final_m = rhsa_module
                            else:
                                self.logger.debug(
                                    f"{cve_id}, platform={ar_obj.platform} : no matches found for {ar_obj.rhsa_id} and package={ar_obj.name} Falling back to CVE version {ar_obj.version}",  # noqa: E501
                                )
                                final_v = ar_obj.version
                                final_m = rhsa_module
                        else:
                            self.logger.debug(
                                f"{cve_id}, platform={ar_obj.platform} : no associated RHSA for package={ar_obj.name} Falling back to CVE version {ar_obj.version}",  # noqa: E501
                            )
                            final_v = ar_obj.version
                            final_m = None

                    elif ar_obj.rhsa_id:  # package name missing but there's at least an rhsa ID to go off
                        self.logger.debug(
                            f"{cve_id}, platform={ar_obj.platform} : missing package, trying to find a match using {ar_obj.rhsa_id} and other affected releases",  # noqa: E501
                        )

                        # TODO: doc comment here. What is this line doing? Why is this a good way to get package names?
                        # also note: based on my experimentation, this block is never entered.
                        possible_packages = set().union(*platform_packages.values()).difference(platform_packages[ar_obj.platform])

                        for pkg_name in possible_packages:
                            rhsa_version, rhsa_module = self._fetch_rhsa_fix_version(cve_id, ar_obj, override_package_name=pkg_name)

                            if rhsa_version:
                                self.logger.debug(
                                    f"{cve_id} platform={ar_obj.platform} : found RHSA match package={pkg_name} version={rhsa_version}",
                                )
                                final_v = rhsa_version
                                final_m = rhsa_module

                                platform_packages[ar_obj.platform].add(
                                    pkg_name,
                                )  # add it to guessed package names to avoid repeats
                                ar_obj.name = pkg_name
                                break
                        else:
                            self.logger.debug(
                                f"{cve_id}, platform={ar_obj.platform} : no package name matches found using {ar_obj.rhsa_id} and other affected releases",  # noqa: E501
                            )
                            final_v = None
                            final_m = None
                    else:
                        self.logger.debug(f"{cve_id}, platform={ar_obj.platform} : missing package and RHSA ID")
                        final_v = None
                        final_m = None

                    if not ar_obj.name or not final_v:
                        self.logger.debug(
                            f"{cve_id}, platform={ar_obj.platform} : skipping affected release record as all attempts to deduce package name and or version were futile",  # noqa: E501
                        )
                        continue

                    ar_obj.version = final_v  # store the final_v in the object for future usage
                    ar_obj.module = final_m

                    prev_ar_obj = final_ar_objs.get((ar_obj.name, ar_obj.platform, ar_obj.module), None)
                    if prev_ar_obj:
                        if rpm.compare_versions(prev_ar_obj.version, ar_obj.version) < 0:
                            self.logger.debug(
                                f"{cve_id}, platform={prev_ar_obj.platform}, package={prev_ar_obj.name}, module={prev_ar_obj.module} : multiple fix versions found, {ar_obj.version} > {prev_ar_obj.version}",  # noqa: E501
                            )
                            final_ar_objs[(ar_obj.name, ar_obj.platform, ar_obj.module)] = ar_obj
                        else:
                            self.logger.debug(
                                f"{cve_id}, platform={prev_ar_obj.platform}, package={prev_ar_obj.name}, module={prev_ar_obj.module} : multiple fix versions found, {ar_obj.version} <= {prev_ar_obj.version}",  # noqa: E501
                            )
                    else:
                        final_ar_objs[(ar_obj.name, ar_obj.platform, ar_obj.module)] = ar_obj

                except Exception:
                    self.logger.exception(f"error processing {cve_id} affected release object: {ar_obj.__dict__}")

            # construct the final fixed in objects
            fixed_ins = [
                FixedIn(
                    platform=ar_obj.platform,
                    package=ar_obj.name,
                    version=ar_obj.version,
                    module=ar_obj.module,
                    advisory=(
                        Advisory(
                            wont_fix=False,
                            rhsa_id=ar_obj.rhsa_id,
                            link=f"https://access.redhat.com/errata/{ar_obj.rhsa_id}",
                            severity=None,
                        )
                        if ar_obj.rhsa_id
                        else Advisory(wont_fix=False, rhsa_id=None, link=None, severity=None)
                    ),
                )
                for ar_obj in final_ar_objs.values()
            ]
        finally:
            # free up intermediate data structures
            try:
                platform_packages.clear()
                final_ar_objs.clear()
                del all_ar_objs[:]
                del platform_packages
                del final_ar_objs
                del all_ar_objs
            except Exception:
                self.logger.info("exception freeing up intermediate data structures", exc_info=True)

        return fixed_ins

    def _parse_package_name_and_module(self, item: dict) -> tuple[str | None, str | None]:
        package_name = item.get("package_name")
        module = None

        if package_name and "/" in package_name:
            components = package_name.split("/")
            package_name = components[1]
            module = components[0]

        return package_name, module

    def _parse_package_state(self, cve_id: str, content) -> list[FixedIn]:
        affected: list[FixedIn] = []
        out_of_support: list[FixedIn] = []  # Track items out of support to be able to add them if others are affected
        pss = content.get("package_state", [])

        for item in pss:
            try:
                platform = self._parse_platform(item.get("product_name", None))
                if not platform or f"{namespace}:{platform}" in self.skip_namespaces:
                    continue

                package_name, module = self._parse_package_name_and_module(item)

                if not package_name:
                    self.logger.debug(f"package state package_name missing for {cve_id} platform {platform}")
                    continue

                if module and module.endswith(":flatpak"):
                    self.logger.debug(f"skipping flatpak entry {package_name} for {cve_id} platform {platform}")
                    continue

                state = item.get("fix_state", None)
                if state in ["Affected", "Fix deferred"]:
                    affected.append(
                        FixedIn(
                            platform=platform,
                            package=package_name,
                            version="None",
                            module=module,
                            advisory=Advisory(wont_fix=False, rhsa_id=None, link=None, severity=None),
                        ),
                    )
                elif state in ["Will not fix"]:
                    affected.append(
                        FixedIn(
                            platform=platform,
                            package=package_name,
                            version="None",
                            module=module,
                            advisory=Advisory(wont_fix=True, rhsa_id=None, link=None, severity=None),
                        ),
                    )
                elif state in ["Out of support scope"]:
                    out_of_support.append(
                        FixedIn(
                            platform=platform,
                            package=package_name,
                            version="None",
                            module=module,
                            advisory=Advisory(wont_fix=True, rhsa_id=None, link=None, severity=None),
                        ),
                    )
                elif state in [
                    "New",
                    "Not affected",
                    "Under investigation",
                ]:
                    continue
                else:
                    self.logger.debug(f"{state!r} is an unknown state")
                    continue
            except Exception:
                self.logger.exception(f"error parsing {cve_id} package state entity: {item}")

        return affected + out_of_support

    def _parse_platform(self, product_name: str | None) -> str | None:
        is_eus = False
        match = re.match(
            self.__rhel_release_pattern__,
            product_name,
        )
        if not match:
            match = re.match(
                self.__rhel_eus_pattern__,
                product_name,
            )
            if not match:
                return None
            is_eus = True

        platform = match.group(1)
        if platform and is_eus:
            platform = f"{platform}+eus"
        return platform

    def _parse_cvss3(self, cvss3: dict | None) -> RHELCVSS3 | None:
        if not cvss3:
            return None

        vector = cvss3.get("cvss3_scoring_vector", None)
        base_score = cvss3.get("cvss3_base_score", None)

        if not vector or not base_score:
            return None

        try:
            return RHELCVSS3(
                vector,
                base_score,
                cvss3.get("status", None),
            )

        except Exception:
            self.logger.info("unable to make cvss3, defaulting to None", exc_info=True)

        return None

    def _parse_cve(self, cve_id, content):  # noqa: C901, PLR0912, PLR0915
        # logger.debug('Parsing {}'.format(cve_id))

        results = []
        platform_artifacts = {}
        # compute fixed ins from "affected_release" key in JSON + OVAL Parsing
        fins = self._parse_affected_release(cve_id, content)
        # compute "not fixed ins" from "package_state" key in JSON (affected or out of support)
        nfins = self._parse_package_state(cve_id, content)
        platform_package_module_tuples = set()

        if fins or nfins:
            sev = content.get("threat_severity", None)
            if sev:
                sev = sev.lower()
                if sev == "critical":
                    sev = "Critical"
                elif sev == "important":
                    sev = "High"
                elif sev == "moderate":
                    sev = "Medium"
                elif sev == "low":
                    sev = "Low"
                elif sev == "unknown":
                    sev = "Unknown"
                else:
                    sev = "Unknown"
            else:
                sev = "Unknown"

            details = content.get("details", [])
            if details and isinstance(details, list):  # noqa: SIM108
                description = details[-1]
            else:
                description = ""  # leaving this empty to be compatible with some old client side logic that expects it

            cvssv3_obj = self._parse_cvss3(content.get("cvss3", None))

            for item in nfins:  # process not fixed in packages first as that trumps fixes
                if item.platform not in platform_artifacts:
                    platform_artifacts[item.platform] = []

                platform_artifacts[item.platform].append(item)
                platform_package_module_tuples.add((item.platform, item.package, item.module))

            for item in fins:  # process fixed in packages, exclude packages that are still affected
                if (
                    item.platform,
                    item.package,
                    item.module,
                ) in platform_package_module_tuples:
                    self.logger.debug(
                        f"{cve_id}, platform={item.platform}, package={item.package}, module={item.module} : partial fix found but package is still vulnerable. Ignoring fix version {item.version}",  # noqa: E501
                    )
                    continue

                if item.platform not in platform_artifacts:
                    platform_artifacts[item.platform] = []

                platform_artifacts[item.platform].append(item)

            for platform, artifacts in platform_artifacts.items():
                ns = f"{namespace}:{platform}"

                # if len(artifacts) == 1 and artifacts[0].advisory.severity and artifacts[0].advisory.severity != sev:
                #     rel_sev = artifacts[0].advisory.severity
                #     logger.info('{}, overall severity: {}, rhsa severity: {}'.format(cve_id, sev, rel_sev))
                # else:
                #     rel_sev = sev

                v = copy.deepcopy(vulnerability_element)
                v["Vulnerability"]["NamespaceName"] = ns
                v["Vulnerability"]["Severity"] = sev
                v["Vulnerability"]["Name"] = cve_id
                v["Vulnerability"]["Link"] = f"https://access.redhat.com/security/cve/{cve_id}"
                v["Vulnerability"]["Description"] = description
                v["Vulnerability"]["FixedIn"] = []
                if cvssv3_obj:
                    v["Vulnerability"]["CVSS"].append(cvssv3_obj.normalize())

                for artifact in artifacts:
                    if artifact.advisory.wont_fix:
                        a = {"NoAdvisory": True}
                    else:
                        a = {"NoAdvisory": False, "AdvisorySummary": []}
                        if artifact.advisory.rhsa_id and artifact.advisory.link:
                            a["AdvisorySummary"].append(
                                {
                                    "ID": artifact.advisory.rhsa_id,
                                    "Link": artifact.advisory.link,
                                },
                            )

                    v["Vulnerability"]["FixedIn"].append(
                        {
                            "Name": artifact.package,
                            "Version": artifact.version,
                            "Module": artifact.module,
                            "VersionFormat": "rpm",  # hard code version format for now
                            "NamespaceName": ns,
                            "VendorAdvisory": a,
                        },
                    )

                results.append(NamespacePayload(namespace=ns, payload=v))

        return results

    def _process_full_cve(self, cve_id, cve_file_path):
        with open(cve_file_path, encoding="utf-8") as fp:
            content = orjson.loads(fp.read())

        return self._parse_cve(cve_id, content)

    def get(self, skip_if_exists=False):
        try:
            # initialize rhsa data
            self._init_rhsa_data(skip_if_exists=skip_if_exists)

            full_dir = os.path.join(self.cve_dir_path, self.__full_dir_name__)
            if not self.skip_download:
                # download cves
                self._sync_cves(skip_if_exists)

            # normalize cve files
            self.logger.debug(f"normalizing CVEs from {full_dir}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_cve_dict = {
                    executor.submit(
                        self._process_full_cve,
                        cve_id=cve_id,
                        cve_file_path=os.path.join(full_dir, cve_id),
                    ): cve_id
                    for cve_id in sorted(os.listdir(full_dir))
                }

                for future in concurrent.futures.as_completed(future_cve_dict):
                    cve_id = future_cve_dict[future]
                    try:
                        results = future.result()
                        for item in results:
                            yield item.namespace, cve_id, item.payload
                    except Exception:
                        self.logger.exception(f"ignoring error processing {cve_id}. May retry on next iteration")
        finally:
            # clear memory for rhsa dict
            if self.rhsa_dict:
                self.rhsa_dict.clear()
                del self.rhsa_dict


class RHELCVSS3:
    def __init__(self, vector_string, base_score, status):
        if not vector_string or not base_score:
            raise ValueError("vector_string and base_score must be valid")

        self.vector_string = vector_string
        self.base_score = base_score
        self.status = status
        self.cvss3_obj = CVSS3(vector_string)

    def normalize(self):
        return {
            "version": f"3.{self.cvss3_obj.minor_version}",
            "status": self.status,
            "vector_string": self.vector_string,
            "base_metrics": {
                "base_score": float(self.base_score),
                "exploitability_score": float(self.cvss3_obj.esc.quantize(D("0.1"))),
                "impact_score": float(self.cvss3_obj.isc.quantize(D("0.1"))),
                "base_severity": self.cvss3_obj.severities()[0],
            },
        }
