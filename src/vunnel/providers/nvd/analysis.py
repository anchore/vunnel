from __future__ import annotations

import logging
import os
from typing import Any

import orjson

from vunnel.providers.nvd.git import Git
from vunnel.providers.nvd.normalization import generate_candidates, normalize, normalize_collection_url


class CPEPatternLookup:
    def __init__(self, curated_files: list[str], generated_files: list[str], logger: logging.logger=None):
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.cpe_types = ["application", "os", "hardware"]
        self.__lookup_by_collection_url_and_package_name__: dict[str, dict[str, dict[str, list[str]]]] = {}
        self.__lookup_by_vendor_and_product__: dict[str, dict[str, dict[str, list[str]]]] = {}
        self.__lookup_by_product__: dict[str, dict[str, list[str]]] = {}
        self.__load_data__(curated_files, generated_files)

    def __load_data__(self, curated_files: list[str], generated_files: list[str]):
        if not curated_files:
            curated_files = []

        if not generated_files:
            generated_files = []

        for t in self.cpe_types:
            if t not in self.__lookup_by_collection_url_and_package_name__:
                self.__lookup_by_collection_url_and_package_name__[t] = {}
            if t not in self.__lookup_by_vendor_and_product__:
                self.__lookup_by_vendor_and_product__[t] = {}
            if t not in self.__lookup_by_product__:
                self.__lookup_by_product__[t] = {}

        for file in generated_files + curated_files:
            if os.path.exists(file):
                self.logger.trace(f"loading CPE mapping file {file}")
                cpe_type = None
                if file.endswith("/application.json"):
                    cpe_type = "application"
                elif file.endswith("/os.json"):
                    cpe_type = "os"
                elif file.endswith("/hardware.json"):
                    cpe_type = "hardware"
                else:
                    self.logger.warning(f"skipping loading CPE mapping {file} because the type is not recognized")
                    continue

                with open(file) as fp:
                    if "/by_collection_url_and_package_name/" in file:
                        self.__lookup_by_collection_url_and_package_name__[cpe_type].update(orjson.loads(fp.read()))
                    elif "/by_vendor_and_product/" in file:
                        self.__lookup_by_vendor_and_product__[cpe_type].update(orjson.loads(fp.read()))
                    elif "/by_product/" in file:
                        self.__lookup_by_product__[cpe_type].update(orjson.loads(fp.read()))

    def lookup(
        self,
        collection_url: str | None,
        package_name: str | None,
        vendor: str | None,
        product: str | None,
        cpe_types: list[str] | None = None,
    ) -> list[str] | None:
        if not cpe_types:
            cpe_types = self.cpe_types

        collection_url = normalize_collection_url(collection_url)
        package_names = generate_candidates(normalize(package_name))
        vendors = generate_candidates(normalize(vendor))
        products = generate_candidates(normalize(product))

        if not package_names:
            package_names = products

        if collection_url and package_name:
            for p in package_names:
                cpes = set()
                for t in cpe_types:
                    type_cpes = self.__lookup_by_collection_url_and_package_name__[t].get(collection_url, {}).get(p)
                    if type_cpes:
                        cpes.update(type_cpes)
                if cpes:
                    return cpes

        if vendors and products:
            for v in vendors:
                for p in products:
                    cpes = set()
                    for t in cpe_types:
                        type_cpes = self.__lookup_by_vendor_and_product__[t].get(v, {}).get(p)
                        if type_cpes:
                            cpes.update(type_cpes)
                    if cpes:
                        return cpes

        if products:
            for p in products:
                cpes = set()
                for t in cpe_types:
                    type_cpes = self.__lookup_by_product__[t].get(p)
                    if type_cpes:
                        cpes.update(type_cpes)
                if cpes:
                    return cpes

        return None


class Analysis:
    def __init__(self, destination: str, logger: logging.Logger | None = None, timeout: int = 30):
        self.timeout = timeout

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.git = Repo(
            destination=destination,
            logger=self.logger,
        )
        self._cpe_lookup = None

    def urls(self) -> list[str]:
        return self.git.urls()

    def download(self) -> None:
        self.git.clone_or_update_repo()

    def get_nvd_override(self, cve_id: str) -> dict[str, Any] | None:
        path = self.git.nvd_override_file(cve_id=cve_id)

        if not path:
            self.logger.trace(f"no NVD override record for {cve_id!r}")
            return None

        self.logger.trace(f"found NVD override record for {cve_id!r} at {path!r}")

        with open(path) as fp:
            return orjson.loads(fp.read())

    @property
    def cpe_lookup(self) -> CPEPatternLookup:
        if not self._cpe_lookup:
            self._cpe_lookup = CPEPatternLookup(self.git.curated_lookup_files, self.git.generated_lookup_files)

        return self._cpe_lookup


class Repo(Git):
    # TODO: finalize the git url... right now it's using ssh for auth reasons, switch to https before prod
    # _git_url_ = "https://github.com/anchore/nvd-analysis.git"
    _git_url_ = "git@github.com:anchore/nvd-analysis.git"
    _repo_name_ = "nvd-analysis"
    _branch_ = "main"

    _ls_files_ = "git ls-files"

    def __init__(self, destination: str, logger: logging.Logger | None = None):
        super().__init__(
            source=self._git_url_,
            destination=os.path.join(destination, self._repo_name_),
            branch=self._branch_,
            logger=logger,
        )
        self._nvd_overrides_cache = None
        self._curated_lookups_cache = None
        self._generated_lookups_cache = None

    def _reset_cache(self):
        super()._reset_cache()
        self._nvd_overrides_cache = None
        self._curated_lookups_cache = None
        self._generated_lookups_cache = None

    @classmethod
    def urls(cls) -> list[str]:
        return [cls._git_url_]

    def nvd_override_file(self, cve_id: str) -> str | None:
        result = self.nvd_override_files.get(cve_id.upper() + ".json", None)
        if result:
            return result
        return None

    @property
    def curated_lookup_files(self) -> list[str] | None:
        if self._curated_lookups_cache is None:
            self._populate_ls_cache()

        return self._curated_lookups_cache

    @property
    def generated_lookup_files(self) -> list[str] | None:
        if self._generated_lookups_cache is None:
            self._populate_ls_cache()
        return self._generated_lookups_cache

    def _populate_ls_cache(self):
        out = self._exec_cmd(self._ls_files_, cwd=self.destination)
        all_files = [os.path.join(self.destination, line) for line in out.decode().splitlines()]

        self._nvd_overrides_cache = {}
        self._curated_lookups_cache = []
        self._generated_lookups_cache = []

        for f in all_files:
            if "data/nvd/overrides" in f:
                basename = os.path.basename(f)
                if basename.startswith("CVE") and basename.endswith(".json"):
                    self._nvd_overrides_cache[basename] = f
            elif "data/cpe/curated/lookup" in f and f.endswith(".json"):
                self._curated_lookups_cache.append(f)
            elif "data/cpe/generated/lookup" in f and f.endswith(".json"):
                self._generated_lookups_cache.append(f)

    @property
    def nvd_override_files(self) -> dict[str, str]:
        if self._nvd_overrides_cache is None:
            self._populate_ls_cache()

        return self._nvd_overrides_cache
