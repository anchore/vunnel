from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import TYPE_CHECKING, Any

import orjson
from packageurl import PackageURL

from vunnel import utils
from vunnel.tool import fixdate
from vunnel.utils import osv

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace


class Parser:
    advisory_id_prefix = "DHI-"
    ecosystem_prefix = "Docker Hardened Images:"

    def __init__(  # noqa: PLR0913
        self,
        ws: Workspace,
        repository_url: str,
        repository_branch: str,
        advisories_path: str,
        skip_download: bool = False,
        fixdater: fixdate.Finder | None = None,
        logger: logging.Logger | None = None,
    ):
        if not fixdater:
            fixdater = fixdate.default_finder(ws)
        self.fixdater = fixdater
        self.workspace = ws
        self.repository_url = repository_url
        self.repository_branch = repository_branch
        self.advisories_path = advisories_path
        self.skip_download = skip_download
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.checkout_path = os.path.join(self.workspace.input_path, "advisories")
        self.urls = [repository_url]
        git_executable = shutil.which("git")
        if git_executable is None:
            raise RuntimeError("git executable is required by the DHI provider")
        self.git_executable = git_executable

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _git(self, *args: str) -> str:
        cmd = [self.git_executable, *args]
        try:
            # S603 disable explanation: running git commands by design
            return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout  # noqa: S603
        except subprocess.CalledProcessError as e:
            self.logger.error(f"git command failed: {' '.join(cmd)}\n{e.stderr.strip()}")
            raise

    def _clone(self) -> None:
        if self.skip_download:
            if not os.path.isdir(self.checkout_path):
                raise RuntimeError(f"DHI advisory checkout does not exist: {self.checkout_path}")
            self.logger.info(f"skipping download, using existing checkout at {self.checkout_path}")
            return
        self._clone_repo()

    @utils.retry_with_backoff()
    def _clone_repo(self) -> None:
        self.logger.info(f"cloning {self.repository_url} branch {self.repository_branch} to {self.checkout_path}")
        shutil.rmtree(self.checkout_path, ignore_errors=True)
        self._git("clone", "--depth", "1", "--branch", self.repository_branch, self.repository_url, self.checkout_path)

    def _record_source_revision(self) -> None:
        revision = self._git("-C", self.checkout_path, "rev-parse", "HEAD").strip()
        if revision:
            self.logger.info(f"using advisory repository revision {revision}")
            self.urls.append(f"{self.repository_url.removesuffix('.git')}/tree/{revision}/{self.advisories_path}")

    def _load(self) -> Generator[dict[str, Any]]:
        root_path = os.path.join(self.checkout_path, self.advisories_path)
        if not os.path.isdir(root_path):
            raise RuntimeError(f"DHI advisory path does not exist: {root_path}")
        for root, dirs, files in os.walk(root_path):
            dirs.sort()
            for filename in sorted(files):
                if not filename.endswith(".json"):
                    continue
                path = os.path.join(root, filename)
                with open(path, "rb") as f:
                    record = orjson.loads(f.read())
                if isinstance(record, dict):
                    yield record

    @classmethod
    def _validate(cls, record: dict[str, Any]) -> tuple[str, str]:
        vuln_id = record.get("id")
        if not isinstance(vuln_id, str) or not vuln_id.startswith(cls.advisory_id_prefix):
            raise ValueError("record is not a DHI advisory")
        schema_version = record.get("schema_version")
        if not isinstance(schema_version, str):
            raise ValueError(f"DHI advisory {vuln_id} has no schema_version")
        affected = record.get("affected")
        if not isinstance(affected, list) or not affected:
            raise ValueError(f"DHI advisory {vuln_id} has no affected packages")
        for item in affected:
            package = item.get("package") if isinstance(item, dict) else None
            if not isinstance(package, dict):
                raise ValueError(f"DHI advisory {vuln_id} has an invalid affected package")
            ecosystem = package.get("ecosystem")
            if not isinstance(ecosystem, str) or not ecosystem.startswith(cls.ecosystem_prefix):
                raise ValueError(f"DHI advisory {vuln_id} has a non-DHI ecosystem")
            purl_value = package.get("purl")
            if not isinstance(purl_value, str):
                raise ValueError(f"DHI advisory {vuln_id} has no affected-package PURL")
            purl = PackageURL.from_string(purl_value)
            if purl.namespace != "dhi" or purl.type not in {"apk", "deb"}:
                raise ValueError(f"DHI advisory {vuln_id} has a non-DHI OS package PURL")
        return vuln_id, schema_version

    def get(self) -> Generator[tuple[str, str, dict[str, Any]]]:
        self._clone()
        self._record_source_revision()
        self.fixdater.download()
        seen: dict[str, bytes] = {}
        for record in self._load():
            vuln_id = record.get("id")
            if not isinstance(vuln_id, str) or not vuln_id.startswith(self.advisory_id_prefix):
                continue
            normalized = orjson.dumps(record, option=orjson.OPT_SORT_KEYS)
            previous = seen.get(vuln_id)
            if previous is not None:
                if previous != normalized:
                    raise ValueError(f"conflicting duplicate DHI advisory ID: {vuln_id}")
                continue
            seen[vuln_id] = normalized
            validated_id, schema_version = self._validate(record)
            osv.patch_fix_date(record, self.fixdater)
            yield validated_id, schema_version, record
