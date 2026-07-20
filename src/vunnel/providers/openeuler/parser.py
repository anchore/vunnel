from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace

from vunnel.utils.csaf_types import Branch, CSAFDoc, ProductIdentificationHelper, from_path

_RPM_FILENAME_RE = re.compile(r"^(.+)-([^-]+)-([^-]+)\.([^.]+)\.rpm$")


class Parser:
    _rsync_path = "/openeuler/security/data/csaf/cve/"
    _vuln_dir = "csaf/cve"

    def __init__(
        self,
        workspace: workspace.Workspace,
        namespace: str,
        # see https://www.openeuler.org/en/mirror/list/ for documentation
        # on the rsync commands used and for available mirrors
        rsync_base_url: str = "rsync://root@repo.openeuler.openatom.cn",
        logger: logging.Logger | None = None,
        skip_download: bool = False,
    ):
        self.advisories_dir_path = Path(workspace.input_path) / self._vuln_dir
        self.namespace = namespace
        self.rsync_url = rsync_base_url.rstrip("/") + self._rsync_path
        self.skip_download = skip_download
        self.cves: list[str] = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download(self) -> None:
        """Sync openEuler CSAF VEX advisory files via rsync."""
        self.advisories_dir_path.mkdir(parents=True, exist_ok=True)
        cmd = [
            "rsync",
            "-avz",
            "--partial",
            "--progress",
            "--delete",
            self.rsync_url,
            str(self.advisories_dir_path) + "/",
        ]
        self.logger.info(f"running: {' '.join(cmd)}")
        subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)  # noqa: S603

    def _discover_cves(self) -> None:
        """Populate self.cves from JSON files on disk."""
        if not self.advisories_dir_path.exists():
            return
        for path in sorted(self.advisories_dir_path.rglob("*.json")):
            self.cves.append(str(path.relative_to(self.advisories_dir_path)))

    @staticmethod
    def _enrich_purls(doc: CSAFDoc) -> None:
        """Synthesize PURLs for RPM product branches that only have CPEs.

        openEuler CSAF data identifies packages by RPM filename in the branch
        name (e.g. ``virglrenderer-0.7.0-5.oe1.x86_64.rpm``) but does not
        include PURLs.  We parse the filename and set a PURL so the grype-db
        CSAF VEX transformer can create proper affected-package handles."""
        for branch in doc.product_tree.product_branches():
            _maybe_set_purl(branch)

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        if self.skip_download:
            self.logger.info("skipping download, using existing data")
        else:
            self._download()

        self._discover_cves()

        for cve_path in self.cves:
            try:
                csaf_doc = from_path(str(self.advisories_dir_path / cve_path))
                self._enrich_purls(csaf_doc)
                cve_id = csaf_doc.vulnerabilities[0].cve
                yield cve_id, csaf_doc.to_dict()
            except Exception as e:
                self.logger.warning(f"Failed to read {cve_path}: {e}")


def _maybe_set_purl(branch: Branch) -> None:
    """If *branch* looks like an RPM filename and has no PURL, synthesize one."""
    if branch.product is None:
        return

    helper = branch.product.product_identification_helper
    if helper is not None and helper.purl is not None:
        return  # already has a PURL

    m = _RPM_FILENAME_RE.match(branch.name)
    if not m:
        return

    name, version, release, arch = m.groups()
    purl = f"pkg:rpm/openeuler/{quote(name, safe='')}@{quote(version + '-' + release, safe='')}"
    if arch != "src":
        purl += f"?arch={quote(arch, safe='')}"
    else:
        purl += "?arch=src"

    if helper is None:
        branch.product.product_identification_helper = ProductIdentificationHelper(purl=purl)
    else:
        helper.purl = purl
