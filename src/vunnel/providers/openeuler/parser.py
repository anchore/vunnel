from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

    from vunnel import workspace

from vunnel.utils.csaf_types import from_path


class Parser:
    _rsync_src = "rsync://repo.openeuler.openatom.cn/openeuler/security/data/csaf/cve/"
    _vuln_dir = "csaf/cve"

    def __init__(
        self,
        workspace: workspace.Workspace,
        namespace: str,
        logger: logging.Logger | None = None,
        skip_download: bool = False,
    ):
        self.advisories_dir_path = Path(workspace.input_path) / self._vuln_dir
        self.namespace = namespace
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
            self._rsync_src,
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

    def get(self) -> Generator[tuple[str, dict[str, Any]], None, None]:
        if self.skip_download:
            self.logger.info("skipping download, using existing data")
        else:
            self._download()

        self._discover_cves()

        for cve_path in self.cves:
            try:
                csaf_doc = from_path(str(self.advisories_dir_path / cve_path))
                cve_id = csaf_doc.vulnerabilities[0].cve
                yield cve_id, csaf_doc.to_dict()
            except Exception as e:
                self.logger.warning(f"Failed to read {cve_path}: {e}")
