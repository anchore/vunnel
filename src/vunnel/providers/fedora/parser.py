from __future__ import annotations

import gzip
import hashlib
import logging
import lzma
import os
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree

import zstandard

from vunnel.utils import http_wrapper as http

if TYPE_CHECKING:
    from collections.abc import Generator
    from types import TracebackType

    from vunnel.workspace import Workspace

    from . import Config


# Severity mapping from Fedora/Bodhi to Vunnel schema
# Fedora uses: urgent, critical, important, moderate, low, unspecified
SEVERITY_MAP = {
    "urgent": "Critical",
    "critical": "Critical",
    "important": "High",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
    "none": "Unknown",
    "unspecified": "Unknown",
    "": "Unknown",
}

# XML namespace for repomd.xml
REPO_NS = {"repo": "http://linux.duke.edu/metadata/repo"}


class Parser:
    """Parser for Fedora updateinfo.xml repository metadata."""

    def __init__(
        self,
        workspace: Workspace,
        config: Config,
        logger: logging.Logger | None = None,
    ):
        self.workspace = workspace
        self.config = config
        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger
        self.urls: list[str] = []

    def __enter__(self) -> Parser:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass

    def _discover_releases(self) -> list[str]:
        """Query Bodhi API to discover current Fedora releases."""
        if self.config.releases:
            self.logger.info(f"using configured releases: {self.config.releases}")
            return self.config.releases

        url = f"{self.config.bodhi_url}/releases/"
        params = "?state=current&id_prefix=FEDORA&rows_per_page=50"
        full_url = url + params
        self.urls.append(full_url)

        try:
            self.logger.info(f"discovering releases from Bodhi API: {full_url}")
            resp = http.get(full_url, self.logger, timeout=self.config.request_timeout)
            resp.raise_for_status()
            data = resp.json()

            releases = []
            for release in data.get("releases", []):
                version = release.get("version")
                # Only include numeric versions (skip "eln", "rawhide", etc.)
                if version and version.isdigit():
                    releases.append(version)

            if releases:
                releases = sorted(releases, key=int, reverse=True)
                self.logger.info(f"discovered releases from Bodhi: {releases}")
                return releases
            else:
                self.logger.warning("no releases found from Bodhi API, using fallback")
                return self._fallback_releases()

        except Exception as e:
            self.logger.warning(f"failed to discover releases from Bodhi: {e}, using fallback")
            return self._fallback_releases()

    def _fallback_releases(self) -> list[str]:
        """Fallback releases if Bodhi API is unavailable."""
        # These are commonly supported releases as of late 2024
        return ["41", "40", "39"]

    def _get_repo_urls(self, release: str) -> list[tuple[str, str, str]]:
        """Get repository URLs for a release.

        Returns:
            List of (repo_type, repo_url, source) tuples where source is 'mirror' or 'archive'
        """
        base = self.config.mirror_url.rstrip("/")
        archive_base = self.config.archive_url.rstrip("/")

        # Try main mirror first, then archive as fallback
        repos = [
            ("updates", f"{base}/updates/{release}/Everything/x86_64", "mirror"),
            ("updates", f"{archive_base}/updates/{release}/Everything/x86_64", "archive"),
        ]
        if self.config.include_testing:
            repos.append(("updates-testing", f"{base}/updates/testing/{release}/Everything/x86_64", "mirror"))
            repos.append(("updates-testing", f"{archive_base}/updates/testing/{release}/Everything/x86_64", "archive"))
        return repos

    def _fetch_repomd(self, repo_url: str) -> ElementTree.Element | None:
        """Fetch and parse repomd.xml from a repository."""
        repomd_url = f"{repo_url}/repodata/repomd.xml"
        self.urls.append(repomd_url)

        try:
            self.logger.debug(f"fetching repomd.xml from {repomd_url}")
            # Use a custom status handler to not retry on 404
            def status_handler(resp):
                if resp.status_code == 404:
                    # Don't retry on 404 - the repo doesn't exist at this URL
                    return
                resp.raise_for_status()

            resp = http.get(
                repomd_url,
                self.logger,
                timeout=self.config.request_timeout,
                retries=2,  # Fewer retries since we have fallback URLs
                status_handler=status_handler,
            )
            if resp.status_code == 404:
                self.logger.debug(f"repomd.xml not found at {repomd_url}")
                return None
            return ElementTree.fromstring(resp.content)
        except Exception as e:
            self.logger.debug(f"failed to fetch repomd.xml from {repomd_url}: {e}")
            return None

    def _find_updateinfo_location(self, repomd: ElementTree.Element) -> tuple[str, str | None] | None:
        """Find updateinfo location and checksum from repomd.xml.

        Returns:
            Tuple of (href, expected_sha256) or None if not found
        """
        updateinfo_data = repomd.find(".//repo:data[@type='updateinfo']", REPO_NS)
        if updateinfo_data is None:
            return None

        location = updateinfo_data.find("repo:location", REPO_NS)
        if location is None:
            return None

        href = location.get("href")
        if not href:
            return None

        # Get checksum for validation
        checksum_elem = updateinfo_data.find("repo:checksum", REPO_NS)
        expected_checksum = None
        if checksum_elem is not None and checksum_elem.get("type") == "sha256":
            expected_checksum = checksum_elem.text

        return href, expected_checksum

    def _decompress(self, data: bytes, filename: str) -> bytes:
        """Decompress data based on file extension."""
        if filename.endswith(".gz"):
            return gzip.decompress(data)
        elif filename.endswith(".xz"):
            return lzma.decompress(data)
        elif filename.endswith(".zst"):
            dctx = zstandard.ZstdDecompressor()
            return dctx.decompress(data)
        else:
            # Assume uncompressed
            return data

    def _fetch_updateinfo(self, repo_url: str, release: str, repo_type: str) -> str | None:
        """Fetch and decompress updateinfo.xml from a repository.

        Returns:
            Path to the downloaded updateinfo.xml file, or None on failure
        """
        repomd = self._fetch_repomd(repo_url)
        if repomd is None:
            return None

        location_info = self._find_updateinfo_location(repomd)
        if location_info is None:
            self.logger.warning(f"no updateinfo found in repomd.xml for {repo_url}")
            return None

        href, expected_checksum = location_info
        updateinfo_url = f"{repo_url}/{href}"
        self.urls.append(updateinfo_url)

        try:
            self.logger.info(f"fetching updateinfo from {updateinfo_url}")
            resp = http.get(updateinfo_url, self.logger, timeout=self.config.request_timeout, stream=True)
            resp.raise_for_status()
            compressed_data = resp.content

            # Validate checksum if available
            if expected_checksum:
                actual_checksum = hashlib.sha256(compressed_data).hexdigest()
                if actual_checksum != expected_checksum:
                    self.logger.error(f"checksum mismatch for {updateinfo_url}: expected {expected_checksum}, got {actual_checksum}")
                    return None

            # Decompress
            xml_data = self._decompress(compressed_data, href)

            # Save to workspace
            output_filename = f"updateinfo-{release}-{repo_type}.xml"
            output_path = os.path.join(self.workspace.input_path, output_filename)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, "wb") as f:
                f.write(xml_data)

            self.logger.debug(f"saved updateinfo to {output_path}")
            return output_path

        except Exception as e:
            self.logger.warning(f"failed to fetch updateinfo from {updateinfo_url}: {e}")
            return None

    def _download(self) -> list[tuple[str, str]]:
        """Download updateinfo.xml files for all releases.

        Returns:
            List of (release, file_path) tuples
        """
        releases = self._discover_releases()
        downloaded = []

        for release in releases:
            repo_urls = self._get_repo_urls(release)
            # Group by repo_type and try mirror first, then archive
            repo_groups: dict[str, list[tuple[str, str]]] = {}
            for repo_type, repo_url, source in repo_urls:
                if repo_type not in repo_groups:
                    repo_groups[repo_type] = []
                repo_groups[repo_type].append((repo_url, source))

            for repo_type, urls_with_source in repo_groups.items():
                path = None
                for repo_url, source in urls_with_source:
                    self.logger.info(f"trying {repo_type} repository for Fedora {release} from {source}")
                    path = self._fetch_updateinfo(repo_url, release, repo_type)
                    if path:
                        self.logger.info(f"successfully fetched {repo_type} for Fedora {release} from {source}")
                        downloaded.append((release, path))
                        break  # Stop trying other sources for this repo_type
                    else:
                        self.logger.debug(f"failed to fetch from {source}, trying next source")

                if not path:
                    self.logger.warning(f"could not fetch {repo_type} for Fedora {release} from any source")

        return downloaded

    def _parse_updateinfo(self, release: str, file_path: str) -> Generator[dict[str, Any]]:
        """Parse updateinfo.xml and yield security advisories.

        Uses iterparse for memory-efficient parsing of large files.
        """
        self.logger.info(f"parsing {file_path} for release {release}")

        try:
            context = ElementTree.iterparse(file_path, events=("end",))

            for event, elem in context:
                if elem.tag != "update":
                    continue

                # Only process security updates
                update_type = elem.get("type", "")
                if update_type != "security":
                    elem.clear()
                    continue

                advisory = self._parse_advisory(elem, release)
                if advisory:
                    yield advisory

                # Clear element to free memory
                elem.clear()

        except ElementTree.ParseError as e:
            self.logger.error(f"XML parse error in {file_path}: {e}")

    def _parse_advisory(self, elem: ElementTree.Element, release: str) -> dict[str, Any] | None:
        """Parse a single <update> element into an advisory dict."""
        advisory_id = elem.findtext("id", "")
        if not advisory_id:
            return None

        severity = elem.findtext("severity", "").lower()
        severity = SEVERITY_MAP.get(severity, "Unknown")

        title = elem.findtext("title", "")
        description = elem.findtext("description", "")

        issued = elem.find("issued")
        issued_date = issued.get("date", "") if issued is not None else ""

        updated = elem.find("updated")
        updated_date = updated.get("date", "") if updated is not None else ""

        # Extract CVE references
        cves = []
        references = elem.find("references")
        if references is not None:
            for ref in references.findall("reference"):
                if ref.get("type") == "cve":
                    cve_id = ref.get("id", "")
                    cve_link = ref.get("href", "")
                    if cve_id:
                        cves.append({"id": cve_id, "link": cve_link})

        # Extract packages from pkglist
        packages = []
        pkglist = elem.find("pkglist")
        if pkglist is not None:
            for collection in pkglist.findall("collection"):
                # Check for module info
                module_elem = collection.find("module")
                module_str = ""
                if module_elem is not None:
                    mod_name = module_elem.get("name", "")
                    mod_stream = module_elem.get("stream", "")
                    if mod_name and mod_stream:
                        module_str = f"{mod_name}:{mod_stream}"

                for pkg in collection.findall("package"):
                    arch = pkg.get("arch", "")
                    # Skip source RPMs - we want binary packages
                    if arch == "src":
                        continue
                    # Only include x86_64 and noarch for now
                    if arch not in ("x86_64", "noarch"):
                        continue

                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    pkg_release = pkg.get("release", "")
                    epoch = pkg.get("epoch", "0")

                    if not name or not version:
                        continue

                    # Construct full version string with epoch: epoch:version-release
                    full_version = f"{epoch}:{version}-{pkg_release}"

                    packages.append({
                        "name": name,
                        "version": full_version,
                        "module": module_str,
                    })

        # Construct advisory link
        advisory_link = f"https://bodhi.fedoraproject.org/updates/{advisory_id}"

        return {
            "advisory_id": advisory_id,
            "release": release,
            "severity": severity,
            "title": title,
            "description": description,
            "issued_date": issued_date,
            "updated_date": updated_date,
            "cves": cves,
            "packages": packages,
            "link": advisory_link,
        }

    def _normalize(self, advisory: dict[str, Any]) -> Generator[tuple[str, dict[str, Any]]]:
        """Normalize advisory to Vunnel vulnerability schema.

        Yields one record per CVE (or per advisory if no CVEs).
        """
        release = advisory["release"]
        namespace = f"fedora:{release}"
        packages = advisory["packages"]

        if not packages:
            return

        # Build FixedIn list
        fixed_in = []
        for pkg in packages:
            fixed_in_entry = {
                "Name": pkg["name"],
                "Version": pkg["version"],
                "VersionFormat": "rpm",
                "NamespaceName": namespace,
                "Module": pkg.get("module", ""),
                "VendorAdvisory": {
                    "NoAdvisory": False,
                    "AdvisorySummary": [
                        {
                            "ID": advisory["advisory_id"],
                            "Link": advisory["link"],
                        }
                    ],
                },
            }
            fixed_in.append(fixed_in_entry)

        # Build base vulnerability record
        base_record = {
            "Vulnerability": {
                "Severity": advisory["severity"],
                "NamespaceName": namespace,
                "FixedIn": fixed_in,
                "Link": advisory["link"],
                "Description": advisory.get("description", ""),
                "Metadata": {
                    "Issued": advisory.get("issued_date", ""),
                    "Updated": advisory.get("updated_date", ""),
                },
                "Name": "",  # Will be set per CVE/advisory
                "CVSS": [],
            },
        }

        # If we have CVEs, emit one record per CVE
        if advisory["cves"]:
            for cve in advisory["cves"]:
                cve_id = cve["id"]
                record = _deep_copy_record(base_record)
                record["Vulnerability"]["Name"] = cve_id
                record["Vulnerability"]["Metadata"]["CVE"] = [
                    {"Name": cve_id, "Link": cve.get("link", "")}
                ]

                yield (f"{namespace}/{cve_id}", record)
        else:
            # No CVEs - emit record with advisory ID as the identifier
            vuln_id = advisory["advisory_id"]
            record = _deep_copy_record(base_record)
            record["Vulnerability"]["Name"] = vuln_id
            record["Vulnerability"]["Metadata"]["CVE"] = []

            yield (f"{namespace}/{vuln_id}", record)

    def get(self) -> Generator[tuple[str, dict[str, Any]]]:
        """Main entry point - download, parse, and normalize vulnerabilities."""
        downloaded = self._download()

        # Track emitted vulnerabilities to avoid duplicates across repos
        emitted: set[str] = set()

        for release, file_path in downloaded:
            for advisory in self._parse_updateinfo(release, file_path):
                for vuln_id, record in self._normalize(advisory):
                    if vuln_id not in emitted:
                        emitted.add(vuln_id)
                        yield (vuln_id, record)


def _deep_copy_record(record: dict[str, Any]) -> dict[str, Any]:
    """Create a deep copy of a vulnerability record."""
    import copy
    return copy.deepcopy(record)
