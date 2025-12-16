from csv import writer
import time
import re
import requests
import logging
from typing import List, Dict, Any

from vunnel import provider

# Helper class to satisfy Vunnel's requirement for a schema object with a URL
class BodhiSchema:
    # This URL contains "os" and "1.0.0", satisfying grype-db's checks
    url = "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json"

class Provider(provider.Provider):
    def __init__(self, root: str, **kwargs):
        super().__init__(root)
        self.config = kwargs.get('config')
        self.source_url = "https://bodhi.fedoraproject.org/updates/"
        self.logger = logging.getLogger(__name__)

    @classmethod
    def name(cls) -> str:
        return "bodhi"

    def update(self, last_updated=None):
        page = 1
        urls_processed = [self.source_url]
        item_count = 0
        
        params = {
            "type": "security",
            "status": "stable",
            "page": page,
            "rows_per_page": 100 
        }

        with self.results_writer() as writer:
            while True:

                if page > 70:
                    self.logger.info("Reached page limit (70). Stopping.")
                    break

                self.logger.info(f"Fetching Bodhi updates page {page}...")
                
                # --- RETRY LOGIC START ---
                data = None
                for attempt in range(3):
                    try:
                        # Timeout set to 120s
                        r = requests.get(self.source_url, params=params, timeout=120)
                        r.raise_for_status()
                        data = r.json()
                        break  # Success! Exit the retry loop
                    except Exception as e:
                        self.logger.warning(f"Attempt {attempt+1}/3 failed for page {page}: {e}")
                        if attempt == 2:
                            self.logger.error(f"Giving up on page {page}. Finalizing results.")
                            # Return what we have so far instead of crashing
                            return urls_processed, item_count
                        time.sleep(5)  # Wait 5s before retrying
                # --- RETRY LOGIC END ---

                updates = data.get("updates", [])
                if not updates:
                    break

                for update in updates:
                    self._process_update(update, writer)
                    item_count += 1

                # Pagination check: If we got fewer items than requested, we are done
                if len(updates) < params["rows_per_page"]:
                    break
                
                params["page"] += 1
                page += 1
        
        return urls_processed, item_count

    def _process_update(self, update: Dict[str, Any], writer):
        # 1. Identify the Advisory ID
        advisory_id = update.get("alias") or update.get("updateid")
        if not advisory_id:
            return

        # 2. Identify the OS Release
        release_version = update.get("release", {}).get("version")
        if not release_version:
            return
        namespace = f"fedora:{release_version}"

        # 3. Extract CVEs
        cve_ids = set()
        
        # Strategy A: Check 'bugs' list
        for bug in update.get("bugs", []):
            if bug.get("security", False):
                found_cves = re.findall(r"(CVE-\d{4}-\d+)", bug.get("title", ""))
                cve_ids.update(found_cves)

        # Strategy B: Check 'notes' text
        if not cve_ids:
            notes = update.get("notes", "")
            found_cves = re.findall(r"(CVE-\d{4}-\d+)", notes)
            cve_ids.update(found_cves)

        if not cve_ids:
            return

        # 4. Extract Package Information
        for build in update.get("builds", []):
            nvr = build.get("nvr")
            if not nvr:
                continue

            name, version = self._parse_nvr(nvr)
            
            # 5. Build the Record
            record = {
                "Vulnerability": {
                    "Name": advisory_id,
                    "NamespaceName": namespace,
                    "Description": update.get("notes", ""),
                    "Link": update.get("url"),
                    "Severity": update.get("severity", "unknown"),
                    "FixedIn": [
                        {
                            "Name": name,
                            "Version": version,
                            "Module": None,
                            "VersionFormat": "rpm",
                            "NamespaceName": namespace
                        }
                    ],
                    "Metadata": {
                        # Convert each CVE string into a dictionary with Name and Link
                        "CVE": [
                            {
                                "Name": cve,
                                "Link": f"https://nvd.nist.gov/vuln/detail/{cve}"
                            } 
                            for cve in cve_ids
                        ],
                        "DateIssued": update.get("date_stable")
                    }
                }
            }
            # 6. Write the Record
        writer.write(
            identifier=f"{namespace}/{advisory_id}/{name}",
            schema=BodhiSchema,
            payload=[record]  # <--- WRAP IN A LIST
        )

    def _parse_nvr(self, nvr: str):
        # Parses chromium-143.0.7499.109-2.fc42 -> (chromium, 143.0.7499.109-2.fc42)
        parts = nvr.rsplit("-", 2)
        if len(parts) == 3:
            name = parts[0]
            version_release = f"{parts[1]}-{parts[2]}"
            return name, version_release
        return nvr, "unknown"