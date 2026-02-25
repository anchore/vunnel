import logging
import os
import threading
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import oras.client
import oras.defaults
import oras.utils
import sqlalchemy as db
import zstandard
from sqlalchemy import event

from vunnel import workspace

from .ecosystem import normalize_package_name
from .finder import Result, Strategy


def cpe_to_v6_format(cpe: str) -> str | None:
    """Convert a standard CPE 2.3 string to v6 simplified format.

    Standard format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
    V6 format: part:vendor:product:edition:lang:sw_edition:target_hw:target_sw:other

    The v6 format omits version and update, and swaps target_hw/target_sw order
    relative to CPE 2.3. Wildcard (*) values are replaced with empty strings.

    Returns None if the input is not a valid CPE 2.3 string.
    """
    if not cpe or not cpe.lower().startswith("cpe:2.3:"):
        return None

    parts = cpe.split(":")
    if len(parts) < 5:
        return None

    # parts[2] is the part type (a, o, h)
    part = parts[2]
    if part not in ("a", "o", "h"):
        return None

    # map CPE 2.3 indices to v6 field order, skipping version[5] and update[6],
    # and swapping target_hw[11] before target_sw[10]
    v6_indices = [3, 4, 7, 8, 9, 11, 10, 12]
    fields = []
    for i in v6_indices:
        val = parts[i] if i < len(parts) else "*"
        fields.append("" if val == "*" else val)

    return f"{part}:{':'.join(fields)}"


if TYPE_CHECKING:
    from oras.container import Container as container_type


class _StoreThreadLocal(threading.local):
    """thread-local storage for per-thread SQLAlchemy connections and table references."""

    conn: db.engine.Connection | None = None
    table: db.Table | None = None


class _ProgressLoggingOrasClient(oras.client.OrasClient):
    """ORAS client wrapper that logs download progress at debug level."""

    def __init__(self, logger: logging.Logger | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.logger = logger or logging.getLogger(__name__)

    def download_blob(self, container: "container_type", digest: str, outfile: str) -> str:
        """Override download_blob to add progress logging."""
        try:
            # Ensure output directory exists first
            outdir = os.path.dirname(outfile)
            if outdir and not os.path.exists(outdir):
                oras.utils.mkdir_p(outdir)

            with self.get_blob(container, digest, stream=True) as r:
                r.raise_for_status()

                # Get content length if available
                total_size = int(r.headers.get("content-length", 0))
                downloaded = 0
                last_logged_percent = 0

                # Calculate how often to log (every 5% of total, or every 10MB if size unknown)
                log_interval = max(total_size * 0.05, 1024 * 1024) if total_size > 0 else 10 * 1024 * 1024

                with open(outfile, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            # Log progress every 5% or at the calculated interval
                            if total_size > 0:
                                current_percent = int((downloaded / total_size) * 20)  # 5% increments (100/5 = 20)
                                if current_percent > last_logged_percent:
                                    percent = (downloaded / total_size) * 100
                                    total_mb = total_size / (1024 * 1024)
                                    downloaded_mb = downloaded / (1024 * 1024)
                                    self.logger.debug(f"downloaded {downloaded_mb:.1f} MB of {total_mb:.1f} MB ({percent:.1f}%)")
                                    last_logged_percent = current_percent
                            elif downloaded // log_interval > (downloaded - len(chunk)) // log_interval:
                                downloaded_mb = downloaded / (1024 * 1024)
                                self.logger.debug(f"downloaded {downloaded_mb:.1f} MB")

        # Allow an empty layer to fail and return /dev/null
        except Exception as e:
            if digest == oras.defaults.blank_hash:
                return os.devnull
            raise e
        return outfile


@dataclass
class FixDate:
    """
    This is the model representing the fixdate table in the underlying sqlite database.
    """

    vuln_id: str
    provider: str
    package_name: str
    full_cpe: str
    ecosystem: str
    fix_version: str | None
    first_observed_date: date
    resolution: str
    source: str
    run_id: int
    database_id: int
    updated_at: datetime | None = None


class Store(Strategy):
    def __init__(self, ws: workspace.Workspace) -> None:
        self.workspace = ws
        self.provider = ws.name
        self.db_path = Path(ws.input_path) / "grype-db-observed-fix-dates.db"
        self.digest_path = self.db_path.with_suffix(".db.digest")
        self.logger = logging.getLogger("grype-db-fixes-" + self.provider)
        self.engine: db.engine.Engine | None = None
        self._thread_local = _StoreThreadLocal()
        self._not_found = False
        self._downloaded = False

    def _get_remote_digest(self, image_ref: str) -> str | None:
        """Get the digest of a remote OCI artifact using oras client.

        Args:
            image_ref: Full image reference (e.g., "ghcr.io/org/repo:tag")

        Returns:
            Digest string (e.g., "sha256:abc123...") or None if failed
        """
        try:
            client = oras.client.OrasClient()

            # authenticate if token is available
            github_token = os.getenv("GITHUB_TOKEN")
            if github_token:
                client.login(
                    hostname="ghcr.io",
                    username="token",
                    password=github_token,
                )

            # parse the image reference and get manifest URL
            container = client.get_container(image_ref)
            manifest_url = f"{client.prefix}://{container.manifest_url()}"

            # HEAD request to get digest from Docker-Content-Digest header
            headers = {"Accept": oras.defaults.default_manifest_media_type}
            response = client.do_request(manifest_url, "HEAD", headers=headers)

            if response.status_code == 200:
                return response.headers.get("Docker-Content-Digest")

            self.logger.debug(f"manifest HEAD request returned status {response.status_code}")
            return None

        except Exception as e:
            self.logger.debug(f"failed to get remote digest: {e}")
            return None

    def _resolve_image_ref(self, image_base: str) -> tuple[str, str | None]:
        """resolve the image reference and digest, trying latest-zstd first then falling back to latest.

        Returns:
            Tuple of (image_ref, remote_digest) where remote_digest may be None if resolution failed.
        """
        # try latest-zstd first
        image_ref = f"{image_base}:latest-zstd"
        remote_digest = self._get_remote_digest(image_ref)
        if remote_digest:
            return image_ref, remote_digest

        # fall back to latest
        self.logger.debug("latest-zstd tag not resolvable, trying latest")
        image_ref = f"{image_base}:latest"
        remote_digest = self._get_remote_digest(image_ref)
        return image_ref, remote_digest

    def _pull(
        self,
        client: _ProgressLoggingOrasClient,
        image_ref: str,
        download_dir: Path,
    ) -> None:
        """pull the OCI artifact from the registry."""
        self.logger.info(f"pulling fix date database from {image_ref}")
        client.pull(target=image_ref, outdir=str(download_dir))
        self.logger.info(f"successfully fetched fix date database for {self.provider}")

    def _process_downloaded_file(self, download_zst_path: Path, download_db_path: Path) -> None:
        """decompress zstd file if present, otherwise verify db file exists."""
        if download_zst_path.exists():
            self.logger.debug(f"decompressing {download_zst_path} to {download_db_path}")
            dctx = zstandard.ZstdDecompressor()
            # this will truncate or create any existing DBs and archives
            with download_zst_path.open("rb") as ifh, download_db_path.open("wb") as ofh:
                dctx.copy_stream(ifh, ofh)
            download_zst_path.unlink()
        elif not download_db_path.exists():
            raise FileNotFoundError(f"expected {download_db_path} or {download_zst_path} after pull")

    def download(self) -> None:
        """fetch the fix date database from the OCI registry using ORAS"""

        # we don't need to verify that a download has actually occured, since it might be that an old DB can be used
        # as a fallback, instead we want to ensure that we have attempted to download the DB.
        self._downloaded = True

        # construct the image reference base
        image_base = f"ghcr.io/anchore/grype-db-observed-fix-date/{self.provider}"

        # ensure the parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # resolve image reference with fallback (latest-zstd -> latest)
        image_ref, remote_digest = self._resolve_image_ref(image_base)

        # check if we can skip download by comparing digests
        if remote_digest and self.db_path.exists() and self.digest_path.exists():
            try:
                local_digest = self.digest_path.read_text().strip()
                if local_digest == remote_digest:
                    self.logger.info(f"fix date database is up to date (digest: {remote_digest})")
                    return
                self.logger.debug(f"fix date database digest changed (local: {local_digest}, remote: {remote_digest})")
            except Exception as e:
                self.logger.debug(f"failed to read local digest: {e}")

        # download the database file using ORAS
        client = _ProgressLoggingOrasClient(logger=self.logger)

        # authenticate with GitHub Container Registry if token is available
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            try:
                client.login(
                    hostname="ghcr.io",
                    username="token",
                    password=github_token,
                )
                self.logger.debug("authenticated with GitHub Container Registry using GITHUB_TOKEN")
            except Exception as e:
                self.logger.warning(f"failed to authenticate with GitHub Container Registry: {e}")

        # set up download paths
        download_dir = Path(self.workspace.input_path) / "fix-dates"
        download_zst_path = download_dir / f"{self.provider}.db.zst"
        download_db_path = download_dir / f"{self.provider}.db"

        try:
            self._pull(client, image_ref, download_dir)
            self._process_downloaded_file(download_zst_path, download_db_path)

            # atomically move the downloaded file to the exact self.db_path
            # os.replace is atomic on POSIX and replaces existing file if present
            os.replace(download_db_path, self.db_path)

            # save the digest for future comparisons
            if remote_digest:
                self.digest_path.write_text(remote_digest)
                self.logger.debug(f"saved digest: {remote_digest}")

        except ValueError as e:
            # if this is a 404 or not found error, log a warning and continue
            if "not found" in str(e).lower():
                self.logger.warning(f"no fix date database found for provider {self.provider}")
                self._not_found = True
            else:
                self.logger.error(f"failed to fetch fix date database for {self.provider}: {e}")
                raise e
        except Exception as e:
            self.logger.error(f"failed to fetch fix date database for {self.provider}: {e}")
            raise

    def get(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[FixDate]:
        """synchronous get existing vulnerability operation"""

        if not self._downloaded:
            raise RuntimeError("fix date database has not been downloaded")

        if self._not_found:
            # this is in cases where the fix date database does not exist for the provider. We want to act as
            # if the database is empty and return no results.
            return []

        conn, table = self._get_connection()

        # build query - if cpe_or_package looks like a CPE, search by full_cpe, otherwise by package_name
        query = table.select().where(
            (table.c.vuln_id == vuln_id) & (table.c.provider == self.provider),
        )

        is_cpe = cpe_or_package.lower().startswith("cpe:")
        if is_cpe:
            # try v6 simplified CPE format (e.g., "a:vendor:product:...") since grype-db stores CPEs this way
            v6_cpe = cpe_to_v6_format(cpe_or_package)
            if v6_cpe:
                query = query.where(
                    (table.c.full_cpe == cpe_or_package) | (table.c.full_cpe == v6_cpe),
                )
            else:
                query = query.where(table.c.full_cpe == cpe_or_package)
        else:
            normalized_pkg = normalize_package_name(cpe_or_package, ecosystem)
            query = query.where(
                (table.c.package_name == normalized_pkg) & (table.c.full_cpe == ""),
            )
            if ecosystem:
                query = query.where(table.c.ecosystem == ecosystem)

        if fix_version:
            query = query.where(table.c.fix_version == fix_version)

        results = conn.execute(query).fetchall()

        if not results:
            return []

        return [
            FixDate(
                vuln_id=row.vuln_id,
                provider=row.provider,
                package_name=row.package_name,
                full_cpe=row.full_cpe,
                ecosystem=row.ecosystem,
                fix_version=row.fix_version,
                first_observed_date=date.fromisoformat(row.first_observed_date),
                resolution=row.resolution,
                source=row.source,
                run_id=row.run_id,
                database_id=row.database_id,
                updated_at=row.updated_at,
            )
            for row in results
            if row and row.first_observed_date
        ]

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[Result]:
        return [
            Result(
                date=fd.first_observed_date,
                kind="first-observed",
                version=fd.fix_version,
                accurate=fd.database_id != 1,
                source="grype-db",
            )
            for fd in self.get(
                vuln_id=vuln_id,
                cpe_or_package=cpe_or_package,
                fix_version=fix_version,
                ecosystem=ecosystem,
            )
        ]

    def get_changed_vuln_ids_since(self, since_date: datetime) -> set[str]:
        """get all vulnerability IDs that have been created or modified after the given date.

        This queries the runs table to find applicable runs, then returns all unique
        vuln_ids from fixdate entries with those run_ids. These vulnerabilities will
        need to be fully reprocessed.

        Args:
            since_date: Only return vuln IDs from runs after this datetime

        Returns:
            Set of unique vulnerability IDs that have changed
        """
        if not self._downloaded:
            raise RuntimeError("fix date database has not been downloaded")

        if self._not_found:
            # this is in cases where the fix date database does not exist for the provider. We want to act as
            # if the database is empty and return no results.
            return set()

        conn, _ = self._get_connection()

        # reflect the runs table structure
        metadata = db.MetaData()
        runs_table = db.Table("runs", metadata, autoload_with=self.engine)
        fixdates_table = db.Table("fixdates", metadata, autoload_with=self.engine)

        # get run IDs for runs after the given date
        run_query = runs_table.select().where(runs_table.c.run_timestamp >= since_date)
        run_results = conn.execute(run_query).fetchall()

        if not run_results:
            return set()

        run_ids = [row.id for row in run_results]

        # get distinct vuln_ids from fixdates with those run_ids
        vuln_query = (
            db.select(fixdates_table.c.vuln_id)
            .distinct()
            .where(
                fixdates_table.c.run_id.in_(run_ids),
            )
        )
        vuln_results = conn.execute(vuln_query).fetchall()

        return {row.vuln_id for row in vuln_results}

    def _get_connection(self) -> tuple[db.engine.Connection, db.Table]:
        """get or create thread-local SQLAlchemy connection and table"""
        # get thread-local connection and table, or create them if they don't exist
        if self._thread_local.conn is None or self._thread_local.table is None:
            # create engine once if it doesn't exist
            if not self.engine:
                self.engine = db.create_engine(f"sqlite:///{self.db_path}")

                # configure SQLAlchemy engine with SQLite pragmas for read-only performance
                @event.listens_for(self.engine, "connect")
                def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA query_only = ON")
                    cursor.execute("PRAGMA cache_size=10000")  # ~40MB cache
                    cursor.execute("PRAGMA temp_store=MEMORY")
                    cursor.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O
                    cursor.close()

            # create thread-local connection
            self._thread_local.conn = self.engine.connect()

            # reflect the existing table structure for this thread
            metadata = db.MetaData()
            self._thread_local.table = db.Table("fixdates", metadata, autoload_with=self.engine)

        return self._thread_local.conn, self._thread_local.table

    def cleanup_thread_connections(self) -> None:
        """clean up thread-local connections for the current thread, then dispose the engine."""
        if self._thread_local.conn is not None:
            try:
                self.logger.debug("closing grype-db fixdates database")
                self._thread_local.conn.close()
            except Exception:
                # ignore errors during cleanup
                self.logger.exception("error closing grype-db fixdates database connection")
            finally:
                # clear the thread-local storage
                self._thread_local.conn = None
                self._thread_local.table = None

        # dispose the engine to close all pooled connections from any thread
        if self.engine:
            self.engine.dispose()
            self.engine = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        self.cleanup_thread_connections()
