import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from vunnel import workspace

from .finder import Result, Strategy
from .grype_db_first_observed import Store as GrypeDBStore
from .vunnel_first_observed import Store as VunnelStore


@dataclass
class _LookupStats:
    """thread-safe statistics for fix date lookups."""

    vunnel_hits: int = 0
    grype_db_hits: int = 0
    misses: int = 0
    total_lookups: int = 0
    vunnel_query_time_ms: float = 0.0
    grype_db_query_time_ms: float = 0.0
    insert_time_ms: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_log_count: int = 0
    _last_log_time: float = 0.0
    _start_time: float = field(default_factory=time.time)

    def record_vunnel_hit(self, query_time_ms: float) -> None:
        with self._lock:
            self.vunnel_hits += 1
            self.total_lookups += 1
            self.vunnel_query_time_ms += query_time_ms

    def record_grype_db_hit(self, vunnel_query_time_ms: float, grype_db_query_time_ms: float) -> None:
        with self._lock:
            self.grype_db_hits += 1
            self.total_lookups += 1
            self.vunnel_query_time_ms += vunnel_query_time_ms
            self.grype_db_query_time_ms += grype_db_query_time_ms

    def record_miss(self, vunnel_query_time_ms: float, grype_db_query_time_ms: float, insert_time_ms: float) -> None:
        with self._lock:
            self.misses += 1
            self.total_lookups += 1
            self.vunnel_query_time_ms += vunnel_query_time_ms
            self.grype_db_query_time_ms += grype_db_query_time_ms
            self.insert_time_ms += insert_time_ms

    def should_log(self, interval: int = 10000) -> tuple[bool, float]:
        """check if we should log stats (every interval lookups). Returns (should_log, interval_elapsed_sec)."""
        with self._lock:
            if self.total_lookups - self._last_log_count >= interval:
                now = time.time()
                interval_elapsed = now - self._last_log_time if self._last_log_time > 0 else now - self._start_time
                self._last_log_count = self.total_lookups
                self._last_log_time = now
                return True, interval_elapsed
            return False, 0.0

    def summary(self) -> str:
        with self._lock:
            if self.total_lookups == 0:
                return "no lookups yet"
            vunnel_pct = (self.vunnel_hits / self.total_lookups) * 100
            grype_db_pct = (self.grype_db_hits / self.total_lookups) * 100
            miss_pct = (self.misses / self.total_lookups) * 100
            avg_vunnel_ms = self.vunnel_query_time_ms / self.total_lookups if self.total_lookups else 0
            avg_grype_db_ms = self.grype_db_query_time_ms / max(self.grype_db_hits + self.misses, 1)
            avg_vunnel_insert_ms = self.insert_time_ms / max(self.misses, 1)
            return (
                f"lookups={self.total_lookups} "
                f"vunnel_hits={self.vunnel_hits} ({vunnel_pct:.1f}%) "
                f"grype_db_hits={self.grype_db_hits} ({grype_db_pct:.1f}%) "
                f"misses={self.misses} ({miss_pct:.1f}%) "
                f"avg_vunnel_query={avg_vunnel_ms:.2f}ms "
                f"avg_grype_db_query={avg_grype_db_ms:.2f}ms "
                f"avg_vunnel_insert={avg_vunnel_insert_ms:.2f}ms"
            )


class Store(Strategy):
    def __init__(self, ws: workspace.Workspace) -> None:
        self.workspace = ws
        self.logger = logging.getLogger("grype-db-fixes-" + ws.name)
        self.grype_db_store = GrypeDBStore(ws)
        self.vunnel_store = VunnelStore(ws)
        self._stats = _LookupStats()

    def __enter__(self) -> "Store":
        """context manager entry - ensure connection is ready"""
        self.grype_db_store.__enter__()
        self.vunnel_store.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """context manager exit - cleanup thread connections"""
        # log final stats
        if self._stats.total_lookups > 0:
            self.logger.debug(f"fix date lookup stats: {self._stats.summary()}")
        self.grype_db_store.__exit__(exc_type, exc_val, exc_tb)
        self.vunnel_store.__exit__(exc_type, exc_val, exc_tb)

    def download(self) -> None:
        self.grype_db_store.download()

    def get_changed_vuln_ids_since(self, since_date: datetime) -> set[str]:
        return self.grype_db_store.get_changed_vuln_ids_since(since_date)

    def find(
        self,
        vuln_id: str,
        cpe_or_package: str,
        fix_version: str,
        ecosystem: str | None = None,
    ) -> list[Result]:
        is_cpe = cpe_or_package.lower().startswith("cpe:")

        # trace log the lookup parameters
        self.logger.trace(
            f"find: vuln_id={vuln_id} {'cpe' if is_cpe else 'pkg'}={cpe_or_package} "
            f"version={fix_version} ecosystem={ecosystem}",
        )

        # always look for results from vunnel first, returning any results
        vunnel_start = time.perf_counter()
        results = self.vunnel_store.find(vuln_id, cpe_or_package, fix_version, ecosystem)
        vunnel_query_ms = (time.perf_counter() - vunnel_start) * 1000

        if results:
            self._stats.record_vunnel_hit(vunnel_query_ms)
            self.logger.trace(f"find: vunnel HIT ({vunnel_query_ms:.2f}ms)")
            self._maybe_log_stats()
            return results

        self.logger.trace(f"find: vunnel MISS ({vunnel_query_ms:.2f}ms)")

        # if no results from vunnel, look in grype db
        grype_db_start = time.perf_counter()
        results = self.grype_db_store.find(vuln_id, cpe_or_package, fix_version, ecosystem)
        grype_db_query_ms = (time.perf_counter() - grype_db_start) * 1000

        if results:
            self._stats.record_grype_db_hit(vunnel_query_ms, grype_db_query_ms)
            self.logger.trace(f"find: grype_db HIT ({grype_db_query_ms:.2f}ms)")
            self._maybe_log_stats()
            return results

        self.logger.trace(f"find: grype_db MISS ({grype_db_query_ms:.2f}ms)")

        # if no results, add a new entry into vunnel (this is a new observed fix date) and return that
        insert_start = time.perf_counter()
        today = datetime.now(UTC).date()
        self.vunnel_store.add(today, vuln_id, cpe_or_package, fix_version, ecosystem)
        insert_ms = (time.perf_counter() - insert_start) * 1000

        self._stats.record_miss(vunnel_query_ms, grype_db_query_ms, insert_ms)
        self.logger.trace(
            f"find: INSERT new fix date ({insert_ms:.2f}ms) - "
            f"vuln_id={vuln_id} {'cpe' if is_cpe else 'pkg'}={cpe_or_package}",
        )
        self._maybe_log_stats()

        return [
            Result(
                date=today,
                kind="first-observed",
                version=fix_version,
                source="vunnel",
            ),
        ]

    def _maybe_log_stats(self) -> None:
        """log stats periodically at INFO level."""
        should_log, interval_elapsed = self._stats.should_log(interval=10000)
        if should_log:
            lookups_per_sec = 10000 / interval_elapsed if interval_elapsed > 0 else 0
            self.logger.debug(
                f"fix date lookup progress: {self._stats.summary()} "
                f"interval={interval_elapsed:.1f}s ({lookups_per_sec:.0f} lookups/s)",
            )
