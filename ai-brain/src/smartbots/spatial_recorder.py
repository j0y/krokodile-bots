"""Records bot positions for spatial mapping using DuckDB."""

from __future__ import annotations

import logging
import math
from pathlib import Path

import duckdb

log = logging.getLogger(__name__)

DEDUP_DIST = 5.0  # Only record when bot moves >5u from last recorded pos


class SpatialRecorder:
    """Accumulates walkable (x,y,z) points in memory, saves to DuckDB on shutdown."""

    def __init__(self, map_name: str, data_dir: str = "/app/data") -> None:
        self._map_name = map_name
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / f"{map_name}_traces.duckdb"

        self._db = duckdb.connect(":memory:")
        self._db.execute("CREATE TABLE traces (x REAL, y REAL, z REAL)")

        self._last_pos: dict[int, tuple[float, float, float]] = {}
        self._buffer: list[tuple[float, float, float]] = []
        self._total_rows = 0

        log.info("SpatialRecorder: in-memory DB ready, will save to %s", self._db_path)

    def record(self, bot_id: int, pos: tuple[float, float, float]) -> None:
        last = self._last_pos.get(bot_id)
        if last is not None:
            dx = pos[0] - last[0]
            dy = pos[1] - last[1]
            dz = pos[2] - last[2]
            if math.sqrt(dx * dx + dy * dy + dz * dz) < DEDUP_DIST:
                return
        self._last_pos[bot_id] = pos
        self._buffer.append((round(pos[0], 1), round(pos[1], 1), round(pos[2], 1)))
        if len(self._buffer) >= 1000:
            self._flush_to_memory()

    def maybe_save(self, tick: int) -> None:
        pass

    def save(self) -> None:
        """Flush buffer to memory DB, then export everything to disk file."""
        self._flush_to_memory()
        if self._total_rows == 0:
            log.info("No traces to save")
            return

        try:
            self._db.execute(f"ATTACH '{self._db_path}' AS disk")
            self._db.execute("CREATE TABLE IF NOT EXISTS disk.traces (x REAL, y REAL, z REAL)")
            self._db.execute("INSERT INTO disk.traces SELECT * FROM traces")
            count = self._db.execute("SELECT COUNT(*) FROM disk.traces").fetchone()[0]  # type: ignore[index]
            self._db.execute("DETACH disk")
            log.info("Saved %d new rows to %s (%d total on disk)", self._total_rows, self._db_path, count)
        except Exception:
            log.exception("Failed to save traces to disk")

    def _flush_to_memory(self) -> None:
        if not self._buffer:
            return
        self._db.executemany("INSERT INTO traces VALUES (?, ?, ?)", self._buffer)
        self._total_rows += len(self._buffer)
        self._buffer.clear()
