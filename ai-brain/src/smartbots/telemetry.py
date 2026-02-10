"""Navigation telemetry — records per-tick bot decisions to PostgreSQL."""

from __future__ import annotations

import logging
import time
from dataclasses import astuple, dataclass

import psycopg

log = logging.getLogger(__name__)

FLUSH_ROWS = 500
FLUSH_INTERVAL_SEC = 5.0

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS nav_telemetry (
  tick        INTEGER,
  bot_id      INTEGER,
  x           REAL, y REAL, z REAL,
  goal_x      REAL, goal_y REAL, goal_z REAL,
  seg_idx     INTEGER,
  seg_total   INTEGER,
  move_x      REAL, move_y REAL, move_z REAL,
  steer_dx    REAL, steer_dy REAL,
  steer_clr   REAL,
  path_min_clr REAL,
  path_tight_seg INTEGER,
  deviation   REAL,
  stuck_count INTEGER,
  flags       INTEGER,
  area_id     INTEGER
)"""

_INSERT = (
    "INSERT INTO nav_telemetry VALUES ("
    "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
    "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


@dataclass
class NavTelemetryRow:
    tick: int
    bot_id: int
    x: float
    y: float
    z: float
    goal_x: float
    goal_y: float
    goal_z: float
    seg_idx: int
    seg_total: int
    move_x: float
    move_y: float
    move_z: float
    steer_dx: float
    steer_dy: float
    steer_clr: float
    path_min_clr: float
    path_tight_seg: int | None
    deviation: float
    stuck_count: int
    flags: int
    area_id: int


class TelemetryClient:
    """Buffered writer that INSERTs telemetry rows into PostgreSQL."""

    def __init__(self, host: str = "localhost", port: int = 5432) -> None:
        conninfo = f"host={host} port={port} dbname=telemetry user=smartbots password=smartbots"
        self._conn = psycopg.connect(conninfo, autocommit=False)
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()
        self._buffer: list[tuple[object, ...]] = []
        self._last_flush = time.monotonic()
        self._total_rows = 0
        log.info("Telemetry connected to PostgreSQL at %s:%d", host, port)

    def record_tick(self, row: NavTelemetryRow) -> None:
        self._buffer.append(astuple(row))
        now = time.monotonic()
        if len(self._buffer) >= FLUSH_ROWS or (now - self._last_flush) >= FLUSH_INTERVAL_SEC:
            self._flush()

    def _flush(self) -> None:
        if not self._buffer:
            return
        try:
            with self._conn.cursor() as cur:
                cur.executemany(_INSERT, self._buffer)
            self._conn.commit()
            self._total_rows += len(self._buffer)
            if self._total_rows % 5000 < len(self._buffer):
                log.info("Telemetry: %d rows flushed (%d total)", len(self._buffer), self._total_rows)
        except Exception:
            log.exception("Telemetry flush failed")
            try:
                self._conn.rollback()
            except Exception:
                pass
        self._buffer.clear()
        self._last_flush = time.monotonic()

    def close(self) -> None:
        self._flush()
        self._conn.close()
        log.info("Telemetry closed (%d total rows)", self._total_rows)
