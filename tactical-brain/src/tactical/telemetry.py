"""Telemetry — records bot state and planner decisions to PostgreSQL."""

from __future__ import annotations

import logging
import time
from dataclasses import astuple, dataclass

import psycopg

log = logging.getLogger(__name__)

FLUSH_ROWS = 500
FLUSH_INTERVAL_SEC = 5.0

_CREATE_STATE_TABLE = """\
CREATE TABLE IF NOT EXISTS bot_state (
  tick       INTEGER,
  bot_id     INTEGER,
  alive      BOOLEAN,
  team       INTEGER,
  health     INTEGER,
  pos_x      REAL, pos_y REAL, pos_z REAL
)"""

_CREATE_COMMANDS_TABLE = """\
CREATE TABLE IF NOT EXISTS bot_commands (
  tick       INTEGER,
  bot_id     INTEGER,
  target_x   REAL, target_y REAL, target_z REAL,
  profile    TEXT
)"""

_INSERT_STATE = (
    "INSERT INTO bot_state VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
)

_INSERT_COMMAND = (
    "INSERT INTO bot_commands VALUES (%s, %s, %s, %s, %s, %s)"
)


@dataclass
class BotStateRow:
    tick: int
    bot_id: int
    alive: bool
    team: int
    health: int
    pos_x: float
    pos_y: float
    pos_z: float


@dataclass
class BotCommandRow:
    tick: int
    bot_id: int
    target_x: float
    target_y: float
    target_z: float
    profile: str


class TelemetryClient:
    """Buffered writer that INSERTs telemetry rows into PostgreSQL."""

    def __init__(self, host: str = "localhost", port: int = 5432) -> None:
        conninfo = f"host={host} port={port} dbname=telemetry user=smartbots password=smartbots"
        self._conn = psycopg.connect(conninfo, autocommit=False)
        self._conn.execute(_CREATE_STATE_TABLE)
        self._conn.execute(_CREATE_COMMANDS_TABLE)
        self._conn.commit()
        self._state_buf: list[tuple[object, ...]] = []
        self._cmd_buf: list[tuple[object, ...]] = []
        self._last_flush = time.monotonic()
        self._total_rows = 0
        log.info("Telemetry connected to PostgreSQL at %s:%d", host, port)

    def record_state(self, rows: list[BotStateRow]) -> None:
        for row in rows:
            self._state_buf.append(astuple(row))
        self._maybe_flush()

    def record_commands(self, rows: list[BotCommandRow]) -> None:
        for row in rows:
            self._cmd_buf.append(astuple(row))
        self._maybe_flush()

    def _maybe_flush(self) -> None:
        total = len(self._state_buf) + len(self._cmd_buf)
        now = time.monotonic()
        if total >= FLUSH_ROWS or (now - self._last_flush) >= FLUSH_INTERVAL_SEC:
            self._flush()

    def _flush(self) -> None:
        if not self._state_buf and not self._cmd_buf:
            return
        try:
            with self._conn.cursor() as cur:
                if self._state_buf:
                    cur.executemany(_INSERT_STATE, self._state_buf)
                if self._cmd_buf:
                    cur.executemany(_INSERT_COMMAND, self._cmd_buf)
            self._conn.commit()
            flushed = len(self._state_buf) + len(self._cmd_buf)
            self._total_rows += flushed
            if self._total_rows % 5000 < flushed:
                log.info("Telemetry: %d rows flushed (%d total)", flushed, self._total_rows)
        except Exception:
            log.exception("Telemetry flush failed")
            try:
                self._conn.rollback()
            except Exception:
                pass
        self._state_buf.clear()
        self._cmd_buf.clear()
        self._last_flush = time.monotonic()

    def close(self) -> None:
        self._flush()
        self._conn.close()
        log.info("Telemetry closed (%d total rows)", self._total_rows)
