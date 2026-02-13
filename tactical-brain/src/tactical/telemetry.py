"""Telemetry — records bot state, game events, and strategy decisions to PostgreSQL."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import astuple, dataclass

import psycopg

log = logging.getLogger(__name__)

FLUSH_ROWS = 500
FLUSH_INTERVAL_SEC = 5.0

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_CREATE_SESSIONS = """\
CREATE TABLE IF NOT EXISTS sessions (
    session_id      UUID PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    map_name        TEXT NOT NULL,
    controlled_team INTEGER NOT NULL,
    strategist_type TEXT NOT NULL
)"""

_CREATE_STATE_TABLE = """\
CREATE TABLE IF NOT EXISTS bot_state (
    session_id UUID NOT NULL,
    tick       INTEGER,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    bot_id     INTEGER,
    alive      BOOLEAN,
    team       INTEGER,
    health     INTEGER,
    pos_x      REAL, pos_y REAL, pos_z REAL,
    is_bot     BOOLEAN
)"""

_CREATE_COMMANDS_TABLE = """\
CREATE TABLE IF NOT EXISTS bot_commands (
    session_id UUID NOT NULL,
    tick       INTEGER,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    bot_id     INTEGER,
    target_x   REAL, target_y REAL, target_z REAL,
    profile    TEXT
)"""

_CREATE_GAME_EVENTS = """\
CREATE TABLE IF NOT EXISTS game_events (
    session_id          UUID NOT NULL,
    tick                INTEGER NOT NULL,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    round_num           INTEGER,
    objective_num       INTEGER,
    kind                TEXT NOT NULL,
    message             TEXT NOT NULL,
    count               INTEGER DEFAULT 0,
    remaining           INTEGER DEFAULT 0,
    total_field         INTEGER DEFAULT 0,
    areas_json          JSONB,
    friendly_alive      INTEGER,
    enemy_alive         INTEGER,
    objectives_lost INTEGER
)"""

_CREATE_STRATEGY_DECISIONS = """\
CREATE TABLE IF NOT EXISTS strategy_decisions (
    session_id          UUID NOT NULL,
    tick                INTEGER NOT NULL,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    round_num           INTEGER,
    objective_num       INTEGER,
    state               TEXT NOT NULL,
    prev_state          TEXT,
    friendly_alive      INTEGER NOT NULL,
    friendly_total      INTEGER NOT NULL,
    enemy_alive         INTEGER NOT NULL,
    spotted_count       INTEGER NOT NULL,
    objectives_lost INTEGER NOT NULL,
    reasoning           TEXT,
    orders_json         JSONB NOT NULL,
    trigger_events      JSONB NOT NULL,
    threat_map_json     JSONB
)"""

_CREATE_ROUND_SUMMARIES = """\
CREATE TABLE IF NOT EXISTS round_summaries (
    session_id       UUID NOT NULL,
    round_num        INTEGER NOT NULL,
    started_tick     INTEGER NOT NULL,
    ended_tick       INTEGER,
    started_ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_ts         TIMESTAMPTZ,
    duration_secs    REAL,
    objectives_completed INTEGER DEFAULT 0,
    round_won        BOOLEAN,
    total_casualties INTEGER DEFAULT 0,
    total_contacts   INTEGER DEFAULT 0,
    total_enemies_down INTEGER DEFAULT 0,
    total_decisions  INTEGER DEFAULT 0,
    PRIMARY KEY (session_id, round_num)
)"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_bot_state_session_tick ON bot_state (session_id, tick)",
    "CREATE INDEX IF NOT EXISTS idx_bot_commands_session_tick ON bot_commands (session_id, tick)",
    "CREATE INDEX IF NOT EXISTS idx_game_events_session_tick ON game_events (session_id, tick)",
    "CREATE INDEX IF NOT EXISTS idx_strategy_decisions_session_tick ON strategy_decisions (session_id, tick)",
]

# ---------------------------------------------------------------------------
# INSERT statements
# ---------------------------------------------------------------------------

_INSERT_STATE = (
    "INSERT INTO bot_state (session_id, tick, bot_id, alive, team, health, pos_x, pos_y, pos_z, is_bot)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_INSERT_COMMAND = (
    "INSERT INTO bot_commands (session_id, tick, bot_id, target_x, target_y, target_z, profile)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s)"
)

_INSERT_GAME_EVENT = (
    "INSERT INTO game_events"
    " (session_id, tick, round_num, objective_num, kind, message,"
    "  count, remaining, total_field, areas_json,"
    "  friendly_alive, enemy_alive, objectives_lost)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_INSERT_DECISION = (
    "INSERT INTO strategy_decisions"
    " (session_id, tick, round_num, objective_num, state, prev_state,"
    "  friendly_alive, friendly_total, enemy_alive, spotted_count,"
    "  objectives_lost, reasoning, orders_json, trigger_events, threat_map_json)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

_INSERT_ROUND_START = (
    "INSERT INTO round_summaries (session_id, round_num, started_tick)"
    " VALUES (%s, %s, %s)"
    " ON CONFLICT (session_id, round_num) DO NOTHING"
)

_UPDATE_ROUND_END = (
    "UPDATE round_summaries"
    " SET ended_tick = %s, ended_ts = now(),"
    "     duration_secs = EXTRACT(EPOCH FROM now() - started_ts),"
    "     objectives_completed = %s, round_won = %s,"
    "     total_casualties = %s, total_contacts = %s,"
    "     total_enemies_down = %s, total_decisions = %s"
    " WHERE session_id = %s AND round_num = %s"
)

# ---------------------------------------------------------------------------
# Dataclasses (callers still use these — session_id is prepended in _flush)
# ---------------------------------------------------------------------------


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
    is_bot: bool


@dataclass
class BotCommandRow:
    tick: int
    bot_id: int
    target_x: float
    target_y: float
    target_z: float
    profile: str


@dataclass
class GameEventRow:
    tick: int
    round_num: int | None
    objective_num: int | None
    kind: str
    message: str
    count: int
    remaining: int
    total: int
    areas_json: str | None  # JSON string
    friendly_alive: int | None
    enemy_alive: int | None
    objectives_lost: int | None


@dataclass
class StrategyDecisionRow:
    tick: int
    round_num: int | None
    objective_num: int | None
    state: str
    prev_state: str | None
    friendly_alive: int
    friendly_total: int
    enemy_alive: int
    spotted_count: int
    objectives_lost: int
    reasoning: str | None
    orders_json: str  # JSON string
    trigger_events: str  # JSON string
    threat_map_json: str | None  # JSON string


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class TelemetryClient:
    """Buffered writer that INSERTs telemetry rows into PostgreSQL."""

    def __init__(
        self,
        session_id: str,
        map_name: str,
        controlled_team: int,
        strategist_type: str,
        host: str = "localhost",
        port: int = 5432,
    ) -> None:
        self.session_id = session_id
        conninfo = f"host={host} port={port} dbname=telemetry user=smartbots password=smartbots"
        self._conn = psycopg.connect(conninfo, autocommit=False)

        # Create all tables + indexes
        for ddl in (
            _CREATE_SESSIONS,
            _CREATE_STATE_TABLE,
            _CREATE_COMMANDS_TABLE,
            _CREATE_GAME_EVENTS,
            _CREATE_STRATEGY_DECISIONS,
            _CREATE_ROUND_SUMMARIES,
        ):
            self._conn.execute(ddl)
        for idx in _CREATE_INDEXES:
            self._conn.execute(idx)
        self._conn.commit()

        # Insert session row
        self._conn.execute(
            "INSERT INTO sessions (session_id, map_name, controlled_team, strategist_type)"
            " VALUES (%s, %s, %s, %s)",
            (session_id, map_name, controlled_team, strategist_type),
        )
        self._conn.commit()

        self._state_buf: list[tuple[object, ...]] = []
        self._cmd_buf: list[tuple[object, ...]] = []
        self._event_buf: list[tuple[object, ...]] = []
        self._decision_buf: list[tuple[object, ...]] = []
        self._last_flush = time.monotonic()
        self._total_rows = 0
        log.info(
            "Telemetry connected (session=%s, map=%s, team=%d, strategist=%s)",
            session_id[:8], map_name, controlled_team, strategist_type,
        )

    # ------------------------------------------------------------------
    # Record methods (buffered)
    # ------------------------------------------------------------------

    def record_state(self, rows: list[BotStateRow]) -> None:
        for row in rows:
            self._state_buf.append((self.session_id,) + astuple(row))
        self._maybe_flush()

    def record_commands(self, rows: list[BotCommandRow]) -> None:
        for row in rows:
            self._cmd_buf.append((self.session_id,) + astuple(row))
        self._maybe_flush()

    def record_game_events(self, rows: list[GameEventRow]) -> None:
        for row in rows:
            self._event_buf.append((self.session_id,) + astuple(row))
        self._maybe_flush()

    def record_decision(self, row: StrategyDecisionRow) -> None:
        self._decision_buf.append((self.session_id,) + astuple(row))
        self._maybe_flush()

    # ------------------------------------------------------------------
    # Round summaries (immediate writes — once per round)
    # ------------------------------------------------------------------

    def start_round(self, round_num: int, tick: int) -> None:
        try:
            self._conn.execute(_INSERT_ROUND_START, (self.session_id, round_num, tick))
            self._conn.commit()
            log.info("Telemetry: started round %d at tick %d", round_num, tick)
        except Exception:
            log.exception("Telemetry: failed to start round %d", round_num)
            try:
                self._conn.rollback()
            except Exception:
                pass

    def end_round(
        self,
        round_num: int,
        tick: int,
        objectives_completed: int,
        round_won: bool,
        total_casualties: int,
        total_contacts: int,
        total_enemies_down: int,
        total_decisions: int,
    ) -> None:
        try:
            self._conn.execute(
                _UPDATE_ROUND_END,
                (
                    tick, objectives_completed, round_won,
                    total_casualties, total_contacts,
                    total_enemies_down, total_decisions,
                    self.session_id, round_num,
                ),
            )
            self._conn.commit()
            log.info(
                "Telemetry: ended round %d (obj=%d, won=%s)",
                round_num, objectives_completed, round_won,
            )
        except Exception:
            log.exception("Telemetry: failed to end round %d", round_num)
            try:
                self._conn.rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Flush
    # ------------------------------------------------------------------

    def _maybe_flush(self) -> None:
        total = (
            len(self._state_buf) + len(self._cmd_buf)
            + len(self._event_buf) + len(self._decision_buf)
        )
        now = time.monotonic()
        if total >= FLUSH_ROWS or (now - self._last_flush) >= FLUSH_INTERVAL_SEC:
            self._flush()

    def _flush(self) -> None:
        if (
            not self._state_buf
            and not self._cmd_buf
            and not self._event_buf
            and not self._decision_buf
        ):
            return
        try:
            with self._conn.cursor() as cur:
                if self._state_buf:
                    cur.executemany(_INSERT_STATE, self._state_buf)
                if self._cmd_buf:
                    cur.executemany(_INSERT_COMMAND, self._cmd_buf)
                if self._event_buf:
                    cur.executemany(_INSERT_GAME_EVENT, self._event_buf)
                if self._decision_buf:
                    cur.executemany(_INSERT_DECISION, self._decision_buf)
            self._conn.commit()
            flushed = (
                len(self._state_buf) + len(self._cmd_buf)
                + len(self._event_buf) + len(self._decision_buf)
            )
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
        self._event_buf.clear()
        self._decision_buf.clear()
        self._last_flush = time.monotonic()

    def close(self) -> None:
        self._flush()
        self._conn.close()
        log.info("Telemetry closed (%d total rows)", self._total_rows)
