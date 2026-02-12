"""Base strategist ABC: observes game state, detects tactical events,
and issues per-area orders for the planner.

Subclasses implement _decide() to choose *how* orders are generated
(LLM call, state machine, etc.)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from tactical.areas import AreaMap
from tactical.influence_map import WEIGHT_PROFILES
from tactical.planner import Order, Planner
from tactical.state import GameState
from tactical.telemetry import GameEventRow, StrategyDecisionRow, TelemetryClient

log = logging.getLogger(__name__)

VALID_PROFILES = frozenset(WEIGHT_PROFILES.keys())


@dataclass(frozen=True, slots=True)
class _Snapshot:
    timestamp: float
    friendly_alive: int
    friendly_total: int
    enemy_alive: int
    spotted_enemy_ids: frozenset[int]
    friendly_ids_alive: frozenset[int]
    enemy_ids_alive: frozenset[int]
    current_profile: str
    objectives_captured: int
    capping_cp: int
    counter_attack: bool


@dataclass
class TacticalEvent:
    """Structured tactical event with machine-readable fields and human-readable str()."""

    kind: str           # "ROUND_START", "CONTACT", "CASUALTY", "ENEMY_DOWN",
                        # "LOST_CONTACT", "OBJECTIVE_LOST", "HEAVY_LOSSES", "STALEMATE"
    message: str        # pre-built human-readable string (for LLM/logging)
    count: int = 0      # primary count (enemies spotted, friendlies lost, etc.)
    areas: dict[str, int] = field(default_factory=dict)  # area_name → count
    remaining: int = 0  # remaining after event (alive friendlies/enemies)
    total: int = 0      # denominator where applicable

    def __str__(self) -> str:
        return self.message


class BaseStrategist(ABC):
    def __init__(
        self,
        planner: Planner,
        area_map: AreaMap,
        min_interval: float = 12.0,
        telemetry: TelemetryClient | None = None,
    ) -> None:
        self._planner = planner
        self._area_map = area_map
        self._min_interval = min_interval
        self._telemetry = telemetry

        self._pending_state: GameState | None = None
        self._prev_snapshot: _Snapshot | None = None
        self._last_call_time: float = 0.0
        self._last_event_time: float = 0.0

        self._task: asyncio.Task[None] | None = None
        self._heavy_losses_triggered = False

        # Counter-attack tracking (driven by engine's CINSRules::IsCounterAttack flag)
        self._prev_counter_attack: bool = False

        # Round/objective tracking
        self._round_num: int = 0
        self._objective_num: int = 0
        self._prev_objectives_captured: int = 0
        self._round_casualties: int = 0
        self._round_contacts: int = 0
        self._round_enemies_down: int = 0
        self._round_decisions: int = 0
        self._round_start_tick: int = 0

    def update_state(self, state: GameState) -> None:
        """Called from datagram_received -- just stash the latest state."""
        self._pending_state = state

    def start(self) -> None:
        """Start the background polling task on the current event loop."""
        self._task = asyncio.create_task(self._run())
        log.info("Strategist background task started")

    async def close(self) -> None:
        """Cancel the background task."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Strategist tick error")

    async def _tick(self) -> None:
        state = self._pending_state
        if state is None:
            return

        # Don't run during freeze time or between rounds
        if state.phase != "active":
            self._prev_snapshot = None  # reset to avoid stale diffs on resume
            return

        # Don't run if no humans are on playing teams
        has_humans = any(
            not b.is_bot for b in state.bots.values() if b.team > 1
        )
        if not has_humans:
            return

        controlled = self._planner.controlled_team
        friendly_alive = [
            b for b in state.bots.values()
            if b.alive and b.team == controlled
        ]
        if not friendly_alive:
            return

        curr = self._take_snapshot(state, controlled)
        now = curr.timestamp

        events = self._detect_events(self._prev_snapshot, curr, state)

        # Counter-attack management (driven by CINSRules::IsCounterAttack engine flag)
        if state.counter_attack and not self._prev_counter_attack:
            events.append(TacticalEvent(
                kind="COUNTER_ATTACK",
                message="COUNTER_ATTACK: engine flag active",
            ))
            log.info("Counter-attack started (engine flag)")
        elif not state.counter_attack and self._prev_counter_attack:
            events.append(TacticalEvent(
                kind="COUNTER_ATTACK_END",
                message="COUNTER_ATTACK_END: engine flag cleared",
            ))
            log.info("Counter-attack ended (engine flag)")
        self._prev_counter_attack = state.counter_attack

        # Check stalemate (separate timer)
        if not events and self._prev_snapshot is not None:
            if now - self._last_event_time >= 30.0:
                events.append(TacticalEvent(
                    kind="STALEMATE",
                    message=f"STALEMATE: no change for {int(now - self._last_event_time)}s",
                ))

        if events:
            self._last_event_time = now

        # Round/objective tracking
        self._update_round_tracking(events, curr, state)

        # Record game events to telemetry
        if events and self._telemetry is not None:
            self._record_events(events, curr, state)

        self._prev_snapshot = curr

        if not events:
            return

        # Rate limiting
        if now - self._last_call_time < self._min_interval:
            log.debug("Strategist: rate limited, skipping decision (events: %s)", events)
            return

        # Build enemy positions for area mapping
        enemy_positions: list[tuple[float, float, float]] = []
        for b in state.bots.values():
            if b.alive and b.team != controlled and b.team > 1:
                if b.id in curr.spotted_enemy_ids:
                    enemy_positions.append(b.pos)

        log.info("Strategist: triggering decision -- events: %s", events)
        self._last_call_time = now

        reasoning, orders = await self._decide(curr, events, enemy_positions)

        if orders is not None:
            self._planner.orders = orders
            self._planner.profile_name = orders[0].posture
            summary = ", ".join(
                f"{o.posture}@{'+'.join(o.areas)}({o.bots})" for o in orders
            )
            log.info("Strategist: area orders: %s (%s)", summary, reasoning)

            # Record decision to telemetry
            self._round_decisions += 1
            if self._telemetry is not None:
                self._record_decision(curr, events, reasoning, orders)

    # ------------------------------------------------------------------
    # Abstract decision method
    # ------------------------------------------------------------------

    @abstractmethod
    async def _decide(
        self,
        snapshot: _Snapshot,
        events: list[TacticalEvent],
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str | None, list[Order] | None]:
        """Return (reasoning, orders) or (None, None) to skip this tick."""
        ...

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def _take_snapshot(self, state: GameState, controlled_team: int) -> _Snapshot:
        friendly_alive_ids: set[int] = set()
        friendly_total = 0
        enemy_alive_ids: set[int] = set()
        spotted: set[int] = set()

        for b in state.bots.values():
            if b.team == controlled_team:
                friendly_total += 1
                if b.alive:
                    friendly_alive_ids.add(b.id)
                    spotted.update(b.sees)
            elif b.team > 1:
                if b.alive:
                    enemy_alive_ids.add(b.id)

        now = time.monotonic()
        return _Snapshot(
            timestamp=now,
            friendly_alive=len(friendly_alive_ids),
            friendly_total=friendly_total,
            enemy_alive=len(enemy_alive_ids),
            spotted_enemy_ids=frozenset(spotted & enemy_alive_ids),
            friendly_ids_alive=frozenset(friendly_alive_ids),
            enemy_ids_alive=frozenset(enemy_alive_ids),
            current_profile=self._planner.profile_name,
            objectives_captured=state.objectives_captured,
            capping_cp=state.capping_cp,
            counter_attack=state.counter_attack,
        )

    # ------------------------------------------------------------------
    # Area helpers for event enrichment
    # ------------------------------------------------------------------

    def _area_counts(self, bot_ids: set[int] | frozenset[int], state: GameState) -> dict[str, int]:
        """Map bot IDs to area names, return {area_name: count}."""
        counts: dict[str, int] = {}
        for bid in bot_ids:
            bot = state.bots.get(bid)
            if bot is None:
                continue
            area = self._area_map.pos_to_area(bot.pos)
            if area:
                counts[area] = counts.get(area, 0) + 1
        return counts

    @staticmethod
    def _fmt_areas(areas: dict[str, int]) -> str:
        """Format area counts as ' in courtyard (2), lobby' or '' if empty."""
        if not areas:
            return ""
        parts = [f"{name} ({n})" if n > 1 else name for name, n in areas.items()]
        return " in " + ", ".join(parts)

    # ------------------------------------------------------------------
    # Event detection
    # ------------------------------------------------------------------

    def _detect_events(self, prev: _Snapshot | None, curr: _Snapshot, state: GameState) -> list[TacticalEvent]:
        events: list[TacticalEvent] = []

        if prev is None:
            events.append(TacticalEvent(
                kind="ROUND_START",
                message=f"ROUND_START: {curr.friendly_alive} friendlies vs {curr.enemy_alive} enemies",
                count=curr.friendly_alive, remaining=curr.enemy_alive,
            ))
            return events

        # Wave respawn: new friendly bots appeared mid-round.
        # Note: real round restarts go through phase="preround" which resets
        # _prev_snapshot to None, hitting the prev is None check above.
        # If we reach here with prev valid, phase stayed "active" → wave respawn.
        gained = curr.friendly_ids_alive - prev.friendly_ids_alive
        if len(gained) >= 3:
            events.append(TacticalEvent(
                kind="WAVE_RESPAWN",
                message=f"WAVE_RESPAWN: {len(gained)} friendlies spawned "
                        f"({curr.friendly_alive}/{curr.friendly_total} alive)",
                count=len(gained), remaining=curr.friendly_alive,
                total=curr.friendly_total,
            ))
            self._heavy_losses_triggered = False

        # Friendly casualties
        lost = prev.friendly_ids_alive - curr.friendly_ids_alive
        if lost:
            areas = self._area_counts(lost, state)
            where = self._fmt_areas(areas)
            events.append(TacticalEvent(
                kind="CASUALTY",
                message=f"CASUALTY: lost {len(lost)} friendlies{where} ({curr.friendly_alive} remaining)",
                count=len(lost), areas=areas, remaining=curr.friendly_alive,
            ))

        # Enemy down
        killed = prev.enemy_ids_alive - curr.enemy_ids_alive
        if killed:
            areas = self._area_counts(killed, state)
            where = self._fmt_areas(areas)
            events.append(TacticalEvent(
                kind="ENEMY_DOWN",
                message=f"ENEMY_DOWN: {len(killed)} eliminated{where} ({curr.enemy_alive} remaining)",
                count=len(killed), areas=areas, remaining=curr.enemy_alive,
            ))

        # New contacts
        new_contacts = curr.spotted_enemy_ids - prev.spotted_enemy_ids
        if new_contacts:
            areas = self._area_counts(new_contacts, state)
            where = self._fmt_areas(areas)
            events.append(TacticalEvent(
                kind="CONTACT",
                message=f"CONTACT: {len(new_contacts)} new enemies spotted{where} "
                        f"({len(curr.spotted_enemy_ids)} total)",
                count=len(new_contacts), areas=areas,
                remaining=len(curr.spotted_enemy_ids),
            ))

        # Lost all contact
        if prev.spotted_enemy_ids and not curr.spotted_enemy_ids:
            events.append(TacticalEvent(
                kind="LOST_CONTACT",
                message="LOST_CONTACT: no enemies visible",
            ))

        # Objective lost
        if curr.objectives_captured > prev.objectives_captured:
            events.append(TacticalEvent(
                kind="OBJECTIVE_LOST",
                message=f"OBJECTIVE_LOST: objective #{curr.objectives_captured} captured by enemy "
                        f"({curr.objectives_captured} total lost)",
                count=curr.objectives_captured, total=curr.objectives_captured,
            ))

        # Capture in progress
        if curr.capping_cp >= 0 and (prev is None or prev.capping_cp != curr.capping_cp):
            events.append(TacticalEvent(
                kind="CAPTURE_START",
                message=f"CAPTURE_START: enemy capturing point {curr.capping_cp}",
                count=curr.capping_cp,
            ))

        # Heavy losses threshold (trigger once per round)
        if (
            not self._heavy_losses_triggered
            and curr.friendly_total > 0
            and curr.friendly_alive <= curr.friendly_total * 0.5
            and prev.friendly_alive > prev.friendly_total * 0.5
        ):
            self._heavy_losses_triggered = True
            events.append(TacticalEvent(
                kind="HEAVY_LOSSES",
                message=f"HEAVY_LOSSES: below 50% strength "
                        f"({curr.friendly_alive}/{curr.friendly_total})",
                count=curr.friendly_alive, total=curr.friendly_total,
            ))

        return events

    # ------------------------------------------------------------------
    # Round / objective tracking
    # ------------------------------------------------------------------

    def _update_round_tracking(
        self, events: list[TacticalEvent], curr: _Snapshot, state: GameState,
    ) -> None:
        """Update round_num, objective_num based on events. Manage round lifecycle.

        Round = one full game attempt (all waves). Detected by objectives_captured
        going DOWN (engine resets on game_end / changelevel). Wave respawns within
        the same attempt keep objectives_captured the same or higher.
        """
        for ev in events:
            if ev.kind == "ROUND_START":
                obj = curr.objectives_captured
                if self._round_num == 0:
                    # First spawn of session → round 1
                    self._round_num = 1
                    self._objective_num = obj
                    self._start_new_round(curr, state)
                elif obj < self._prev_objectives_captured:
                    # objectives went DOWN → map restart → new round
                    self._end_current_round(curr, state)
                    self._round_num += 1
                    self._objective_num = obj
                    self._start_new_round(curr, state)
                else:
                    # Wave respawn within same round — don't reset counters.
                    # Objectives may have advanced during non-active phase.
                    if obj > self._prev_objectives_captured:
                        self._objective_num = obj
                        log.info(
                            "Objective advanced during respawn: %d → %d",
                            self._prev_objectives_captured, obj,
                        )
            elif ev.kind == "OBJECTIVE_LOST":
                self._objective_num = curr.objectives_captured
            elif ev.kind == "CASUALTY":
                self._round_casualties += ev.count
            elif ev.kind == "CONTACT":
                self._round_contacts += ev.count
            elif ev.kind == "ENEMY_DOWN":
                self._round_enemies_down += ev.count

        self._prev_objectives_captured = curr.objectives_captured

    def _start_new_round(self, curr: _Snapshot, state: GameState) -> None:
        """Reset round counters and record round start."""
        self._round_casualties = 0
        self._round_contacts = 0
        self._round_enemies_down = 0
        self._round_decisions = 0
        self._round_start_tick = state.tick
        if self._telemetry is not None:
            self._telemetry.start_round(self._round_num, state.tick)

    def _end_current_round(self, curr: _Snapshot, state: GameState) -> None:
        """Finalize the previous round summary."""
        if self._round_num == 0 or self._telemetry is None:
            return
        obj_areas = [
            a for a in self._area_map.areas.values() if a.role == "objective"
        ]
        total_objectives = len(obj_areas) if obj_areas else 1
        round_won = self._prev_objectives_captured >= total_objectives
        self._telemetry.end_round(
            round_num=self._round_num,
            tick=state.tick,
            objectives_completed=self._prev_objectives_captured,
            round_won=round_won,
            total_casualties=self._round_casualties,
            total_contacts=self._round_contacts,
            total_enemies_down=self._round_enemies_down,
            total_decisions=self._round_decisions,
        )

    # ------------------------------------------------------------------
    # Telemetry recording helpers
    # ------------------------------------------------------------------

    def _record_events(
        self, events: list[TacticalEvent], curr: _Snapshot, state: GameState,
    ) -> None:
        rows = [
            GameEventRow(
                tick=state.tick,
                round_num=self._round_num if self._round_num > 0 else None,
                objective_num=self._objective_num,
                kind=ev.kind,
                message=ev.message,
                count=ev.count,
                remaining=ev.remaining,
                total=ev.total,
                areas_json=json.dumps(ev.areas) if ev.areas else None,
                friendly_alive=curr.friendly_alive,
                enemy_alive=curr.enemy_alive,
                objectives_captured=curr.objectives_captured,
            )
            for ev in events
        ]
        self._telemetry.record_game_events(rows)  # type: ignore[union-attr]

    def _record_decision(
        self,
        curr: _Snapshot,
        events: list[TacticalEvent],
        reasoning: str | None,
        orders: list[Order],
    ) -> None:
        state = self._pending_state
        tick = state.tick if state else 0
        orders_data = [
            {"areas": o.areas, "posture": o.posture, "bots": o.bots}
            for o in orders
        ]
        trigger_data = [
            {"kind": ev.kind, "areas": ev.areas}
            for ev in events
        ]
        row = StrategyDecisionRow(
            tick=tick,
            round_num=self._round_num if self._round_num > 0 else None,
            objective_num=self._objective_num,
            state=self._get_state_name(),
            prev_state=self._get_prev_state_name(),
            friendly_alive=curr.friendly_alive,
            friendly_total=curr.friendly_total,
            enemy_alive=curr.enemy_alive,
            spotted_count=len(curr.spotted_enemy_ids),
            objectives_captured=curr.objectives_captured,
            reasoning=reasoning,
            orders_json=json.dumps(orders_data),
            trigger_events=json.dumps(trigger_data),
            threat_map_json=self._get_threat_map_json(),
        )
        self._telemetry.record_decision(row)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Overridable hooks for subclass state info
    # ------------------------------------------------------------------

    def _get_state_name(self) -> str:
        """Current strategist state name. Override in subclasses."""
        return "UNKNOWN"

    def _get_prev_state_name(self) -> str | None:
        """Previous strategist state name. Override in subclasses."""
        return None

    def _get_threat_map_json(self) -> str | None:
        """JSON representation of threat map. Override in subclasses."""
        return None
