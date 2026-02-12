"""Base strategist ABC: observes game state, detects tactical events,
and issues per-area orders for the planner.

Subclasses implement _decide() to choose *how* orders are generated
(LLM call, state machine, etc.)."""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from tactical.areas import AreaMap
from tactical.influence_map import WEIGHT_PROFILES
from tactical.planner import Order, Planner
from tactical.state import GameState

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
    ) -> None:
        self._planner = planner
        self._area_map = area_map
        self._min_interval = min_interval

        self._pending_state: GameState | None = None
        self._prev_snapshot: _Snapshot | None = None
        self._last_call_time: float = 0.0
        self._last_event_time: float = 0.0

        self._task: asyncio.Task[None] | None = None
        self._heavy_losses_triggered = False

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

        # Check stalemate (separate timer)
        if not events and self._prev_snapshot is not None:
            if now - self._last_event_time >= 30.0:
                events.append(TacticalEvent(
                    kind="STALEMATE",
                    message=f"STALEMATE: no change for {int(now - self._last_event_time)}s",
                ))

        if events:
            self._last_event_time = now

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

        return _Snapshot(
            timestamp=time.monotonic(),
            friendly_alive=len(friendly_alive_ids),
            friendly_total=friendly_total,
            enemy_alive=len(enemy_alive_ids),
            spotted_enemy_ids=frozenset(spotted & enemy_alive_ids),
            friendly_ids_alive=frozenset(friendly_alive_ids),
            enemy_ids_alive=frozenset(enemy_alive_ids),
            current_profile=self._planner.profile_name,
            objectives_captured=state.objectives_captured,
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

        # Round restart: everyone was dead, now alive again
        if prev.friendly_alive == 0 and curr.friendly_alive > 0:
            events.append(TacticalEvent(
                kind="ROUND_START",
                message=f"ROUND_START: {curr.friendly_alive} friendlies vs {curr.enemy_alive} enemies",
                count=curr.friendly_alive, remaining=curr.enemy_alive,
            ))
            self._heavy_losses_triggered = False
            return events

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
