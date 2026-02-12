"""Base strategist ABC: observes game state, detects tactical events,
and issues per-area orders for the planner.

Subclasses implement _decide() to choose *how* orders are generated
(LLM call, state machine, etc.)."""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

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

        events = self._detect_events(self._prev_snapshot, curr)

        # Check stalemate (separate timer)
        if not events and self._prev_snapshot is not None:
            if now - self._last_event_time >= 30.0:
                events.append(f"STALEMATE: no change for {int(now - self._last_event_time)}s")

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
        events: list[str],
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
        )

    # ------------------------------------------------------------------
    # Event detection
    # ------------------------------------------------------------------

    def _detect_events(self, prev: _Snapshot | None, curr: _Snapshot) -> list[str]:
        events: list[str] = []

        if prev is None:
            events.append(
                f"ROUND_START: {curr.friendly_alive} friendlies vs {curr.enemy_alive} enemies"
            )
            return events

        # Round restart: everyone was dead, now alive again
        if prev.friendly_alive == 0 and curr.friendly_alive > 0:
            events.append(
                f"ROUND_START: {curr.friendly_alive} friendlies vs {curr.enemy_alive} enemies"
            )
            self._heavy_losses_triggered = False
            return events

        # Friendly casualties
        lost = prev.friendly_ids_alive - curr.friendly_ids_alive
        if lost:
            events.append(
                f"CASUALTY: lost {len(lost)} friendlies ({curr.friendly_alive} remaining)"
            )

        # Enemy down
        killed = prev.enemy_ids_alive - curr.enemy_ids_alive
        if killed:
            events.append(
                f"ENEMY_DOWN: {len(killed)} eliminated ({curr.enemy_alive} remaining)"
            )

        # New contacts
        new_contacts = curr.spotted_enemy_ids - prev.spotted_enemy_ids
        if new_contacts:
            events.append(
                f"CONTACT: {len(new_contacts)} new enemies spotted "
                f"({len(curr.spotted_enemy_ids)} total)"
            )

        # Lost all contact
        if prev.spotted_enemy_ids and not curr.spotted_enemy_ids:
            events.append("LOST_CONTACT: no enemies visible")

        # Heavy losses threshold (trigger once per round)
        if (
            not self._heavy_losses_triggered
            and curr.friendly_total > 0
            and curr.friendly_alive <= curr.friendly_total * 0.5
            and prev.friendly_alive > prev.friendly_total * 0.5
        ):
            self._heavy_losses_triggered = True
            events.append(
                f"HEAVY_LOSSES: below 50% strength "
                f"({curr.friendly_alive}/{curr.friendly_total})"
            )

        return events
