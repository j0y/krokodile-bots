"""State-machine strategist: deterministic team-level tactics without API calls.

NextBot-style state machine for defensive team coordination.

    SETUP  -->  HOLD  <-->  ENGAGE
                             |
                          FALLBACK  -->  HOLD
"""

from __future__ import annotations

import enum
import logging

from tactical.areas import AreaMap
from tactical.planner import Order, Planner
from tactical.strategist import BaseStrategist, _Snapshot

log = logging.getLogger(__name__)


class _State(enum.Enum):
    SETUP = "SETUP"
    HOLD = "HOLD"
    ENGAGE = "ENGAGE"
    FALLBACK = "FALLBACK"


class SMStrategist(BaseStrategist):
    def __init__(
        self,
        planner: Planner,
        area_map: AreaMap,
        min_interval: float = 5.0,
    ) -> None:
        super().__init__(planner, area_map, min_interval=min_interval)
        self._state = _State.SETUP
        self._state_enter_time: float = 0.0
        self._last_contact_time: float = 0.0

    # ------------------------------------------------------------------
    # Decision: process events → transition → generate orders
    # ------------------------------------------------------------------

    async def _decide(
        self,
        snapshot: _Snapshot,
        events: list[str],
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str | None, list[Order] | None]:
        now = snapshot.timestamp

        # Classify events
        has_round_start = any(e.startswith("ROUND_START") for e in events)
        has_contact = any(e.startswith("CONTACT") for e in events)
        has_heavy_losses = any(e.startswith("HEAVY_LOSSES") for e in events)

        if has_contact:
            self._last_contact_time = now

        # --- State transitions ---
        if has_round_start:
            self._transition(_State.SETUP, now)
        elif has_heavy_losses:
            self._transition(_State.FALLBACK, now)
        elif self._state == _State.SETUP:
            if now - self._state_enter_time >= 5.0:
                self._transition(_State.HOLD, now)
        elif self._state == _State.HOLD:
            if has_contact:
                self._transition(_State.ENGAGE, now)
        elif self._state == _State.ENGAGE:
            if self._last_contact_time and now - self._last_contact_time >= 15.0:
                self._transition(_State.HOLD, now)
        elif self._state == _State.FALLBACK:
            if now - self._state_enter_time >= 20.0:
                self._transition(_State.HOLD, now)

        # --- Generate orders for current state ---
        dispatch = {
            _State.SETUP: self._orders_setup,
            _State.HOLD: self._orders_hold,
            _State.ENGAGE: self._orders_engage,
            _State.FALLBACK: self._orders_fallback,
        }
        return dispatch[self._state](snapshot, enemy_positions)

    def _transition(self, new_state: _State, now: float) -> None:
        old = self._state
        self._state = new_state
        self._state_enter_time = now
        if old != new_state:
            log.info("SM: [%s] -> [%s]", old.value, new_state.value)

    # ------------------------------------------------------------------
    # Area helpers
    # ------------------------------------------------------------------

    def _objective_areas(self) -> list[str]:
        """Area names with role 'objective', sorted by order."""
        return [
            a.name
            for a in sorted(
                (a for a in self._area_map.areas.values() if a.role == "objective"),
                key=lambda a: a.order,
            )
        ]

    def _approach_areas(self) -> list[str]:
        """Area names where enemies spawn or approach from."""
        return [
            a.name
            for a in self._area_map.areas.values()
            if a.role in ("enemy_spawn", "enemy_approach")
        ]

    def _areas_near(self, area_name: str) -> list[str]:
        """Adjacent areas from the pre-computed adjacency graph."""
        return self._area_map._adjacency.get(area_name, [])

    def _all_area_names(self) -> list[str]:
        return list(self._area_map.areas.keys())

    # ------------------------------------------------------------------
    # Per-state order generators
    # ------------------------------------------------------------------

    def _orders_setup(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """First seconds after round start: deploy to objective + ambush approaches."""
        objectives = self._objective_areas()
        approaches = self._approach_areas()
        n = snapshot.friendly_alive

        if not objectives:
            return "setup: defending all areas", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        obj = [objectives[0]]
        n_defend = max(1, round(n * 0.6))
        orders: list[Order] = [Order(areas=obj, posture="defend", bots=n_defend)]

        rest = n - n_defend
        if rest > 0 and approaches:
            orders.append(Order(areas=approaches, posture="ambush", bots=rest))
        elif rest > 0:
            orders[0] = Order(areas=obj, posture="defend", bots=n)

        return "setup: initial deployment", orders

    def _orders_hold(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Default: defend objective, ambush approaches."""
        objectives = self._objective_areas()
        approaches = self._approach_areas()
        n = snapshot.friendly_alive

        if not objectives:
            return "hold: defending all areas", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        obj = [objectives[0]]
        n_defend = max(1, round(n * 0.6))
        orders: list[Order] = [Order(areas=obj, posture="defend", bots=n_defend)]

        rest = n - n_defend
        if rest > 0 and approaches:
            orders.append(Order(areas=approaches, posture="ambush", bots=rest))
        elif rest > 0:
            orders[0] = Order(areas=obj, posture="defend", bots=n)

        return "hold: defending objective", orders

    def _orders_engage(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Enemies spotted: push toward contact area, defend the rest."""
        objectives = self._objective_areas()
        n = snapshot.friendly_alive

        enemies_by_area = self._area_map.enemies_per_area(enemy_positions)

        if enemies_by_area:
            hottest = max(enemies_by_area, key=enemies_by_area.get)
            n_push = max(1, round(n * 0.5))
            n_defend = n - n_push

            orders: list[Order] = [
                Order(areas=[hottest], posture="push", bots=n_push),
            ]
            if objectives and n_defend > 0:
                orders.append(
                    Order(areas=[objectives[0]], posture="defend", bots=n_defend),
                )
            return f"engage: pushing {hottest}", orders

        # No enemies located — fall back to hold posture
        return self._orders_hold(snapshot, enemy_positions)

    def _orders_fallback(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Heavy losses: tight defense around objective, sniper on flanks."""
        objectives = self._objective_areas()
        n = snapshot.friendly_alive

        if not objectives:
            return "fallback: defending all areas", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        obj_name = objectives[0]
        n_defend = max(1, round(n * 0.8))
        n_sniper = n - n_defend

        orders: list[Order] = [
            Order(areas=[obj_name], posture="defend", bots=n_defend),
        ]

        if n_sniper > 0:
            adjacent = self._areas_near(obj_name)
            if adjacent:
                orders.append(
                    Order(areas=adjacent, posture="sniper", bots=n_sniper),
                )
            else:
                # No flanks known — all on defense
                orders[0] = Order(areas=[obj_name], posture="defend", bots=n)

        return "fallback: tight defense", orders
