"""State-machine strategist: deterministic team-level tactics without API calls.

NextBot-style state machine for defensive team coordination.

    SETUP  -->  HOLD  <-->  ENGAGE
                  |           |
                  |        FALLBACK  -->  HOLD
                  |
    any  --OBJECTIVE_LOST-->  COUNTER_ATTACK  --timer-->  HOLD
"""

from __future__ import annotations

import enum
import json
import logging
import time

from tactical.areas import AreaMap
from tactical.planner import Order, Planner
from tactical.strategist import BaseStrategist, TacticalEvent, _Snapshot
from tactical.telemetry import TelemetryClient

log = logging.getLogger(__name__)


class _State(enum.Enum):
    SETUP = "SETUP"
    HOLD = "HOLD"
    ENGAGE = "ENGAGE"
    FALLBACK = "FALLBACK"
    COUNTER_ATTACK = "COUNTER_ATTACK"


THREAT_DECAY_SECS = 20.0


class SMStrategist(BaseStrategist):
    def __init__(
        self,
        planner: Planner,
        area_map: AreaMap,
        min_interval: float = 5.0,
        telemetry: TelemetryClient | None = None,
    ) -> None:
        super().__init__(planner, area_map, min_interval=min_interval, telemetry=telemetry)
        self._state = _State.SETUP
        self._prev_state: _State = _State.SETUP
        self._state_enter_time: float = 0.0
        self._threat_map: dict[str, float] = {}  # area_name → last_threat_time

    # ------------------------------------------------------------------
    # Threat memory
    # ------------------------------------------------------------------

    def _active_threats(self, now: float) -> dict[str, float]:
        """Return {area: seconds_since_last_threat} for non-expired threats."""
        active = {}
        for area, t in self._threat_map.items():
            age = now - t
            if age < THREAT_DECAY_SECS:
                active[area] = age
        return active

    # ------------------------------------------------------------------
    # Decision: process events → transition → generate orders
    # ------------------------------------------------------------------

    async def _decide(
        self,
        snapshot: _Snapshot,
        events: list[TacticalEvent],
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str | None, list[Order] | None]:
        now = snapshot.timestamp

        # Classify events
        has_round_start = any(e.kind == "ROUND_START" for e in events)
        has_contact = any(e.kind == "CONTACT" for e in events)
        has_heavy_losses = any(e.kind == "HEAVY_LOSSES" for e in events)
        has_objective_lost = any(e.kind == "OBJECTIVE_LOST" for e in events)
        has_capture_start = any(e.kind == "CAPTURE_START" for e in events)
        has_counter_attack = any(e.kind == "COUNTER_ATTACK" for e in events)
        has_counter_attack_end = any(e.kind == "COUNTER_ATTACK_END" for e in events)

        # Update threat map from events
        for e in events:
            if e.kind in ("CONTACT", "CASUALTY"):
                for area in e.areas:
                    self._threat_map[area] = now

        # Update threat map from currently visible enemies
        if enemy_positions:
            visible_areas = self._area_map.enemies_per_area(enemy_positions)
            for area in visible_areas:
                self._threat_map[area] = now

        # --- State transitions ---
        if has_round_start:
            self._threat_map.clear()
            self._transition(_State.SETUP, now)
        elif has_counter_attack:
            self._transition(_State.COUNTER_ATTACK, now)
        elif self._state == _State.COUNTER_ATTACK:
            if has_counter_attack_end:
                self._transition(_State.HOLD, now)
            # Stay in COUNTER_ATTACK — ignore HEAVY_LOSSES / CAPTURE_START
        elif has_objective_lost:
            # Objective lost but no counter-attack confirmed yet — hold position
            self._transition(_State.HOLD, now)
        elif has_heavy_losses:
            self._transition(_State.FALLBACK, now)
        elif has_capture_start:
            self._transition(_State.ENGAGE, now)
        elif self._state == _State.SETUP:
            if now - self._state_enter_time >= 5.0:
                self._transition(_State.HOLD, now)
        elif self._state == _State.HOLD:
            if has_contact:
                # Only engage if contact is near objective or adjacent areas
                obj_name = self._active_objective(snapshot)
                if obj_name:
                    near_obj = {obj_name} | set(self._areas_near(obj_name))
                    contact_areas: set[str] = set()
                    for e in events:
                        if e.kind == "CONTACT":
                            contact_areas.update(e.areas)
                    if contact_areas & near_obj:
                        self._transition(_State.ENGAGE, now)
                    # else: enemies far from objective, stay HOLD
                else:
                    self._transition(_State.ENGAGE, now)
        elif self._state == _State.ENGAGE:
            if not self._active_threats(now):
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
            _State.COUNTER_ATTACK: self._orders_counter_attack,
        }
        return dispatch[self._state](snapshot, enemy_positions)

    def _transition(self, new_state: _State, now: float) -> None:
        old = self._state
        self._prev_state = old
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

    def _active_objective(self, snapshot: _Snapshot) -> str | None:
        """Return the name of the objective we should be defending."""
        objectives = self._objective_areas()
        if not objectives:
            return None
        idx = min(snapshot.objectives_lost, len(objectives) - 1)
        return objectives[idx]

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

    def _defend_allocation(
        self, n: int, obj_name: str,
    ) -> tuple[int, list[str], list[str]]:
        """Compute defend count, defend areas, and adjacent areas for an objective.

        Excludes other objectives from adjacent list so bots don't leak
        into neighboring objectives (e.g. obj_c_basement → obj_d_upper).

        Returns (n_defend, defend_areas, adjacent).
        """
        adjacent = [
            a for a in self._areas_near(obj_name)
            if self._area_map.areas[a].role != "objective"
        ]
        n_per_approach = 2
        n_defend = min(n, 1 + len(adjacent) * n_per_approach)
        defend_areas = [obj_name] + adjacent
        return n_defend, defend_areas, adjacent

    def _orders_setup(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """First seconds after round start: deploy to objective + ambush approaches."""
        approaches = self._approach_areas()
        n = snapshot.friendly_alive
        obj_name = self._active_objective(snapshot)

        if not obj_name:
            return "setup: defending all areas", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        n_defend, defend_areas, _ = self._defend_allocation(n, obj_name)
        orders: list[Order] = [Order(areas=defend_areas, posture="defend", bots=n_defend)]

        rest = n - n_defend
        if rest > 0 and approaches:
            orders.append(Order(areas=approaches, posture="ambush", bots=rest))
        elif rest > 0:
            orders[0] = Order(areas=defend_areas, posture="defend", bots=n)

        return "setup: initial deployment", orders

    def _orders_hold(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Default: defend objective, ambush approaches."""
        approaches = self._approach_areas()
        n = snapshot.friendly_alive
        obj_name = self._active_objective(snapshot)

        if not obj_name:
            return "hold: defending all areas", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        n_defend, defend_areas, _ = self._defend_allocation(n, obj_name)
        orders: list[Order] = [Order(areas=defend_areas, posture="defend", bots=n_defend)]

        rest = n - n_defend
        if rest > 0 and approaches:
            orders.append(Order(areas=approaches, posture="ambush", bots=rest))
        elif rest > 0:
            orders[0] = Order(areas=defend_areas, posture="defend", bots=n)

        return "hold: defending objective", orders

    def _orders_engage(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Enemies spotted: push toward contact area, defend the rest."""
        n = snapshot.friendly_alive
        obj_name = self._active_objective(snapshot)
        now = snapshot.timestamp

        # Merge current sightings with threat memory
        enemies_by_area = self._area_map.enemies_per_area(enemy_positions)
        threats = self._active_threats(now)

        combined: dict[str, int] = {}
        for area, count in enemies_by_area.items():
            combined[area] = count
        for area in threats:
            if area not in combined:
                combined[area] = 0  # known threat, no current count

        if combined:
            hottest = max(combined, key=lambda a: combined[a])

            if obj_name:
                n_defend, defend_areas, _ = self._defend_allocation(n, obj_name)
                n_push = n - n_defend
            else:
                n_push = max(1, round(n * 0.5))
                n_defend = n - n_push
                defend_areas = []

            orders: list[Order] = []
            if n_push > 0:
                orders.append(
                    Order(areas=[hottest], posture="push", bots=n_push),
                )
            if obj_name and n_defend > 0:
                orders.append(
                    Order(areas=defend_areas, posture="defend", bots=n_defend),
                )
            return f"engage: pushing {hottest}", orders

        # No enemies located and no threat memory — fall back to hold posture
        return self._orders_hold(snapshot, enemy_positions)

    def _orders_fallback(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Heavy losses: tight defense around objective, sniper on flanks."""
        n = snapshot.friendly_alive
        obj_name = self._active_objective(snapshot)

        if not obj_name:
            return "fallback: defending all areas", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        n_defend, defend_areas, adjacent = self._defend_allocation(n, obj_name)
        n_sniper = n - n_defend

        orders: list[Order] = [
            Order(areas=defend_areas, posture="defend", bots=n_defend),
        ]

        if n_sniper > 0 and adjacent:
            orders.append(
                Order(areas=adjacent, posture="sniper", bots=n_sniper),
            )
        elif n_sniper > 0:
            orders[0] = Order(areas=defend_areas, posture="defend", bots=n)

        return "fallback: tight defense", orders

    def _orders_counter_attack(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Counter-attack: push to retake the objective that was just lost."""
        n = snapshot.friendly_alive
        approaches = self._approach_areas()

        # objectives_lost already incremented — go back one to get the lost objective
        objectives = self._objective_areas()
        idx = snapshot.objectives_lost - 1
        lost_obj = objectives[idx] if 0 <= idx < len(objectives) else None

        if not lost_obj:
            return "counter-attack: pushing all", [
                Order(areas=self._all_area_names(), posture="push", bots=n),
            ]

        adjacent = [
            a for a in self._areas_near(lost_obj)
            if self._area_map.areas[a].role != "objective"
        ]
        n_per_approach = 2
        n_push = min(n, 1 + len(adjacent) * n_per_approach + 2)  # slightly more for aggression
        n_flank = n - n_push

        push_areas = [lost_obj] + adjacent
        orders: list[Order] = [Order(areas=push_areas, posture="push", bots=n_push)]

        if n_flank > 0 and approaches:
            orders.append(Order(areas=approaches, posture="push", bots=n_flank))
        elif n_flank > 0:
            orders[0] = Order(areas=push_areas, posture="push", bots=n)

        return f"counter-attack: pushing {lost_obj}", orders

    # ------------------------------------------------------------------
    # Telemetry hooks
    # ------------------------------------------------------------------

    def _get_state_name(self) -> str:
        return self._state.value

    def _get_prev_state_name(self) -> str | None:
        return self._prev_state.value

    def _get_threat_map_json(self) -> str | None:
        now = time.monotonic()
        active = self._active_threats(now)
        if not active:
            return None
        return json.dumps({area: round(age, 1) for area, age in active.items()})
