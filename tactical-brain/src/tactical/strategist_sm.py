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
from collections import deque

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
                # Engage if contact is in objective area, its neighbors, or any corridor
                obj_name = self._active_objective(snapshot)
                if obj_name:
                    engage_zones = {obj_name} | set(self._areas_near(obj_name))
                    engage_zones.update(self._approach_corridors(obj_name))
                    contact_areas: set[str] = set()
                    for e in events:
                        if e.kind == "CONTACT":
                            contact_areas.update(e.areas)
                    if contact_areas & engage_zones:
                        self._transition(_State.ENGAGE, now)
                    # else: enemies outside corridor net, stay HOLD
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
    #
    # Each generator names only the TARGET area(s).  The planner auto-
    # expands to adjacent rooms so bots have space to spread.
    # ------------------------------------------------------------------

    def _approach_corridors(self, obj_name: str) -> list[str]:
        """Discover corridor zones between enemy approach areas and the objective.

        Works on the zone-only adjacency subgraph (ignoring objective/spawn
        nodes whose asymmetric edges break disjoint-path finding).  Does a
        depth-limited BFS from each approach zone; the depth limit is the
        shortest zone-graph distance to the objective zone + 1, so alternate
        routes one hop longer than the shortest are included.

        Returns zone names sorted by hop distance from approach (forward first).
        """
        approaches = self._approach_areas()
        if not approaches:
            return []

        zones = self._area_map.zones  # zone-only subset
        # Zone-only adjacency subgraph
        zone_adj: dict[str, list[str]] = {
            name: [n for n in self._area_map._adjacency.get(name, []) if n in zones]
            for name in zones
        }

        # Map approach areas and objective to their containing zones
        approach_zones: set[str] = set()
        for a in approaches:
            area = self._area_map.areas.get(a)
            if area:
                z = self._area_map.pos_to_zone(area.center)
                if z:
                    approach_zones.add(z)

        obj_area = self._area_map.areas.get(obj_name)
        obj_zone = self._area_map.pos_to_zone(obj_area.center) if obj_area else None
        if not obj_zone or not approach_zones:
            return []

        # Longest zone-graph distance from any approach zone to objective zone
        # (use max so the depth covers the farthest approach route)
        max_dist: int | None = None
        for az in approach_zones:
            path = self._area_map._bfs_path(az, obj_zone)
            if path is not None:
                d = len(path) - 1
                if max_dist is None or d > max_dist:
                    max_dist = d
        if max_dist is None:
            return []

        # Depth-limited BFS from all approach zones through zone-only graph
        max_depth = max_dist + 1
        zone_hop: dict[str, int] = {}
        queue: deque[tuple[str, int]] = deque()
        for az in approach_zones:
            zone_hop[az] = 0
            queue.append((az, 0))
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in zone_adj.get(current, []):
                if neighbor not in zone_hop:
                    zone_hop[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))

        # Exclude approach zones and objective zone
        exclude = approach_zones | {obj_zone}
        corridors = {z: h for z, h in zone_hop.items() if z not in exclude}

        return sorted(corridors, key=lambda z: corridors[z])

    def _orders_setup(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """First seconds after round start: deploy to corridors immediately."""
        reason, orders = self._orders_hold(snapshot, enemy_positions)
        return f"setup: {reason.split(': ', 1)[-1]}", orders

    def _orders_hold(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Distribute bots across corridor zones for crossfire coverage."""
        n = snapshot.friendly_alive
        obj_name = self._active_objective(snapshot)
        if not obj_name:
            return "hold: no objective", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]

        corridors = self._approach_corridors(obj_name)
        if not corridors:
            # No corridors found — fall back to all on objective
            return "hold: defending objective", [
                Order(areas=[obj_name], posture="defend", bots=n),
            ]

        n_obj = max(1, n // 5)          # ~20% backstop
        n_corridor = n - n_obj
        per_zone = max(1, n_corridor // len(corridors))

        orders: list[Order] = []
        assigned = 0
        for zone in corridors:
            bots = min(per_zone, n_corridor - assigned)
            if bots > 0:
                orders.append(Order(areas=[zone], posture="defend", bots=bots))
                assigned += bots

        # Leftover to first (most forward) corridor
        leftover = n_corridor - assigned
        if leftover > 0 and orders:
            first = orders[0]
            orders[0] = Order(areas=first.areas, posture=first.posture, bots=first.bots + leftover)

        orders.append(Order(areas=[obj_name], posture="defend", bots=n_obj))

        zone_str = ", ".join(corridors[:3])
        if len(corridors) > 3:
            zone_str += f" +{len(corridors) - 3}"
        return f"hold: corridor net [{zone_str}]", orders

    def _orders_engage(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Enemies spotted: push hotspot, flank from adjacent corridors, backstop objective."""
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
                combined[area] = 0

        if combined:
            hotspot = max(combined, key=lambda a: combined[a])

            corridors = self._approach_corridors(obj_name) if obj_name else []
            hotspot_neighbors = [z for z in corridors if z in self._areas_near(hotspot)]

            n_push = max(2, n // 3)
            n_obj = max(1, n // 5)
            n_flank = n - n_push - n_obj

            orders: list[Order] = [
                Order(areas=[hotspot], posture="push", bots=n_push),
            ]

            if hotspot_neighbors and n_flank > 0:
                orders.append(
                    Order(areas=hotspot_neighbors, posture="defend", bots=n_flank),
                )
            elif n_flank > 0:
                # No flanking zones available — reinforce push
                first = orders[0]
                orders[0] = Order(areas=first.areas, posture=first.posture, bots=first.bots + n_flank)

            if obj_name:
                orders.append(
                    Order(areas=[obj_name], posture="defend", bots=n_obj),
                )
            return f"engage: push {hotspot}, flank {hotspot_neighbors}", orders

        return self._orders_hold(snapshot, enemy_positions)

    def _orders_fallback(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Heavy losses: tight defense around objective."""
        n = snapshot.friendly_alive
        obj_name = self._active_objective(snapshot)
        if not obj_name:
            return "fallback: no objective", [
                Order(areas=self._all_area_names(), posture="defend", bots=n),
            ]
        n_defend = max(1, round(n * 0.75))
        n_sniper = n - n_defend
        orders: list[Order] = [
            Order(areas=[obj_name], posture="defend", bots=n_defend),
        ]
        if n_sniper > 0:
            orders.append(
                Order(areas=[obj_name], posture="sniper", bots=n_sniper),
            )
        return "fallback: tight defense", orders

    def _orders_counter_attack(
        self,
        snapshot: _Snapshot,
        enemy_positions: list[tuple[float, float, float]],
    ) -> tuple[str, list[Order]]:
        """Counter-attack: push to retake the objective that was just lost."""
        n = snapshot.friendly_alive
        objectives = self._objective_areas()
        idx = snapshot.objectives_lost - 1
        lost_obj = objectives[idx] if 0 <= idx < len(objectives) else None

        if not lost_obj:
            return "counter-attack: pushing all", [
                Order(areas=self._all_area_names(), posture="push", bots=n),
            ]

        return f"counter-attack: pushing {lost_obj}", [
            Order(areas=[lost_obj], posture="push", bots=n),
        ]

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
