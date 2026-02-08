"""Flow field navigation — shared reverse Dijkstra for multi-bot pathfinding."""

from __future__ import annotations

import heapq
import logging
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartbots.nav_parser import Vector3
    from smartbots.navigation import NavGraph

log = logging.getLogger(__name__)


def _dist(a: Vector3, b: Vector3) -> float:
    return math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2)


@dataclass
class FlowField:
    """Pre-computed navigation field: every area knows its next step toward the goal."""

    goal_area: int
    next_area: dict[int, int]   # area_id → next area toward goal
    cost: dict[int, float]      # area_id → distance to goal

    def extract_path(self, start_area: int, max_steps: int = 500) -> list[int] | None:
        """Follow next_area pointers from *start_area* to goal. Returns area ID path."""
        if start_area not in self.next_area:
            return None
        path = [start_area]
        current = start_area
        for _ in range(max_steps):
            if current == self.goal_area:
                return path
            nxt = self.next_area[current]
            path.append(nxt)
            current = nxt
        return None  # exceeded max steps


def build_flow_field(nav: NavGraph, goal_area: int) -> FlowField:
    """Reverse Dijkstra from *goal_area* — every reachable area gets a next-step pointer."""
    cost: dict[int, float] = {goal_area: 0.0}
    next_area: dict[int, int] = {goal_area: goal_area}
    counter = 0
    open_set: list[tuple[float, int, int]] = [(0.0, counter, goal_area)]
    closed: set[int] = set()

    while open_set:
        current_cost, _, current_id = heapq.heappop(open_set)
        if current_id in closed:
            continue
        closed.add(current_id)

        current_center = nav._centers[current_id]
        current_area = nav.areas[current_id]

        for neighbor_id in current_area.neighbor_ids():
            if neighbor_id not in nav.areas or neighbor_id in closed:
                continue
            neighbor_center = nav._centers[neighbor_id]
            edge_cost = _dist(current_center, neighbor_center)
            tentative = current_cost + edge_cost

            if tentative < cost.get(neighbor_id, float("inf")):
                cost[neighbor_id] = tentative
                # Expanding FROM goal: neighbor's next step is current
                next_area[neighbor_id] = current_id
                counter += 1
                heapq.heappush(open_set, (tentative, counter, neighbor_id))

    log.info(
        "Flow field for goal area %d: %d reachable areas",
        goal_area, len(cost),
    )
    return FlowField(goal_area=goal_area, next_area=next_area, cost=cost)


class FlowFieldCache:
    """Caches flow fields by goal area (nav mesh is static at runtime)."""

    def __init__(self, nav: NavGraph) -> None:
        self._nav = nav
        self._cache: dict[int, FlowField] = {}

    def get(self, goal_area: int) -> FlowField:
        if goal_area not in self._cache:
            self._cache[goal_area] = build_flow_field(self._nav, goal_area)
        return self._cache[goal_area]
