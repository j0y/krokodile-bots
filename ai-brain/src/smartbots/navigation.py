"""Navigation graph with A* pathfinding on Source Engine nav meshes."""

from __future__ import annotations

import heapq
import logging
import math
from collections import deque
from pathlib import Path

from smartbots.nav_parser import NavArea, NavMesh, Vector3, parse_nav

log = logging.getLogger(__name__)


def _dist(a: Vector3, b: Vector3) -> float:
    """Euclidean distance between two points."""
    return math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2)


def _dist_sq_2d(ax: float, ay: float, bx: float, by: float) -> float:
    """Squared 2D distance (fast, for comparisons only)."""
    return (ax - bx) ** 2 + (ay - by) ** 2


class NavGraph:
    """Wraps a parsed NavMesh and provides pathfinding."""

    def __init__(self, nav_path: str | Path) -> None:
        log.info("Loading nav mesh from %s", nav_path)
        self.mesh: NavMesh = parse_nav(nav_path)
        self.areas: dict[int, NavArea] = self.mesh.areas

        # Pre-compute centers for fast lookup
        self._centers: dict[int, Vector3] = {
            aid: area.center() for aid, area in self.areas.items()
        }

        log.info(
            "Nav mesh loaded: %d areas, %d ladders",
            len(self.areas),
            len(self.mesh.ladders),
        )

    def area_center(self, area_id: int) -> tuple[float, float, float]:
        """Return the center of an area as (x, y, z)."""
        c = self._centers[area_id]
        return (c.x, c.y, c.z)

    def find_area(self, pos: tuple[float, float, float]) -> int:
        """Find the nav area containing *pos*, or the nearest one by center distance."""
        x, y = pos[0], pos[1]

        # Try containment check first (2D bounding box)
        for aid, area in self.areas.items():
            min_x = min(area.nw.x, area.se.x)
            max_x = max(area.nw.x, area.se.x)
            min_y = min(area.nw.y, area.se.y)
            max_y = max(area.nw.y, area.se.y)
            if min_x <= x <= max_x and min_y <= y <= max_y:
                return aid

        # Fallback: closest center (2D)
        best_id = -1
        best_dist = float("inf")
        for aid, center in self._centers.items():
            d = _dist_sq_2d(x, y, center.x, center.y)
            if d < best_dist:
                best_dist = d
                best_id = aid
        return best_id

    def find_path(self, start_id: int, goal_id: int) -> list[int] | None:
        """A* pathfinding on the nav area graph. Returns area ID list or None."""
        if start_id not in self.areas or goal_id not in self.areas:
            return None
        if start_id == goal_id:
            return [start_id]

        goal_center = self._centers[goal_id]

        # (f_score, tie-breaker counter, area_id)
        counter = 0
        open_set: list[tuple[float, int, int]] = [(0.0, counter, start_id)]
        came_from: dict[int, int] = {}
        g_score: dict[int, float] = {start_id: 0.0}
        closed: set[int] = set()

        while open_set:
            _, _, current = heapq.heappop(open_set)

            if current == goal_id:
                path = [current]
                while current in came_from:
                    current = came_from[current]
                    path.append(current)
                path.reverse()
                return path

            if current in closed:
                continue
            closed.add(current)

            current_center = self._centers[current]
            current_area = self.areas[current]

            for neighbor_id in current_area.neighbor_ids():
                if neighbor_id not in self.areas or neighbor_id in closed:
                    continue

                neighbor_center = self._centers[neighbor_id]
                tentative_g = g_score[current] + _dist(current_center, neighbor_center)

                if tentative_g < g_score.get(neighbor_id, float("inf")):
                    came_from[neighbor_id] = current
                    g_score[neighbor_id] = tentative_g
                    f = tentative_g + _dist(neighbor_center, goal_center)
                    counter += 1
                    heapq.heappush(open_set, (f, counter, neighbor_id))

        return None  # no path found

    def crossing_point(
        self, from_id: int, to_id: int
    ) -> tuple[float, float, float]:
        """Midpoint of the shared edge between two connected areas.

        Falls back to the *to* area center if they aren't directly connected.
        """
        from_area = self.areas[from_id]
        to_area = self.areas[to_id]

        # Determine connection direction (0=N, 1=E, 2=S, 3=W)
        direction = -1
        for d, connected_ids in enumerate(from_area.connections):
            if to_id in connected_ids:
                direction = d
                break
        if direction == -1:
            return self.area_center(to_id)

        # Bounding boxes
        f_min_x = min(from_area.nw.x, from_area.se.x)
        f_max_x = max(from_area.nw.x, from_area.se.x)
        f_min_y = min(from_area.nw.y, from_area.se.y)
        f_max_y = max(from_area.nw.y, from_area.se.y)

        t_min_x = min(to_area.nw.x, to_area.se.x)
        t_max_x = max(to_area.nw.x, to_area.se.x)
        t_min_y = min(to_area.nw.y, to_area.se.y)
        t_max_y = max(to_area.nw.y, to_area.se.y)

        # Overlapping range on the shared axis
        if direction in (0, 2):  # north/south — shared Y edge, overlap on X
            ox = (max(f_min_x, t_min_x) + min(f_max_x, t_max_x)) / 2
            oy = f_max_y if direction == 0 else f_min_y
            x, y = ox, oy
        else:  # east/west — shared X edge, overlap on Y
            ox = f_max_x if direction == 1 else f_min_x
            oy = (max(f_min_y, t_min_y) + min(f_max_y, t_max_y)) / 2
            x, y = ox, oy

        # Average Z of both centers
        z = (self._centers[from_id].z + self._centers[to_id].z) / 2
        return (x, y, z)

    def path_to_waypoints(
        self, path: list[int], pull_fraction: float = 0.3
    ) -> list[tuple[float, float, float]]:
        """Convert an area-ID path to XYZ waypoints.

        Uses edge crossing points but pulls each one toward the destination
        area center by *pull_fraction* (0 = exact edge, 1 = area center).
        This keeps waypoints near the walkable edge while avoiding tight
        doorframes and wall-hugging positions.
        """
        if not path:
            return []
        if len(path) == 1:
            return [self.area_center(path[0])]

        waypoints: list[tuple[float, float, float]] = []
        for i in range(1, len(path)):
            if i < len(path) - 1:
                cx = self.crossing_point(path[i - 1], path[i])
                ac = self.area_center(path[i])
                # Blend crossing point toward the area center
                wp = (
                    cx[0] + (ac[0] - cx[0]) * pull_fraction,
                    cx[1] + (ac[1] - cx[1]) * pull_fraction,
                    cx[2] + (ac[2] - cx[2]) * pull_fraction,
                )
                waypoints.append(wp)
            else:
                waypoints.append(self.area_center(path[-1]))
        return waypoints

    def reachable_from(self, area_id: int) -> set[int]:
        """BFS to find all areas reachable from *area_id*."""
        visited: set[int] = set()
        q: deque[int] = deque([area_id])
        visited.add(area_id)
        while q:
            curr = q.popleft()
            for n in self.areas[curr].neighbor_ids():
                if n in self.areas and n not in visited:
                    visited.add(n)
                    q.append(n)
        return visited

    def find_gathering_point(self, near_area: int | None = None) -> int:
        """Pick a gathering area near the geographic center of the reachable component.

        If *near_area* is given, restrict to areas reachable from it.
        """
        if not self._centers:
            raise ValueError("Nav mesh has no areas")

        if near_area is not None and near_area in self.areas:
            candidates = self.reachable_from(near_area)
        else:
            candidates = set(self.areas.keys())

        # Compute component center
        sum_x = sum(self._centers[a].x for a in candidates)
        sum_y = sum(self._centers[a].y for a in candidates)
        n = len(candidates)
        cx, cy = sum_x / n, sum_y / n

        # Find closest area to center within the component
        best_id = -1
        best_dist = float("inf")
        for aid in candidates:
            center = self._centers[aid]
            d = _dist_sq_2d(cx, cy, center.x, center.y)
            if d < best_dist:
                best_dist = d
                best_id = aid

        c = self._centers[best_id]
        log.info(
            "Gathering point: area %d at (%.0f, %.0f, %.0f), component center (%.0f, %.0f), "
            "component size %d",
            best_id, c.x, c.y, c.z, cx, cy, n,
        )
        return best_id
