"""Navigation graph with A* pathfinding and portal helpers."""

from __future__ import annotations

import heapq
import logging
import math
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING

from smartbots.nav_parser import NavArea, NavMesh, Vector3, parse_nav

if TYPE_CHECKING:
    from smartbots.clearance import ClearanceMap

log = logging.getLogger(__name__)

Pos3 = tuple[float, float, float]
Portal = tuple[Pos3, Pos3]  # (endpoint_a, endpoint_b)


# ── geometry helpers ────────────────────────────────────────────────────


def _dist(a: Vector3, b: Vector3) -> float:
    return math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2)


def _dist_sq_2d(ax: float, ay: float, bx: float, by: float) -> float:
    return (ax - bx) ** 2 + (ay - by) ** 2


# ── NavGraph ───────────────────────────────────────────────────────────


class NavGraph:
    """Wraps a parsed NavMesh and provides pathfinding."""

    _GRID_CELL_SIZE = 256.0

    def __init__(self, nav_path: str | Path) -> None:
        log.info("Loading nav mesh from %s", nav_path)
        self.mesh: NavMesh = parse_nav(nav_path)
        self.areas: dict[int, NavArea] = self.mesh.areas

        self._centers: dict[int, Vector3] = {
            aid: area.center() for aid, area in self.areas.items()
        }

        # Precompute area bounds (min_x, min_y, max_x, max_y)
        self._bounds: dict[int, tuple[float, float, float, float]] = {}
        for aid, area in self.areas.items():
            self._bounds[aid] = (
                min(area.nw.x, area.se.x),
                min(area.nw.y, area.se.y),
                max(area.nw.x, area.se.x),
                max(area.nw.y, area.se.y),
            )

        # Spatial grid for O(1) point-in-area queries
        self._build_spatial_grid()

        log.info(
            "Nav mesh loaded: %d areas, %d ladders, %d grid cells",
            len(self.areas), len(self.mesh.ladders), len(self._grid),
        )

    def _build_spatial_grid(self) -> None:
        """Build a hash-grid mapping (cell_x, cell_y) → [area_id, ...]."""
        cs = self._GRID_CELL_SIZE
        grid: dict[tuple[int, int], list[int]] = {}

        if not self._bounds:
            self._grid = grid
            self._grid_origin = (0.0, 0.0)
            return

        ox = min(b[0] for b in self._bounds.values())
        oy = min(b[1] for b in self._bounds.values())
        self._grid_origin = (ox, oy)

        for aid, (min_x, min_y, max_x, max_y) in self._bounds.items():
            cx0 = int((min_x - ox) / cs)
            cx1 = int((max_x - ox) / cs)
            cy0 = int((min_y - oy) / cs)
            cy1 = int((max_y - oy) / cs)
            for cx in range(cx0, cx1 + 1):
                for cy in range(cy0, cy1 + 1):
                    grid.setdefault((cx, cy), []).append(aid)

        self._grid = grid

    def _grid_lookup(self, x: float, y: float) -> list[int]:
        """Return area IDs in the grid cell containing (x, y)."""
        ox, oy = self._grid_origin
        cs = self._GRID_CELL_SIZE
        return self._grid.get((int((x - ox) / cs), int((y - oy) / cs)), [])

    def area_center(self, area_id: int) -> Pos3:
        c = self._centers[area_id]
        return (c.x, c.y, c.z)

    def find_area(self, pos: Pos3) -> int:
        """Find the nav area containing *pos*, or the nearest one by center distance."""
        x, y = pos[0], pos[1]

        # Fast grid lookup
        for aid in self._grid_lookup(x, y):
            min_x, min_y, max_x, max_y = self._bounds[aid]
            if min_x <= x <= max_x and min_y <= y <= max_y:
                return aid

        # Fallback: nearest center
        best_id = -1
        best_dist = float("inf")
        for aid, center in self._centers.items():
            d = _dist_sq_2d(x, y, center.x, center.y)
            if d < best_dist:
                best_dist = d
                best_id = aid
        return best_id

    # ── Nav-mesh trace (replaces engine hull traces) ──────────────

    def is_on_nav(self, x: float, y: float) -> bool:
        """Return True if (x, y) is inside any nav area (with 2u tolerance)."""
        tol = 2.0
        for aid in self._grid_lookup(x, y):
            min_x, min_y, max_x, max_y = self._bounds[aid]
            if (min_x - tol) <= x <= (max_x + tol) and (min_y - tol) <= y <= (max_y + tol):
                return True
        return False

    def trace_nav(
        self,
        start: tuple[float, float],
        end: tuple[float, float],
        steps: int = 8,
    ) -> float:
        """Trace a 2D line; return fraction [0..1] where it first leaves nav.

        1.0 = entire line on nav (clear).
        0.0 = start point is already off-nav.
        Mirrors the ``fraction`` field of engine ``trace_t`` results.
        """
        for i in range(steps + 1):
            t = i / steps
            x = start[0] + t * (end[0] - start[0])
            y = start[1] + t * (end[1] - start[1])
            if not self.is_on_nav(x, y):
                if i == 0:
                    return 0.0
                return (i - 1) / steps
        return 1.0

    # ── A* pathfinding ──────────────────────────────────────────────

    def find_path(
        self,
        start_id: int,
        goal_id: int,
        clearance: ClearanceMap | None = None,
    ) -> list[int] | None:
        if start_id not in self.areas or goal_id not in self.areas:
            return None
        if start_id == goal_id:
            return [start_id]

        goal_center = self._centers[goal_id]
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
                edge_cost = _dist(current_center, neighbor_center)

                # Penalize edges into tight areas so A* prefers wider corridors.
                # Penalty: 1.0 (none) when min_clr >= 80u, up to 1.25x when 0u.
                if clearance is not None:
                    min_clr = clearance.get_min_clearance(neighbor_id)
                    penalty = 1.0 + max(0.0, 1.0 - min_clr / _CLEARANCE_PENALTY_RADIUS) * 0.25
                    edge_cost *= penalty

                tentative_g = g_score[current] + edge_cost

                if tentative_g < g_score.get(neighbor_id, float("inf")):
                    came_from[neighbor_id] = current
                    g_score[neighbor_id] = tentative_g
                    f = tentative_g + _dist(neighbor_center, goal_center)
                    counter += 1
                    heapq.heappush(open_set, (f, counter, neighbor_id))

        return None

    # ── portal / crossing helpers ───────────────────────────────────

    def crossing_point(self, from_id: int, to_id: int) -> Pos3:
        """Midpoint of the shared edge between two connected areas."""
        from_area = self.areas[from_id]
        to_area = self.areas[to_id]

        direction = -1
        for d, connected_ids in enumerate(from_area.connections):
            if to_id in connected_ids:
                direction = d
                break
        if direction == -1:
            return self.area_center(to_id)

        f_min_x = min(from_area.nw.x, from_area.se.x)
        f_max_x = max(from_area.nw.x, from_area.se.x)
        f_min_y = min(from_area.nw.y, from_area.se.y)
        f_max_y = max(from_area.nw.y, from_area.se.y)
        t_min_x = min(to_area.nw.x, to_area.se.x)
        t_max_x = max(to_area.nw.x, to_area.se.x)
        t_min_y = min(to_area.nw.y, to_area.se.y)
        t_max_y = max(to_area.nw.y, to_area.se.y)

        if direction in (0, 2):
            ox = (max(f_min_x, t_min_x) + min(f_max_x, t_max_x)) / 2
            oy = f_max_y if direction == 0 else f_min_y
            x, y = ox, oy
        else:
            ox = f_max_x if direction == 1 else f_min_x
            oy = (max(f_min_y, t_min_y) + min(f_max_y, t_max_y)) / 2
            x, y = ox, oy

        z = (self._centers[from_id].z + self._centers[to_id].z) / 2
        return (x, y, z)

    def _portal_direction(self, from_id: int, to_id: int) -> int:
        """Direction (0=N,1=E,2=S,3=W) of the portal from *from_id* to *to_id*."""
        from_area = self.areas[from_id]
        for d, connected_ids in enumerate(from_area.connections):
            if to_id in connected_ids:
                return d
        return -1

    def portal_width(self, from_id: int, to_id: int) -> float:
        """Width of the shared edge (portal) between two connected areas."""
        from_area = self.areas[from_id]
        to_area = self.areas[to_id]

        direction = -1
        for d, connected_ids in enumerate(from_area.connections):
            if to_id in connected_ids:
                direction = d
                break
        if direction == -1:
            return 0.0

        f_min_x = min(from_area.nw.x, from_area.se.x)
        f_max_x = max(from_area.nw.x, from_area.se.x)
        f_min_y = min(from_area.nw.y, from_area.se.y)
        f_max_y = max(from_area.nw.y, from_area.se.y)
        t_min_x = min(to_area.nw.x, to_area.se.x)
        t_max_x = max(to_area.nw.x, to_area.se.x)
        t_min_y = min(to_area.nw.y, to_area.se.y)
        t_max_y = max(to_area.nw.y, to_area.se.y)

        if direction in (0, 2):  # N/S — overlap on X
            return max(0.0, min(f_max_x, t_max_x) - max(f_min_x, t_min_x))
        else:  # E/W — overlap on Y
            return max(0.0, min(f_max_y, t_max_y) - max(f_min_y, t_min_y))

    def portal_endpoints(self, from_id: int, to_id: int) -> Portal | None:
        """Return (endpoint_a, endpoint_b) of the shared portal edge."""
        from_area = self.areas[from_id]
        to_area = self.areas[to_id]
        direction = self._portal_direction(from_id, to_id)
        if direction == -1:
            return None

        f_min_x = min(from_area.nw.x, from_area.se.x)
        f_max_x = max(from_area.nw.x, from_area.se.x)
        f_min_y = min(from_area.nw.y, from_area.se.y)
        f_max_y = max(from_area.nw.y, from_area.se.y)
        t_min_x = min(to_area.nw.x, to_area.se.x)
        t_max_x = max(to_area.nw.x, to_area.se.x)
        t_min_y = min(to_area.nw.y, to_area.se.y)
        t_max_y = max(to_area.nw.y, to_area.se.y)

        z = (self._centers[from_id].z + self._centers[to_id].z) / 2
        if direction in (0, 2):  # N/S portal runs along X
            o_min = max(f_min_x, t_min_x)
            o_max = min(f_max_x, t_max_x)
            y = f_max_y if direction == 0 else f_min_y
            return ((o_min, y, z), (o_max, y, z))
        else:  # E/W portal runs along Y
            o_min = max(f_min_y, t_min_y)
            o_max = min(f_max_y, t_max_y)
            x = f_max_x if direction == 1 else f_min_x
            return ((x, o_min, z), (x, o_max, z))

    def area_bounds(self, area_id: int) -> tuple[float, float, float, float]:
        """Return (min_x, min_y, max_x, max_y) for an area."""
        return self._bounds[area_id]

    # ── graph queries ───────────────────────────────────────────────

    def reachable_from(self, area_id: int) -> set[int]:
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

    def _area_size(self, area_id: int) -> float:
        """2D area of a nav area in square units."""
        a = self.areas[area_id]
        return abs(a.nw.x - a.se.x) * abs(a.nw.y - a.se.y)

    def find_gathering_point(
        self, near_area: int | None = None, min_size: float = 10000.0,
    ) -> int:
        """Find a large area near the map center suitable for gathering.

        Prefers areas larger than *min_size* sq.u (default 100x100).
        Among those, picks the one closest to the component centroid.
        """
        if not self._centers:
            raise ValueError("Nav mesh has no areas")

        if near_area is not None and near_area in self.areas:
            candidates = self.reachable_from(near_area)
        else:
            candidates = set(self.areas.keys())

        sum_x = sum(self._centers[a].x for a in candidates)
        sum_y = sum(self._centers[a].y for a in candidates)
        n = len(candidates)
        cx, cy = sum_x / n, sum_y / n

        # Filter to large areas; fall back to all if none qualify.
        large = {a for a in candidates if self._area_size(a) >= min_size}
        pool = large or candidates

        best_id = -1
        best_dist = float("inf")
        for aid in pool:
            center = self._centers[aid]
            d = _dist_sq_2d(cx, cy, center.x, center.y)
            if d < best_dist:
                best_dist = d
                best_id = aid

        c = self._centers[best_id]
        sz = self._area_size(best_id)
        log.info(
            "Gathering point: area %d (%.0f sq.u) at (%.0f, %.0f, %.0f), "
            "component center (%.0f, %.0f), component size %d",
            best_id, sz, c.x, c.y, c.z, cx, cy, n,
        )
        return best_id


# Areas with minimum clearance below this get an A* cost penalty (up to 3x)
_CLEARANCE_PENALTY_RADIUS = 80.0
