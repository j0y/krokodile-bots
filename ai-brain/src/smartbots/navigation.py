"""Navigation graph with A* pathfinding and funnel-smoothed paths."""

from __future__ import annotations

import heapq
import logging
import math
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from smartbots.nav_parser import NavArea, NavMesh, Vector3, parse_nav

if TYPE_CHECKING:
    from smartbots.terrain import TerrainAnalyzer

log = logging.getLogger(__name__)

# Portal shrink on each side — keeps the smoothed path slightly off walls.
# Nav mesh portals on ministry are often only 25u wide, so 16u (hull half-width)
# would collapse most of them. 4u is enough to avoid wall-hugging.
AGENT_RADIUS = 4.0

Pos3 = tuple[float, float, float]
Portal = tuple[Pos3, Pos3]  # (left, right)


@dataclass
class AnnotatedWaypoint:
    """A waypoint with terrain annotations for jump/crouch."""

    pos: Pos3
    area_id: int
    needs_jump: bool = False
    needs_crouch: bool = False


# ── geometry helpers ────────────────────────────────────────────────────


def _dist(a: Vector3, b: Vector3) -> float:
    return math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2 + (a.z - b.z) ** 2)


def _dist_sq_2d(ax: float, ay: float, bx: float, by: float) -> float:
    return (ax - bx) ** 2 + (ay - by) ** 2


def _cross2d(o: Pos3, a: Pos3, b: Pos3) -> float:
    """2D cross product of vectors OA and OB. Positive = B is left of O→A."""
    return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])


def _vequal2d(a: Pos3, b: Pos3, eps: float = 0.001) -> bool:
    return abs(a[0] - b[0]) < eps and abs(a[1] - b[1]) < eps


# ── funnel algorithm ───────────────────────────────────────────────────


def _funnel_smooth(
    start: Pos3, goal: Pos3, portals: list[Portal],
) -> list[tuple[Pos3, int]]:
    """Simple Stupid Funnel Algorithm (Mononen).

    Returns list of (waypoint, portal_index) tuples.
    portal_index is -1 for start, len(portals) for goal.
    Intermediate waypoints have the index of the portal they lie on.
    """
    if not portals:
        return [(start, -1), (goal, 0)]

    # Build full portal list: degenerate start, actual portals, degenerate goal
    pts: list[Portal] = [(start, start)]
    pts.extend(portals)
    pts.append((goal, goal))

    result: list[tuple[Pos3, int]] = [(start, -1)]

    apex = start
    apex_idx = 0
    left = start
    left_idx = 0
    right = start
    right_idx = 0

    i = 1
    while i < len(pts):
        pl, pr = pts[i]

        # Try to narrow the right side
        if _cross2d(apex, right, pr) <= 0.0:
            if _vequal2d(apex, right) or _cross2d(apex, left, pr) > 0.0:
                right = pr
                right_idx = i
            else:
                # Right crossed over left — insert left as new apex
                result.append((left, left_idx - 1))
                apex = left
                apex_idx = left_idx
                left = apex
                right = apex
                left_idx = apex_idx
                right_idx = apex_idx
                i = apex_idx + 1
                continue

        # Try to narrow the left side
        if _cross2d(apex, left, pl) >= 0.0:
            if _vequal2d(apex, left) or _cross2d(apex, right, pl) < 0.0:
                left = pl
                left_idx = i
            else:
                # Left crossed over right — insert right as new apex
                result.append((right, right_idx - 1))
                apex = right
                apex_idx = right_idx
                left = apex
                right = apex
                left_idx = apex_idx
                right_idx = apex_idx
                i = apex_idx + 1
                continue

        i += 1

    result.append((goal, len(portals)))
    return result


# ── NavGraph ───────────────────────────────────────────────────────────


class NavGraph:
    """Wraps a parsed NavMesh and provides pathfinding."""

    def __init__(self, nav_path: str | Path) -> None:
        log.info("Loading nav mesh from %s", nav_path)
        self.mesh: NavMesh = parse_nav(nav_path)
        self.areas: dict[int, NavArea] = self.mesh.areas

        self._centers: dict[int, Vector3] = {
            aid: area.center() for aid, area in self.areas.items()
        }

        log.info(
            "Nav mesh loaded: %d areas, %d ladders",
            len(self.areas), len(self.mesh.ladders),
        )

    def area_center(self, area_id: int) -> Pos3:
        c = self._centers[area_id]
        return (c.x, c.y, c.z)

    def find_area(self, pos: Pos3) -> int:
        """Find the nav area containing *pos*, or the nearest one by center distance."""
        x, y = pos[0], pos[1]

        for aid, area in self.areas.items():
            min_x = min(area.nw.x, area.se.x)
            max_x = max(area.nw.x, area.se.x)
            min_y = min(area.nw.y, area.se.y)
            max_y = max(area.nw.y, area.se.y)
            if min_x <= x <= max_x and min_y <= y <= max_y:
                return aid

        best_id = -1
        best_dist = float("inf")
        for aid, center in self._centers.items():
            d = _dist_sq_2d(x, y, center.x, center.y)
            if d < best_dist:
                best_dist = d
                best_id = aid
        return best_id

    # ── A* pathfinding ──────────────────────────────────────────────

    def find_path(self, start_id: int, goal_id: int) -> list[int] | None:
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
                tentative_g = g_score[current] + _dist(current_center, neighbor_center)

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

    def portal_edge(self, from_id: int, to_id: int) -> Portal | None:
        """Shared edge as (left, right) relative to travel direction.

        Portal is shrunk by AGENT_RADIUS on each side to prevent wall-hugging.
        Returns None if areas aren't directly connected.
        """
        from_area = self.areas[from_id]
        to_area = self.areas[to_id]

        direction = -1
        for d, connected_ids in enumerate(from_area.connections):
            if to_id in connected_ids:
                direction = d
                break
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

        if direction in (0, 2):  # north/south — shared Y edge, overlap on X
            shared_y = f_max_y if direction == 0 else f_min_y
            lo = max(f_min_x, t_min_x)
            hi = min(f_max_x, t_max_x)
            width = hi - lo
            if width > AGENT_RADIUS * 2:
                lo += AGENT_RADIUS
                hi -= AGENT_RADIUS
            else:
                mid = (lo + hi) / 2
                lo = hi = mid
            p1: Pos3 = (lo, shared_y, z)
            p2: Pos3 = (hi, shared_y, z)
        else:  # east/west — shared X edge, overlap on Y
            shared_x = f_max_x if direction == 1 else f_min_x
            lo = max(f_min_y, t_min_y)
            hi = min(f_max_y, t_max_y)
            width = hi - lo
            if width > AGENT_RADIUS * 2:
                lo += AGENT_RADIUS
                hi -= AGENT_RADIUS
            else:
                mid = (lo + hi) / 2
                lo = hi = mid
            p1 = (shared_x, lo, z)
            p2 = (shared_x, hi, z)

        # Determine left/right using cross product with travel direction
        from_c = self._centers[from_id]
        to_c = self._centers[to_id]
        travel_x = to_c.x - from_c.x
        travel_y = to_c.y - from_c.y

        cross = travel_x * (p1[1] - from_c.y) - travel_y * (p1[0] - from_c.x)
        if cross >= 0:
            return (p1, p2)  # p1 is left
        return (p2, p1)  # p2 is left

    # ── waypoint generation ─────────────────────────────────────────

    def path_to_waypoints(
        self, path: list[int], pull_fraction: float = 0.3
    ) -> list[Pos3]:
        """Convert an area-ID path to XYZ waypoints (legacy, no funnel)."""
        if not path:
            return []
        if len(path) == 1:
            return [self.area_center(path[0])]

        waypoints: list[Pos3] = []
        for i in range(1, len(path)):
            if i < len(path) - 1:
                cx = self.crossing_point(path[i - 1], path[i])
                ac = self.area_center(path[i])
                wp = (
                    cx[0] + (ac[0] - cx[0]) * pull_fraction,
                    cx[1] + (ac[1] - cx[1]) * pull_fraction,
                    cx[2] + (ac[2] - cx[2]) * pull_fraction,
                )
                waypoints.append(wp)
            else:
                waypoints.append(self.area_center(path[-1]))
        return waypoints

    def path_to_annotated_waypoints(
        self, path: list[int], terrain: TerrainAnalyzer,
    ) -> list[AnnotatedWaypoint]:
        """Convert an area-ID path to funnel-smoothed annotated waypoints.

        Uses the Simple Stupid Funnel Algorithm for path smoothing, then
        inserts extra waypoints at jump transitions that the funnel skipped.
        """
        if not path:
            return []
        if len(path) == 1:
            return [AnnotatedWaypoint(
                pos=self.area_center(path[0]), area_id=path[0],
                needs_crouch=terrain.is_crouch_area(path[0]),
            )]

        start = self.area_center(path[0])
        goal = self.area_center(path[-1])

        # Build portal list
        portals: list[Portal] = []
        for i in range(len(path) - 1):
            edge = self.portal_edge(path[i], path[i + 1])
            if edge is None:
                # Fallback: degenerate portal at crossing point
                cp = self.crossing_point(path[i], path[i + 1])
                portals.append((cp, cp))
            else:
                portals.append(edge)

        # Run funnel algorithm
        funnel_result = _funnel_smooth(start, goal, portals)

        raw_area_count = len(path) - 1  # old method would produce this many waypoints

        # Build annotated waypoints from funnel output
        waypoints: list[AnnotatedWaypoint] = []
        prev_portal_idx = -1  # start

        for pos, portal_idx in funnel_result[1:]:  # skip start point
            # Determine area_id for this waypoint
            if portal_idx >= len(portals):
                area_id = path[-1]
            elif portal_idx >= 0:
                area_id = path[portal_idx + 1]
            else:
                area_id = path[0]

            # Check all transitions between previous and current funnel waypoints
            # to find jump/crouch transitions the funnel may have smoothed away
            check_start = max(0, prev_portal_idx + 1)
            check_end = min(len(portals), portal_idx + 1) if portal_idx >= 0 else 0

            jump_portals: list[int] = []
            for j in range(check_start, check_end):
                trans = terrain.get_transition(path[j], path[j + 1])
                if trans and trans.needs_jump:
                    jump_portals.append(j)

            # Insert extra waypoints at jump transitions that the funnel skipped
            for jp in jump_portals:
                jump_pos = self.crossing_point(path[jp], path[jp + 1])
                jump_area = path[jp + 1]
                waypoints.append(AnnotatedWaypoint(
                    pos=jump_pos, area_id=jump_area,
                    needs_jump=True,
                    needs_crouch=terrain.is_crouch_area(jump_area),
                ))

            # Check crouch for this waypoint's area
            needs_crouch = terrain.is_crouch_area(area_id)
            # Also check if any skipped transition leads to a crouch area
            for j in range(check_start, check_end):
                trans = terrain.get_transition(path[j], path[j + 1])
                if trans and trans.needs_crouch:
                    needs_crouch = True

            waypoints.append(AnnotatedWaypoint(
                pos=pos, area_id=area_id,
                needs_crouch=needs_crouch,
            ))

            prev_portal_idx = portal_idx

        log.info(
            "Funnel: %d areas -> %d raw -> %d smoothed waypoints",
            len(path), raw_area_count, len(waypoints),
        )

        return waypoints

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

    def find_gathering_point(self, near_area: int | None = None) -> int:
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
