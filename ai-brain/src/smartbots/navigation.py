"""Navigation graph with A* pathfinding and center-line safe waypoints."""

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

# Portal width below which we insert an extra crossing-point waypoint
# so the bot threads the doorway precisely.
NARROW_PORTAL_THRESHOLD = 50.0

# How far past a narrow portal to place the perpendicular exit waypoint.
# Must exceed WAYPOINT_REACH_DIST (40u) so the bot can't "consume" the
# waypoint from the source side without actually passing through.
DOORWAY_EXIT_DIST = 50.0

# Portal width below which we insert a single crossing-point waypoint
# to prevent corner-cutting.  Above this, bots can freely cut across
# wide-open portals (trace data shows engine AI only crosses perpendicular
# on portals narrower than ~150u).
MEDIUM_PORTAL_THRESHOLD = 150.0

Pos3 = tuple[float, float, float]
Portal = tuple[Pos3, Pos3]  # (left, right)

# Margin from portal/area edges when applying lateral offset (Source units).
LATERAL_MARGIN = 16.0
# Maximum lateral offset from area center (Source units).
MAX_LATERAL_OFFSET = 200.0


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
        """Return (left, right) endpoints of the shared portal edge."""
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
        area = self.areas[area_id]
        return (
            min(area.nw.x, area.se.x),
            min(area.nw.y, area.se.y),
            max(area.nw.x, area.se.x),
            max(area.nw.y, area.se.y),
        )

    def _offset_crossing(self, from_id: int, to_id: int, lane: float) -> Pos3:
        """Crossing point offset laterally along the portal by *lane* ∈ [-1, 1]."""
        if lane == 0.0:
            return self.crossing_point(from_id, to_id)
        endpoints = self.portal_endpoints(from_id, to_id)
        if endpoints is None:
            return self.crossing_point(from_id, to_id)

        (ax, ay, az), (bx, by, bz) = endpoints
        width = math.sqrt((bx - ax) ** 2 + (by - ay) ** 2)
        usable = max(0.0, width - 2 * LATERAL_MARGIN)
        offset = lane * usable / 2

        mx, my, mz = (ax + bx) / 2, (ay + by) / 2, (az + bz) / 2
        if width > 0.001:
            dx, dy = (bx - ax) / width, (by - ay) / width
        else:
            dx, dy = 0.0, 0.0
        return (mx + dx * offset, my + dy * offset, mz)

    def _offset_area_center(
        self, area_id: int, lane: float,
        travel_dir: Pos3 | None = None,
    ) -> Pos3:
        """Area center offset perpendicular to *travel_dir* by *lane* ∈ [-1, 1]."""
        cx, cy, cz = self.area_center(area_id)
        if lane == 0.0 or travel_dir is None:
            return (cx, cy, cz)

        tx, ty = travel_dir[0], travel_dir[1]
        mag = math.sqrt(tx * tx + ty * ty)
        if mag < 0.001:
            return (cx, cy, cz)
        tx, ty = tx / mag, ty / mag

        # Perpendicular direction (90° clockwise)
        px, py = ty, -tx

        # Max offset before hitting area wall (with margin)
        min_x, min_y, max_x, max_y = self.area_bounds(area_id)
        if abs(px) > 0.001:
            limit_x = min(
                abs(cx - min_x - LATERAL_MARGIN),
                abs(max_x - cx - LATERAL_MARGIN),
            ) / abs(px)
        else:
            limit_x = float("inf")
        if abs(py) > 0.001:
            limit_y = min(
                abs(cy - min_y - LATERAL_MARGIN),
                abs(max_y - cy - LATERAL_MARGIN),
            ) / abs(py)
        else:
            limit_y = float("inf")
        max_off = max(0.0, min(limit_x, limit_y, MAX_LATERAL_OFFSET))

        offset = lane * max_off
        return (cx + px * offset, cy + py * offset, cz)

    def _area_depth_from_portal(self, area_id: int, portal_direction: int) -> float:
        """Extent of *area_id* perpendicular to a portal edge.

        portal_direction: 0/2 (N/S) → Y extent, 1/3 (E/W) → X extent.
        """
        area = self.areas[area_id]
        if portal_direction in (0, 2):
            return abs(area.nw.y - area.se.y)
        return abs(area.nw.x - area.se.x)

    # ── safe waypoint generation ─────────────────────────────────────

    def path_to_safe_waypoints(
        self, path: list[int], terrain: TerrainAnalyzer,
        lane: float = 0.0,
    ) -> list[AnnotatedWaypoint]:
        """Convert an area-ID path to safe waypoints with optional lateral offset.

        Every waypoint is an area center (guaranteed inside the area), so the bot
        cannot get stuck on boundary geometry.  For narrow portals (doorways), an
        extra crossing-point waypoint is inserted so the bot threads the gap.

        *lane* ∈ [-1, 1] offsets waypoints laterally: portal crossings shift
        along the shared edge, area centers shift perpendicular to travel direction.
        Narrow doorways naturally squeeze the offset (little usable width).
        """
        if not path:
            return []
        if len(path) == 1:
            return [AnnotatedWaypoint(
                pos=self.area_center(path[0]), area_id=path[0],
                needs_crouch=terrain.is_crouch_area(path[0]),
            )]

        waypoints: list[AnnotatedWaypoint] = []

        for i, area_id in enumerate(path):
            # Check if the portal INTO this area is narrow (doorway)
            if i > 0:
                prev_id = path[i - 1]
                width = self.portal_width(prev_id, area_id)
                trans = terrain.get_transition(prev_id, area_id)

                if width < NARROW_PORTAL_THRESHOLD:
                    # Two waypoints: approach (source side) + exit (dest side),
                    # both perpendicular to the portal edge so the bot passes
                    # through at 90° for maximum clearance.
                    cp = self._offset_crossing(prev_id, area_id, lane)
                    d = self._portal_direction(prev_id, area_id)

                    # Clamp offsets so waypoints stay inside their areas.
                    approach_depth = self._area_depth_from_portal(prev_id, d)
                    exit_depth = self._area_depth_from_portal(area_id, d)
                    approach_off = max(8.0, min(DOORWAY_EXIT_DIST, approach_depth - 8.0))
                    exit_off = max(8.0, min(DOORWAY_EXIT_DIST, exit_depth - 8.0))

                    if d == 0:    # N: portal at max_y
                        approach_wp: Pos3 = (cp[0], cp[1] - approach_off, cp[2])
                        exit_wp: Pos3 = (cp[0], cp[1] + exit_off, cp[2])
                    elif d == 1:  # E: portal at max_x
                        approach_wp = (cp[0] - approach_off, cp[1], cp[2])
                        exit_wp = (cp[0] + exit_off, cp[1], cp[2])
                    elif d == 2:  # S: portal at min_y
                        approach_wp = (cp[0], cp[1] + approach_off, cp[2])
                        exit_wp = (cp[0], cp[1] - exit_off, cp[2])
                    else:         # W: portal at min_x
                        approach_wp = (cp[0] + approach_off, cp[1], cp[2])
                        exit_wp = (cp[0] - exit_off, cp[1], cp[2])
                    jump = bool(trans and trans.needs_jump)
                    crouch = (bool(trans and trans.needs_crouch)
                              or terrain.is_crouch_area(area_id))
                    waypoints.append(AnnotatedWaypoint(
                        pos=approach_wp, area_id=prev_id,
                        needs_jump=False, needs_crouch=crouch,
                    ))
                    waypoints.append(AnnotatedWaypoint(
                        pos=exit_wp, area_id=area_id,
                        needs_jump=jump, needs_crouch=crouch,
                    ))
                elif width < MEDIUM_PORTAL_THRESHOLD or (trans and trans.needs_jump):
                    # Medium portal or jump transition — single crossing-point
                    # waypoint prevents corner-cutting without approach/exit.
                    cp = self._offset_crossing(prev_id, area_id, lane)
                    jump = bool(trans and trans.needs_jump)
                    crouch = (bool(trans and trans.needs_crouch)
                              or terrain.is_crouch_area(area_id))
                    waypoints.append(AnnotatedWaypoint(
                        pos=cp, area_id=area_id,
                        needs_jump=jump, needs_crouch=crouch,
                    ))

            # Area center waypoint (skip first area — bot is already there)
            if i > 0:
                # Compute travel direction for lateral offset
                prev_center = self.area_center(path[i - 1])
                curr_center = self.area_center(area_id)
                travel_dir: Pos3 = (
                    curr_center[0] - prev_center[0],
                    curr_center[1] - prev_center[1],
                    0.0,
                )
                waypoints.append(AnnotatedWaypoint(
                    pos=self._offset_area_center(area_id, lane, travel_dir),
                    area_id=area_id,
                    needs_crouch=terrain.is_crouch_area(area_id),
                ))

        log.info(
            "Safe waypoints: %d areas -> %d waypoints (lane=%.2f)",
            len(path), len(waypoints), lane,
        )
        return waypoints

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
