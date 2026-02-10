"""NextBot-style path computation and following.

Mirrors Valve's Path + PathFollower from the Source engine NextBot framework.
Key differences from the old flow-field + waypoint system:

- Per-bot A* instead of shared flow field
- Portal crossing uses closest-point-to-previous (string-pulling) instead of midpoint
- Segment types (CLIMB_UP, DROP_DOWN) drive movement flags
- Dividing-plane goal advancement instead of distance-only check
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartbots.clearance import ClearanceMap
    from smartbots.navigation import NavGraph
    from smartbots.terrain import TerrainAnalyzer

log = logging.getLogger(__name__)

Pos3 = tuple[float, float, float]

# Source engine step height — same as terrain.py JUMP_THRESHOLD
STEP_HEIGHT = 18.0

# NextBot default goal tolerance (distance in 2D to consider goal reached)
GOAL_TOLERANCE = 25.0

# How far ahead on the path polyline to place the look target
LOOK_AHEAD_DIST = 200.0

# Jump trigger distance and cooldown (ticks)
JUMP_TRIGGER_DIST = 60.0
JUMP_COOLDOWN = 4

# Crouch approach distance
CROUCH_APPROACH_DIST = 100.0

# NAV flags (duplicated from terrain.py to avoid circular import)
_NAV_STAIRS_FLAG = 0x1000

# ── Corner / portal handling ──
# Half hull width — keeps crossing points away from portal endpoints (walls)
HULL_HALF_WIDTH = 16.0

# Push crossing points this far past the portal into the destination area
AREA_ENTRY_PUSH = 20.0

# Skip ground-level goals closer than this (mirrors nb_goal_look_ahead_range)
MIN_LOOK_AHEAD_RANGE = 30.0

# Blend move target toward next segment when within this range of a curved goal
CORNER_BLEND_RANGE = 80.0

# ── Clearance-steered movement ──
# How far ahead to place the steered move target (caps at dist-to-goal)
STEER_AHEAD_DIST = 120.0
# Forward probe distances: check for walls along the chosen steer direction
_FORWARD_PROBES = (32.0, 64.0, 96.0)
# Clearance below this at a probe point triggers re-steering
_FORWARD_PROBE_MIN = 28.0

# ── Path clearance validation ──
# Hard wall: clearance below this triggers segment skip
_PATH_CLEARANCE_BLOCKED = 24.0
# Caution zone: tight enough to aim past even if not fully blocked
_PATH_CLEARANCE_CAUTION = 48.0
# How many segments ahead to scan
_PATH_LOOKAHEAD = 5
# Sample clearance every this many units along each segment
_PATH_SAMPLE_STEP = 32.0

# ── Portal clearance optimization ──
# Number of evenly-spaced samples along the portal to test clearance
_PORTAL_CLEARANCE_SAMPLES = 8
# Only shift the portal position if improvement exceeds this (units)
_PORTAL_CLEARANCE_THRESHOLD = 50.0


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class SegmentType(Enum):
    ON_GROUND = auto()
    DROP_DOWN = auto()
    CLIMB_UP = auto()
    JUMP_OVER_GAP = auto()


@dataclass
class Segment:
    """One node of the path polyline, mirroring NextBot's Path::Segment."""

    area_id: int
    pos: Pos3
    type: SegmentType = SegmentType.ON_GROUND
    forward: Pos3 = (0.0, 0.0, 0.0)
    length: float = 0.0
    distance_from_start: float = 0.0
    curvature: float = 0.0
    portal_center: Pos3 | None = None
    portal_half_width: float = 0.0


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------

def _dist_2d(a: Pos3, b: Pos3) -> float:
    dx = a[0] - b[0]
    dy = a[1] - b[1]
    return math.sqrt(dx * dx + dy * dy)



# ---------------------------------------------------------------------------
# Path building — mirrors Path::Compute + ComputePathDetails + PostProcess
# ---------------------------------------------------------------------------

def _closest_point_on_segment(
    p: Pos3, a: Pos3, b: Pos3,
) -> tuple[Pos3, float]:
    """Project *p* onto line segment *a*→*b*. Return (closest_point, t)."""
    dx = b[0] - a[0]
    dy = b[1] - a[1]
    seg_len_sq = dx * dx + dy * dy
    if seg_len_sq < 0.001:
        return (a, 0.0)
    t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / seg_len_sq
    t = max(0.0, min(1.0, t))
    return (
        (a[0] + t * dx, a[1] + t * dy, a[2] + t * (b[2] - a[2])),
        t,
    )


def compute_path_details(
    segments: list[Segment],
    nav: NavGraph,
    terrain: TerrainAnalyzer,
    clearance: ClearanceMap | None = None,
) -> list[Segment]:
    """Set segment positions via closest-portal and detect climb/drop.

    Mirrors ``Path::ComputePathDetails``.  Modifies *segments* in-place and
    may insert additional segments for drop-downs and climb-ups.

    When *clearance* is provided, portal crossing points are shifted along
    the portal to the position with the best clearance in the travel direction.
    """
    if len(segments) < 2:
        return segments

    i = 1
    while i < len(segments):
        from_seg = segments[i - 1]
        to_seg = segments[i]

        # Compute portal crossing position — closest point on portal to from_seg.pos
        endpoints = nav.portal_endpoints(from_seg.area_id, to_seg.area_id)
        if endpoints is not None:
            (ax, ay, az), (bx, by, bz) = endpoints
            portal_a = (ax, ay, az)
            portal_b = (bx, by, bz)
            closest, _t = _closest_point_on_segment(from_seg.pos, portal_a, portal_b)

            # Store portal info
            mid_x = (ax + bx) / 2
            mid_y = (ay + by) / 2
            mid_z = (az + bz) / 2
            half_w = math.sqrt((bx - ax) ** 2 + (by - ay) ** 2) / 2
            to_seg.portal_center = (mid_x, mid_y, mid_z)
            to_seg.portal_half_width = half_w

            # ── Portal margin clamping ──
            # Keep crossing point HULL_HALF_WIDTH from portal endpoints to
            # prevent corner-hugging (Avoid()-equivalent for server-side paths).
            portal_len = _dist_2d(portal_a, portal_b)
            if portal_len > 2 * HULL_HALF_WIDTH:
                t_min = HULL_HALF_WIDTH / portal_len
                t_max = 1.0 - t_min
                t_clamped = max(t_min, min(t_max, _t))
                if t_clamped != _t:
                    closest = (
                        portal_a[0] + t_clamped * (portal_b[0] - portal_a[0]),
                        portal_a[1] + t_clamped * (portal_b[1] - portal_a[1]),
                        portal_a[2] + t_clamped * (portal_b[2] - portal_a[2]),
                    )
            else:
                # Portal narrower than hull — use center
                closest = (mid_x, mid_y, mid_z)

            # ── Clearance-aware portal optimization ──
            # Slide the crossing point along the portal to find the position
            # with the best clearance in the travel direction.
            if clearance is not None and portal_len > 2 * HULL_HALF_WIDTH:
                travel_dx = mid_x - from_seg.pos[0]
                travel_dy = mid_y - from_seg.pos[1]
                travel_angle = math.atan2(travel_dy, travel_dx)

                t_min_cl = HULL_HALF_WIDTH / portal_len
                t_max_cl = 1.0 - t_min_cl
                n_samples = _PORTAL_CLEARANCE_SAMPLES
                best_clr = -1.0
                best_t = (closest[0] - portal_a[0]) * (portal_b[0] - portal_a[0]) + \
                         (closest[1] - portal_a[1]) * (portal_b[1] - portal_a[1])
                if portal_len > 0.001:
                    best_t = best_t / (portal_len * portal_len)
                else:
                    best_t = 0.5
                # Query clearance at the current closest-point position
                current_clr = clearance.get_clearance_at(
                    from_seg.area_id, closest[0], closest[1], travel_angle, height=1,
                )
                best_clr = current_clr

                for si in range(n_samples):
                    st = t_min_cl + (t_max_cl - t_min_cl) * si / max(n_samples - 1, 1)
                    sx = portal_a[0] + st * (portal_b[0] - portal_a[0])
                    sy = portal_a[1] + st * (portal_b[1] - portal_a[1])
                    clr = clearance.get_clearance_at(
                        from_seg.area_id, sx, sy, travel_angle, height=1,
                    )
                    if clr > best_clr + _PORTAL_CLEARANCE_THRESHOLD:
                        best_clr = clr
                        best_t = st

                sz = portal_a[2] + best_t * (portal_b[2] - portal_a[2])
                closest = (
                    portal_a[0] + best_t * (portal_b[0] - portal_a[0]),
                    portal_a[1] + best_t * (portal_b[1] - portal_a[1]),
                    sz,
                )

            # ── Push into destination area ──
            # Offset crossing point past the portal edge so the bot aims
            # through the portal, not at it.  Direction: toward to_area center.
            to_center = nav.area_center(to_seg.area_id)
            push_dx = to_center[0] - closest[0]
            push_dy = to_center[1] - closest[1]
            push_mag = math.sqrt(push_dx * push_dx + push_dy * push_dy)
            if push_mag > 0.001:
                push_dist = min(AREA_ENTRY_PUSH, push_mag * 0.5)
                closest = (
                    closest[0] + push_dx / push_mag * push_dist,
                    closest[1] + push_dy / push_mag * push_dist,
                    closest[2],
                )

            # Use Z from destination area (crossing has been pushed into it)
            z = terrain._z_at(nav.areas[to_seg.area_id], closest[0], closest[1])
            to_seg.pos = (closest[0], closest[1], z)
        else:
            # No shared edge — use area center as fallback
            to_seg.pos = nav.area_center(to_seg.area_id)

        # ── Height analysis for drop-down / climb-up ──
        from_area = nav.areas[from_seg.area_id]
        to_area = nav.areas[to_seg.area_id]
        is_stairs = bool(from_area.flags & _NAV_STAIRS_FLAG) or bool(
            to_area.flags & _NAV_STAIRS_FLAG
        )

        from_z = terrain._z_at(from_area, from_seg.pos[0], from_seg.pos[1])
        to_z = terrain._z_at(to_area, to_seg.pos[0], to_seg.pos[1])
        height_delta = to_z - from_z

        if not is_stairs and height_delta < -STEP_HEIGHT:
            # ── DROP_DOWN: insert landing segment below ──
            to_seg.type = SegmentType.DROP_DOWN
            landing_pos = (to_seg.pos[0], to_seg.pos[1], to_z)
            landing = Segment(
                area_id=to_seg.area_id,
                pos=landing_pos,
                type=SegmentType.ON_GROUND,
            )
            segments.insert(i + 1, landing)
            i += 2  # skip both the drop-down and landing
            continue

        if not is_stairs and height_delta > STEP_HEIGHT:
            # ── CLIMB_UP: insert climb segment, set landing to area center ──
            # Launch point: closest point on from_area to the destination
            launch_pos = from_seg.pos
            climb = Segment(
                area_id=from_seg.area_id,
                pos=launch_pos,
                type=SegmentType.CLIMB_UP,
            )
            # Landing: area center of destination (ensures bot moves onto ground)
            to_seg.pos = nav.area_center(to_seg.area_id)
            to_seg.type = SegmentType.ON_GROUND
            segments.insert(i, climb)
            i += 2  # skip both climb and landing
            continue

        i += 1

    return segments


def post_process(segments: list[Segment]) -> None:
    """Compute forward vectors, lengths, distances, and curvature.

    Mirrors ``Path::PostProcess``.
    """
    if not segments:
        return

    if len(segments) == 1:
        segments[0].forward = (0.0, 0.0, 0.0)
        segments[0].length = 0.0
        segments[0].distance_from_start = 0.0
        segments[0].curvature = 0.0
        return

    distance_so_far = 0.0
    for i in range(len(segments) - 1):
        s = segments[i]
        nxt = segments[i + 1]
        dx = nxt.pos[0] - s.pos[0]
        dy = nxt.pos[1] - s.pos[1]
        dz = nxt.pos[2] - s.pos[2]
        length = math.sqrt(dx * dx + dy * dy + dz * dz)
        if length > 0.001:
            s.forward = (dx / length, dy / length, dz / length)
        else:
            s.forward = (0.0, 0.0, 0.0)
        s.length = length
        s.distance_from_start = distance_so_far
        distance_so_far += length

    # Last segment inherits direction from previous
    last = segments[-1]
    last.forward = segments[-2].forward
    last.length = 0.0
    last.distance_from_start = distance_so_far

    # Curvature: 0.5 * (1 - dot(prev_fwd_2d, this_fwd_2d)), signed
    segments[0].curvature = 0.0
    for i in range(1, len(segments) - 1):
        if segments[i].type != SegmentType.ON_GROUND:
            segments[i].curvature = 0.0
            continue
        prev_fwd = segments[i - 1].forward
        this_fwd = segments[i].forward
        # Normalize 2D components
        pm = math.sqrt(prev_fwd[0] ** 2 + prev_fwd[1] ** 2)
        tm = math.sqrt(this_fwd[0] ** 2 + this_fwd[1] ** 2)
        if pm < 0.001 or tm < 0.001:
            segments[i].curvature = 0.0
            continue
        pfx, pfy = prev_fwd[0] / pm, prev_fwd[1] / pm
        tfx, tfy = this_fwd[0] / tm, this_fwd[1] / tm
        dot = pfx * tfx + pfy * tfy
        dot = max(-1.0, min(1.0, dot))
        curv = 0.5 * (1.0 - dot)
        # Sign: cross product
        cross = pfx * tfy - pfy * tfx
        if cross < 0:
            curv = -curv
        segments[i].curvature = curv

    last.curvature = 0.0


# ---------------------------------------------------------------------------
# PathFollower — per-bot path state and following logic
# ---------------------------------------------------------------------------

class PathFollower:
    """NextBot-style segment-based path follower."""

    def __init__(
        self,
        segments: list[Segment],
        nav: NavGraph,
        terrain: TerrainAnalyzer,
        clearance: ClearanceMap | None = None,
    ) -> None:
        self.segments = segments
        self.nav = nav
        self.terrain = terrain
        self.clearance = clearance
        self.goal_idx = 1  # first goal is the second segment (bot starts at first)
        # Telemetry: cached results from the last tick
        self.last_scan: tuple[float, int | None] = (float("inf"), None)
        self.last_steer: tuple[float, float, float] = (0.0, 0.0, 0.0)

    @property
    def total_length(self) -> float:
        if not self.segments:
            return 0.0
        return self.segments[-1].distance_from_start

    def is_valid(self) -> bool:
        return len(self.segments) > 0

    def get_goal(self) -> Segment | None:
        if 0 <= self.goal_idx < len(self.segments):
            return self.segments[self.goal_idx]
        return None

    # ── Goal advancement — mirrors PathFollower::IsAtGoal ──

    def is_at_goal(self, bot_pos: Pos3) -> bool:
        """Check if bot has reached the current goal segment."""
        goal = self.get_goal()
        if goal is None:
            return True

        to_goal = (
            goal.pos[0] - bot_pos[0],
            goal.pos[1] - bot_pos[1],
            goal.pos[2] - bot_pos[2],
        )

        if goal.type == SegmentType.DROP_DOWN:
            # Check if we're at the landing (next segment)
            landing_idx = self.goal_idx + 1
            if landing_idx >= len(self.segments):
                return True
            landing = self.segments[landing_idx]
            if bot_pos[2] - landing.pos[2] < STEP_HEIGHT:
                return True

        elif goal.type == SegmentType.CLIMB_UP:
            # Once we're above the goal, consider it reached
            if bot_pos[2] > goal.pos[2] + STEP_HEIGHT:
                return True

        else:
            # ON_GROUND: dividing plane check + distance fallback
            prior_idx = self.goal_idx - 1
            if prior_idx >= 0:
                prior = self.segments[prior_idx]
                # Average forward of prior and goal
                div_x = prior.forward[0] + goal.forward[0]
                div_y = prior.forward[1] + goal.forward[1]
                # Dot product: if negative, we've crossed the plane
                dot = to_goal[0] * div_x + to_goal[1] * div_y
                if dot < 0.0001:
                    return True

            # Distance fallback
            dist_2d = math.sqrt(to_goal[0] ** 2 + to_goal[1] ** 2)
            if dist_2d < GOAL_TOLERANCE:
                return True

        return False

    def advance(self) -> bool:
        """Advance to next goal segment. Returns False if path is complete."""
        self.goal_idx += 1
        if self.goal_idx >= len(self.segments):
            return False
        return True

    # ── Min look-ahead skip (mirrors PathFollower::CheckProgress) ──

    def skip_close_goals(self, bot_pos: Pos3) -> None:
        """Skip ground-level goals within MIN_LOOK_AHEAD_RANGE.

        Mirrors Valve's ``m_minLookAheadRange`` in ``PathFollower::CheckProgress``:
        if a goal is too close and the next one is also on-ground and reachable,
        advance past it to avoid orbiting tight waypoints at corners.
        """
        while self.goal_idx < len(self.segments) - 1:
            goal = self.segments[self.goal_idx]
            if goal.type != SegmentType.ON_GROUND:
                break

            dx = goal.pos[0] - bot_pos[0]
            dy = goal.pos[1] - bot_pos[1]
            dist = math.sqrt(dx * dx + dy * dy)
            if dist >= MIN_LOOK_AHEAD_RANGE:
                break

            nxt = self.segments[self.goal_idx + 1]
            if nxt.type != SegmentType.ON_GROUND:
                break
            # Don't skip uphill — matches Valve's stepHeight check
            if nxt.pos[2] > bot_pos[2] + STEP_HEIGHT:
                break

            self.goal_idx += 1

    # ── Path clearance validation ──

    def scan_path_clearance(self) -> tuple[float, int | None]:
        """Scan upcoming path and return (min_clearance, tightest_segment_idx).

        Traces along the line between consecutive waypoints, sampling
        clearance every ``_PATH_SAMPLE_STEP`` units.  Returns the minimum
        clearance found and the segment index where it occurs.

        The caller decides how to react based on the value:
        - ``< _PATH_CLEARANCE_BLOCKED`` — hard wall, skip past it
        - ``< _PATH_CLEARANCE_CAUTION`` — tight, aim past it
        - above caution — clear, normal path following

        Returns ``(inf, None)`` when no clearance data is available.
        """
        if self.clearance is None:
            return (float("inf"), None)

        worst_clr = float("inf")
        worst_idx: int | None = None

        end = min(self.goal_idx + _PATH_LOOKAHEAD, len(self.segments))
        for i in range(self.goal_idx, end):
            seg = self.segments[i]
            if seg.type != SegmentType.ON_GROUND:
                continue

            prev = self.segments[i - 1] if i > 0 else None
            if prev is None:
                continue

            dx = seg.pos[0] - prev.pos[0]
            dy = seg.pos[1] - prev.pos[1]
            seg_len = math.sqrt(dx * dx + dy * dy)
            if seg_len < 1.0:
                continue
            travel_angle = math.atan2(dy, dx)

            # Sample along the segment every _PATH_SAMPLE_STEP units
            n_samples = max(2, int(seg_len / _PATH_SAMPLE_STEP) + 1)
            for si in range(n_samples):
                t = si / (n_samples - 1)
                sx = prev.pos[0] + t * dx
                sy = prev.pos[1] + t * dy
                area_id = self.nav.find_area((sx, sy, 0.0))
                clr = self.clearance.get_clearance_at(
                    area_id, sx, sy, travel_angle, height=1,
                )
                if clr < worst_clr:
                    worst_clr = clr
                    worst_idx = i

        self.last_scan = (worst_clr, worst_idx)
        return (worst_clr, worst_idx)

    # ── Movement targets ──

    def get_move_target(self, bot_pos: Pos3) -> Pos3:
        """Return the position the bot should move toward.

        Pipeline: path tightness check → corner blending → clearance steering.
        When the path ahead is tight, the aim point is shifted further along
        the path (past the obstacle) so clearance steering naturally routes
        around it.  The tighter the path, the more we aim past.
        """
        goal = self.get_goal()
        if goal is None:
            return self.segments[-1].pos if self.segments else bot_pos

        goal_pos = goal.pos

        # ── Gradient aim-past: shift aim further ahead when path is tight ──
        if self.clearance is not None and goal.type == SegmentType.ON_GROUND:
            min_clr, tight_idx = self.scan_path_clearance()
            if tight_idx is not None and min_clr < _PATH_CLEARANCE_CAUTION:
                # Blend factor: 0.0 at caution threshold, 1.0 at blocked
                blend = 1.0 - min_clr / _PATH_CLEARANCE_CAUTION
                # Aim past the tight segment: pick 1-2 segments further
                aim_idx = min(tight_idx + 1, len(self.segments) - 1)
                aim_seg = self.segments[aim_idx]
                if aim_seg.type == SegmentType.ON_GROUND:
                    goal_pos = (
                        goal_pos[0] + blend * (aim_seg.pos[0] - goal_pos[0]),
                        goal_pos[1] + blend * (aim_seg.pos[1] - goal_pos[1]),
                        goal_pos[2] + blend * (aim_seg.pos[2] - goal_pos[2]),
                    )

        # Corner blending: when approaching a curve, aim past the corner
        nxt_idx = self.goal_idx + 1
        if (
            abs(goal.curvature) > 0.1
            and goal.type == SegmentType.ON_GROUND
            and nxt_idx < len(self.segments)
            and self.segments[nxt_idx].type == SegmentType.ON_GROUND
        ):
            dx = goal.pos[0] - bot_pos[0]
            dy = goal.pos[1] - bot_pos[1]
            dist = math.sqrt(dx * dx + dy * dy)
            if dist < CORNER_BLEND_RANGE:
                nxt = self.segments[nxt_idx]
                t = 0.5 * (1.0 - dist / CORNER_BLEND_RANGE)
                goal_pos = (
                    goal_pos[0] + t * (nxt.pos[0] - goal_pos[0]),
                    goal_pos[1] + t * (nxt.pos[1] - goal_pos[1]),
                    goal_pos[2] + t * (nxt.pos[2] - goal_pos[2]),
                )

        # Clearance-steered movement: path gives direction, spatial data
        # picks the actual heading.  Falls back to direct goal if no
        # clearance data or no passable direction found.
        if self.clearance is not None and goal.type == SegmentType.ON_GROUND:
            area_id = self.nav.find_area(bot_pos)
            sdx, sdy, best_clr = self.clearance.get_steering_direction(
                area_id, bot_pos[0], bot_pos[1], goal_pos[0], goal_pos[1],
            )
            self.last_steer = (sdx, sdy, best_clr)
            if abs(sdx) > 0.001 or abs(sdy) > 0.001:
                dx = goal_pos[0] - bot_pos[0]
                dy = goal_pos[1] - bot_pos[1]
                dist = math.sqrt(dx * dx + dy * dy)
                step = min(dist, STEER_AHEAD_DIST)

                # Forward probe: check clearance along the chosen direction.
                # If it hits a wall ahead, re-steer from that probe point.
                steer_angle = math.atan2(sdy, sdx)
                for probe in _FORWARD_PROBES:
                    if probe > step:
                        break
                    px = bot_pos[0] + sdx * probe
                    py = bot_pos[1] + sdy * probe
                    probe_area = self.nav.find_area((px, py, 0.0))
                    clr = self.clearance.get_clearance_at(
                        probe_area, px, py, steer_angle, height=1,
                    )
                    if clr < _FORWARD_PROBE_MIN:
                        # Re-steer from the probe point — aims around obstacle
                        sdx2, sdy2, _ = self.clearance.get_steering_direction(
                            probe_area, px, py, goal_pos[0], goal_pos[1],
                        )
                        if abs(sdx2) > 0.001 or abs(sdy2) > 0.001:
                            sdx, sdy = sdx2, sdy2
                            step = min(dist, probe)  # shorter step
                        break

                return (
                    bot_pos[0] + sdx * step,
                    bot_pos[1] + sdy * step,
                    goal_pos[2],
                )

        return goal_pos

    def get_look_target(self, bot_pos: Pos3) -> Pos3:
        """Return a point further ahead on the path for look direction."""
        if not self.segments:
            return bot_pos

        remaining = LOOK_AHEAD_DIST
        current = bot_pos

        for i in range(self.goal_idx, len(self.segments)):
            seg_pos = self.segments[i].pos
            dx = seg_pos[0] - current[0]
            dy = seg_pos[1] - current[1]
            seg_len = math.sqrt(dx * dx + dy * dy)

            if seg_len >= remaining and seg_len > 0.001:
                t = remaining / seg_len
                return (
                    current[0] + dx * t,
                    current[1] + dy * t,
                    current[2] + (seg_pos[2] - current[2]) * t,
                )

            remaining -= seg_len
            current = seg_pos

        return self.segments[-1].pos

    # ── Flags ──

    def compute_flags(
        self, bot_pos: Pos3, tick: int, last_jump_tick: int,
    ) -> tuple[int, int]:
        """Compute movement flags from upcoming segment types.

        Returns ``(flags, updated_last_jump_tick)``.
        """
        from smartbots.protocol import FLAG_DUCK, FLAG_JUMP

        flags = 0
        goal = self.get_goal()
        if goal is None:
            return (flags, last_jump_tick)

        dx = bot_pos[0] - goal.pos[0]
        dy = bot_pos[1] - goal.pos[1]
        dist = math.sqrt(dx * dx + dy * dy)

        # Jump for CLIMB_UP segments
        if goal.type == SegmentType.CLIMB_UP and dist < JUMP_TRIGGER_DIST:
            if (tick - last_jump_tick) >= JUMP_COOLDOWN:
                flags |= FLAG_JUMP
                last_jump_tick = tick

        # Crouch for crouch areas (check goal and next segment)
        if self.terrain.is_crouch_area(goal.area_id):
            flags |= FLAG_DUCK
        elif self.goal_idx + 1 < len(self.segments):
            nxt = self.segments[self.goal_idx + 1]
            if self.terrain.is_crouch_area(nxt.area_id):
                ndx = bot_pos[0] - nxt.pos[0]
                ndy = bot_pos[1] - nxt.pos[1]
                if math.sqrt(ndx * ndx + ndy * ndy) < CROUCH_APPROACH_DIST:
                    flags |= FLAG_DUCK

        # Also check current area
        current_area = self.nav.find_area(bot_pos)
        if self.terrain.is_crouch_area(current_area):
            flags |= FLAG_DUCK

        # Check terrain transitions for crouch
        trans = self.terrain.get_transition(
            self.segments[max(0, self.goal_idx - 1)].area_id, goal.area_id,
        )
        if trans is not None and trans.needs_crouch:
            flags |= FLAG_DUCK

        return (flags, last_jump_tick)

    # ── Path deviation ──

    def deviation(self, bot_pos: Pos3) -> float:
        """Distance from bot to the closest point on the path polyline."""
        best_dist_sq = float("inf")
        start = max(0, self.goal_idx - 1)
        for i in range(start, len(self.segments) - 1):
            a = self.segments[i].pos
            b = self.segments[i + 1].pos
            closest, _ = _closest_point_on_segment(bot_pos, a, b)
            dx = bot_pos[0] - closest[0]
            dy = bot_pos[1] - closest[1]
            d_sq = dx * dx + dy * dy
            if d_sq < best_dist_sq:
                best_dist_sq = d_sq
        return math.sqrt(best_dist_sq) if best_dist_sq < float("inf") else 0.0


# ---------------------------------------------------------------------------
# Top-level path computation
# ---------------------------------------------------------------------------

def compute_path(
    start_pos: Pos3,
    goal_pos: Pos3,
    nav: NavGraph,
    terrain: TerrainAnalyzer,
    clearance: ClearanceMap | None = None,
) -> PathFollower | None:
    """Full pipeline: A* → segment chain → path details → post-process.

    Returns a ready-to-follow ``PathFollower``, or ``None`` if no path exists.
    """
    start_area = nav.find_area(start_pos)
    goal_area = nav.find_area(goal_pos)

    if start_area == goal_area:
        # Trivial path — same area
        segs = [
            Segment(area_id=start_area, pos=start_pos),
            Segment(area_id=goal_area, pos=goal_pos),
        ]
        post_process(segs)
        return PathFollower(segs, nav, terrain, clearance)

    area_path = nav.find_path(start_area, goal_area)
    if area_path is None:
        return None

    # Build raw segment chain (one per area)
    segments: list[Segment] = []
    for j, area_id in enumerate(area_path):
        if j == 0:
            pos = start_pos
        else:
            pos = nav.area_center(area_id)  # placeholder, overwritten by compute_path_details
        segments.append(Segment(area_id=area_id, pos=pos))

    # Append actual goal position as final segment
    segments[-1].pos = goal_pos

    # Set crossing positions, detect climbs/drops
    segments = compute_path_details(segments, nav, terrain, clearance)

    # Compute forward/length/curvature
    post_process(segments)

    log.info(
        "Path: %d areas -> %d segments, length=%.0f",
        len(area_path), len(segments), segments[-1].distance_from_start if segments else 0,
    )
    return PathFollower(segments, nav, terrain, clearance)
