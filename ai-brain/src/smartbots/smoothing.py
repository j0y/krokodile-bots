"""Path smoothing (Catmull-Rom) and separation force for multi-bot navigation."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smartbots.navigation import NavGraph

from smartbots.navigation import AnnotatedWaypoint, NARROW_PORTAL_THRESHOLD

Pos3 = tuple[float, float, float]

# ── Catmull-Rom smoothing ─────────────────────────────────────────────


def _catmull_rom_point(p0: Pos3, p1: Pos3, p2: Pos3, p3: Pos3, t: float) -> Pos3:
    """Evaluate Catmull-Rom spline at parameter *t* between p1 and p2."""
    t2 = t * t
    t3 = t2 * t
    x = 0.5 * (
        2 * p1[0]
        + (-p0[0] + p2[0]) * t
        + (2 * p0[0] - 5 * p1[0] + 4 * p2[0] - p3[0]) * t2
        + (-p0[0] + 3 * p1[0] - 3 * p2[0] + p3[0]) * t3
    )
    y = 0.5 * (
        2 * p1[1]
        + (-p0[1] + p2[1]) * t
        + (2 * p0[1] - 5 * p1[1] + 4 * p2[1] - p3[1]) * t2
        + (-p0[1] + 3 * p1[1] - 3 * p2[1] + p3[1]) * t3
    )
    z = 0.5 * (
        2 * p1[2]
        + (-p0[2] + p2[2]) * t
        + (2 * p0[2] - 5 * p1[2] + 4 * p2[2] - p3[2]) * t2
        + (-p0[2] + 3 * p1[2] - 3 * p2[2] + p3[2]) * t3
    )
    return (x, y, z)


def _is_hard_corner(
    wp_a: AnnotatedWaypoint, wp_b: AnnotatedWaypoint, nav: NavGraph,
) -> bool:
    """True if the segment crosses a narrow doorway — do not smooth."""
    if wp_a.area_id == wp_b.area_id:
        return False
    width = nav.portal_width(wp_a.area_id, wp_b.area_id)
    return 0 < width < NARROW_PORTAL_THRESHOLD


def smooth_waypoints(
    waypoints: list[AnnotatedWaypoint],
    nav: NavGraph,
    subdivisions: int = 3,
) -> list[AnnotatedWaypoint]:
    """Insert Catmull-Rom sub-waypoints for smooth curves.

    Original waypoints are preserved exactly. Between each pair,
    *subdivisions* intermediate points are inserted along the spline.
    Hard corners (narrow doorways) are not smoothed.
    """
    if len(waypoints) <= 2:
        return list(waypoints)

    result: list[AnnotatedWaypoint] = []

    for i in range(len(waypoints) - 1):
        result.append(waypoints[i])

        # Skip smoothing across narrow doorways
        if _is_hard_corner(waypoints[i], waypoints[i + 1], nav):
            continue

        # Four control points with endpoint clamping
        p0 = waypoints[max(i - 1, 0)].pos
        p1 = waypoints[i].pos
        p2 = waypoints[i + 1].pos
        p3 = waypoints[min(i + 2, len(waypoints) - 1)].pos

        # Propagate annotations: inherit the more restrictive flags
        jump = waypoints[i].needs_jump or waypoints[i + 1].needs_jump
        crouch = waypoints[i].needs_crouch or waypoints[i + 1].needs_crouch
        area_id = waypoints[i].area_id

        for s in range(1, subdivisions + 1):
            t = s / (subdivisions + 1)
            pos = _catmull_rom_point(p0, p1, p2, p3, t)
            result.append(AnnotatedWaypoint(
                pos=pos, area_id=area_id,
                needs_jump=jump, needs_crouch=crouch,
            ))

    # Final waypoint
    result.append(waypoints[-1])
    return result


# ── Separation force ──────────────────────────────────────────────────

SEPARATION_RADIUS = 100.0
SEPARATION_STRENGTH = 50.0
MIN_SEPARATION_DIST = 10.0


def apply_separation(
    bot_pos: Pos3,
    move_target: Pos3,
    peer_positions: list[Pos3],
) -> Pos3:
    """Push *move_target* away from nearby peers to prevent clumping."""
    push_x, push_y = 0.0, 0.0

    for peer in peer_positions:
        dx = bot_pos[0] - peer[0]
        dy = bot_pos[1] - peer[1]
        dist = math.sqrt(dx * dx + dy * dy)
        if dist < MIN_SEPARATION_DIST or dist > SEPARATION_RADIUS:
            continue
        force = SEPARATION_STRENGTH / dist
        push_x += (dx / dist) * force
        push_y += (dy / dist) * force

    push_mag = math.sqrt(push_x * push_x + push_y * push_y)
    if push_mag > SEPARATION_STRENGTH:
        scale = SEPARATION_STRENGTH / push_mag
        push_x *= scale
        push_y *= scale

    return (
        move_target[0] + push_x,
        move_target[1] + push_y,
        move_target[2],
    )
