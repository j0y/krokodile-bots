"""Terrain analysis — detect jump/crouch transitions between nav areas."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from smartbots.nav_parser import NavArea
from smartbots.navigation import NavGraph

log = logging.getLogger(__name__)

NAV_CROUCH_FLAG = 0x01
NAV_STAIRS_FLAG = 0x1000
JUMP_THRESHOLD = 18.0  # Source engine step height


@dataclass
class AreaTransition:
    from_id: int
    to_id: int
    height_delta: float
    needs_jump: bool
    needs_crouch: bool


class TerrainAnalyzer:
    """Pre-computes transition metadata between connected nav areas."""

    def __init__(self, nav: NavGraph) -> None:
        self.nav = nav
        self._transitions: dict[tuple[int, int], AreaTransition] = {}
        self._crouch_areas: set[int] = set()
        self._build()

    def _z_at(self, area: NavArea, x: float, y: float) -> float:
        """Bilinear Z interpolation within an area using 4 corner heights."""
        min_x = min(area.nw.x, area.se.x)
        max_x = max(area.nw.x, area.se.x)
        min_y = min(area.nw.y, area.se.y)
        max_y = max(area.nw.y, area.se.y)

        dx = max_x - min_x
        dy = max_y - min_y

        # Normalized coordinates [0,1]
        u = (x - min_x) / dx if dx > 0.001 else 0.5
        v = (y - min_y) / dy if dy > 0.001 else 0.5
        u = max(0.0, min(1.0, u))
        v = max(0.0, min(1.0, v))

        # Corner heights: NW, NE, SW, SE
        z_nw = area.nw.z
        z_ne = area.ne_z
        z_sw = area.sw_z
        z_se = area.se.z

        # Bilinear interpolation
        z_top = z_nw + (z_ne - z_nw) * u     # north edge
        z_bot = z_sw + (z_se - z_sw) * u     # south edge
        return z_top + (z_bot - z_top) * v

    def _build(self) -> None:
        jump_count = 0
        crouch_count = 0

        for area_id, area in self.nav.areas.items():
            if area.flags & NAV_CROUCH_FLAG:
                self._crouch_areas.add(area_id)
                crouch_count += 1

            for neighbor_id in area.neighbor_ids():
                if neighbor_id not in self.nav.areas:
                    continue

                neighbor = self.nav.areas[neighbor_id]
                cross = self.nav.crossing_point(area_id, neighbor_id)

                z_from = self._z_at(area, cross[0], cross[1])
                z_to = self._z_at(neighbor, cross[0], cross[1])
                height_delta = z_to - z_from

                is_stairs = bool(area.flags & NAV_STAIRS_FLAG) or bool(
                    neighbor.flags & NAV_STAIRS_FLAG
                )
                needs_jump = height_delta > JUMP_THRESHOLD and not is_stairs
                needs_crouch = bool(neighbor.flags & NAV_CROUCH_FLAG)

                if needs_jump:
                    jump_count += 1

                self._transitions[(area_id, neighbor_id)] = AreaTransition(
                    from_id=area_id,
                    to_id=neighbor_id,
                    height_delta=height_delta,
                    needs_jump=needs_jump,
                    needs_crouch=needs_crouch,
                )

        log.info(
            "Terrain analysis: %d transitions, %d jumps, %d crouch areas",
            len(self._transitions), jump_count, crouch_count,
        )

    def get_transition(self, from_id: int, to_id: int) -> AreaTransition | None:
        return self._transitions.get((from_id, to_id))

    def is_crouch_area(self, area_id: int) -> bool:
        return area_id in self._crouch_areas
