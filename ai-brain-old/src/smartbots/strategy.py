"""Strategy layer — goal assignment for bots."""

from __future__ import annotations

import logging
import math
from typing import Protocol

from smartbots.behavior import BotBrain, BotBehaviorState, BotGoal, BotGoalType
from smartbots.navigation import NavGraph, Pos3
from smartbots.state import GameState

log = logging.getLogger(__name__)

# Nav area flags (from Source engine)
_NAV_CROUCH_FLAG = 0x01
_NAV_STAIRS_FLAG = 0x1000

# Shuttle pair selection thresholds
_MIN_AREA_SIZE = 10_000.0      # sq.u — ~100x100
_MAX_HEIGHT_DELTA = 10.0       # units
_MIN_PORTAL_WIDTH = 64.0       # units

# Relaxed fallbacks
_MIN_AREA_SIZE_RELAXED = 4_000.0
_MAX_HEIGHT_DELTA_RELAXED = 30.0
_MIN_PORTAL_WIDTH_RELAXED = 32.0


class Strategy(Protocol):
    """Interface for goal-assignment strategies."""

    def assign_goals(
        self,
        state: GameState,
        brains: dict[int, BotBrain],
        nav: NavGraph,
    ) -> dict[int, BotGoal]: ...


class ShuttleStrategy:
    """Each bot shuttles between two nearby adjacent areas for movement testing."""

    def __init__(self) -> None:
        self._pairs: dict[int, tuple[Pos3, Pos3]] = {}

    def assign_goals(
        self,
        state: GameState,
        brains: dict[int, BotBrain],
        nav: NavGraph,
    ) -> dict[int, BotGoal]:
        new_goals: dict[int, BotGoal] = {}
        for bot in state.bots.values():
            if not bot.alive:
                continue
            brain = brains.get(bot.id)
            if brain is None or brain.state == BotBehaviorState.IDLE:
                pair = self._get_pair(bot.id, bot.pos, nav)
                if pair is None:
                    log.warning("bot=%d: no shuttle pair found", bot.id)
                    continue
                new_goals[bot.id] = BotGoal(
                    type=BotGoalType.PATROL,
                    position=pair[0],
                    patrol_points=list(pair),
                    patrol_idx=0,
                )
        return new_goals

    def _get_pair(
        self, bot_id: int, pos: Pos3, nav: NavGraph,
    ) -> tuple[Pos3, Pos3] | None:
        if bot_id in self._pairs:
            return self._pairs[bot_id]

        pair = self._find_pair(pos, nav, strict=True)
        if pair is None:
            pair = self._find_pair(pos, nav, strict=False)
        if pair is None:
            return None

        self._pairs[bot_id] = pair
        log.info(
            "bot=%d: shuttle pair (%.0f,%.0f,%.0f) <-> (%.0f,%.0f,%.0f)",
            bot_id, *pair[0], *pair[1],
        )
        return pair

    def _find_pair(
        self, pos: Pos3, nav: NavGraph, *, strict: bool,
    ) -> tuple[Pos3, Pos3] | None:
        min_size = _MIN_AREA_SIZE if strict else _MIN_AREA_SIZE_RELAXED
        max_hdelta = _MAX_HEIGHT_DELTA if strict else _MAX_HEIGHT_DELTA_RELAXED
        min_portal = _MIN_PORTAL_WIDTH if strict else _MIN_PORTAL_WIDTH_RELAXED

        near_area = nav.find_area(pos)
        # Search within a radius of connected areas (BFS up to depth 6)
        candidates = self._bfs_areas(near_area, nav, max_depth=6)

        # Score candidate pairs: lower = better (closer to bot)
        best: tuple[float, Pos3, Pos3] | None = None

        for aid in candidates:
            area = nav.areas[aid]
            # Filter: no stairs, no crouch
            if area.flags & (_NAV_STAIRS_FLAG | _NAV_CROUCH_FLAG):
                continue
            # Filter: large enough
            if nav._area_size(aid) < min_size:
                continue

            ca = nav._centers[aid]

            for nid in area.neighbor_ids():
                if nid not in nav.areas or nid not in candidates:
                    continue
                nb = nav.areas[nid]
                if nb.flags & (_NAV_STAIRS_FLAG | _NAV_CROUCH_FLAG):
                    continue
                if nav._area_size(nid) < min_size:
                    continue

                # Height delta check
                cb = nav._centers[nid]
                if abs(ca.z - cb.z) > max_hdelta:
                    continue

                # Portal width check
                pw = nav.portal_width(aid, nid)
                if pw < min_portal:
                    continue

                # Score: distance from bot spawn to midpoint of pair
                mx = (ca.x + cb.x) / 2
                my = (ca.y + cb.y) / 2
                dist = math.sqrt((pos[0] - mx) ** 2 + (pos[1] - my) ** 2)

                if best is None or dist < best[0]:
                    best = (dist, (ca.x, ca.y, ca.z), (cb.x, cb.y, cb.z))

        if best is None:
            return None
        return (best[1], best[2])

    @staticmethod
    def _bfs_areas(start: int, nav: NavGraph, max_depth: int) -> set[int]:
        """BFS from *start*, returning all area IDs within *max_depth* hops."""
        from collections import deque

        visited: set[int] = {start}
        queue: deque[tuple[int, int]] = deque([(start, 0)])
        while queue:
            aid, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for nid in nav.areas[aid].neighbor_ids():
                if nid in nav.areas and nid not in visited:
                    visited.add(nid)
                    queue.append((nid, depth + 1))
        return visited
