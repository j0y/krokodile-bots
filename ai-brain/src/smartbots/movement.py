"""Movement controller — pathfind all alive bots to a gathering point."""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass

from smartbots.navigation import AnnotatedWaypoint, NavGraph
from smartbots.protocol import BotCommand, FLAG_DUCK, FLAG_JUMP
from smartbots.state import GameState
from smartbots.terrain import TerrainAnalyzer

log = logging.getLogger(__name__)

# How close (Source units) a bot must be to a waypoint before advancing.
WAYPOINT_REACH_DIST = 150.0
# If the bot is further than this from its next waypoint, recompute the path.
REPATH_DIST = 300.0
# Re-check path validity every N ticks (~5 seconds at 8Hz).
REPATH_INTERVAL = 40
# If a bot hasn't moved at least this far in STUCK_TICKS, nudge it.
STUCK_MOVE_DIST = 20.0
STUCK_TICKS = 40  # ~5 seconds at 8Hz
# Random nudge distance when stuck (short walk to get off a ledge).
NUDGE_DIST = 50.0
# How many ticks the nudge lasts before resuming normal navigation.
NUDGE_TICKS = 16  # ~2 seconds at 8Hz
# Jump trigger distance: start jumping when within this distance of a jump waypoint.
JUMP_TRIGGER_DIST = 50.0
# Jump cooldown in ticks (~0.5s at 8Hz).
JUMP_COOLDOWN = 4
# Crouch approach distance: start crouching this far before a crouch waypoint.
CROUCH_APPROACH_DIST = 100.0


@dataclass
class BotNavState:
    """Per-bot navigation state."""

    waypoints: list[AnnotatedWaypoint]
    waypoint_idx: int = 0
    last_repath_tick: int = 0
    last_progress_tick: int = 0
    last_progress_pos: tuple[float, float, float] = (0.0, 0.0, 0.0)
    last_jump_tick: int = 0
    # Nudge: random walk to get off ledges
    nudge_target: tuple[float, float, float] | None = None
    nudge_until: int = 0


class MovementController:
    """Computes movement commands using nav mesh pathfinding."""

    def __init__(self, nav: NavGraph, terrain: TerrainAnalyzer) -> None:
        self.nav = nav
        self.terrain = terrain
        self.target_area: int | None = None
        self._bot_nav: dict[int, BotNavState] = {}
        self._unreachable: set[int] = set()

    def _ensure_target(self, near_pos: tuple[float, float, float]) -> int:
        """Compute gathering point within the component reachable from *near_pos*."""
        if self.target_area is None:
            near_area = self.nav.find_area(near_pos)
            self.target_area = self.nav.find_gathering_point(near_area)
        return self.target_area

    def _compute_path(self, bot_id: int, pos: tuple[float, float, float],
                      goal_area: int, tick: int) -> BotNavState | None:
        """Compute a fresh path from the bot's current position to the goal."""
        current_area = self.nav.find_area(pos)
        path = self.nav.find_path(current_area, goal_area)

        if path is None:
            local_target = self.nav.find_gathering_point(current_area)
            path = self.nav.find_path(current_area, local_target)

        if path is None:
            return None

        waypoints = self.nav.path_to_safe_waypoints(path, self.terrain)
        nav_state = BotNavState(
            waypoints=waypoints, last_repath_tick=tick,
            last_progress_tick=tick, last_progress_pos=pos,
        )
        log.info(
            "bot=%d: path %d -> %d (%d waypoints)",
            bot_id, path[0], path[-1], len(waypoints),
        )
        return nav_state

    def _compute_flags(
        self, nav_state: BotNavState, bot_pos: tuple[float, float, float], tick: int,
    ) -> int:
        """Compute action flags (jump/crouch) based on annotated waypoints."""
        flags = 0
        idx = nav_state.waypoint_idx
        if idx >= len(nav_state.waypoints):
            return flags

        wp = nav_state.waypoints[idx]
        dx = bot_pos[0] - wp.pos[0]
        dy = bot_pos[1] - wp.pos[1]
        dist = math.sqrt(dx * dx + dy * dy)

        # Jump: trigger when close to a jump waypoint, with cooldown
        if wp.needs_jump and dist < JUMP_TRIGGER_DIST:
            if (tick - nav_state.last_jump_tick) >= JUMP_COOLDOWN:
                flags |= FLAG_JUMP
                nav_state.last_jump_tick = tick

        # Crouch: if current waypoint needs crouch
        if wp.needs_crouch:
            flags |= FLAG_DUCK
        # Also check if approaching a crouch waypoint
        elif idx + 1 < len(nav_state.waypoints):
            next_wp = nav_state.waypoints[idx + 1]
            if next_wp.needs_crouch:
                ndx = bot_pos[0] - next_wp.pos[0]
                ndy = bot_pos[1] - next_wp.pos[1]
                ndist = math.sqrt(ndx * ndx + ndy * ndy)
                if ndist < CROUCH_APPROACH_DIST:
                    flags |= FLAG_DUCK

        # Also crouch if the bot is currently in a crouch area
        current_area = self.nav.find_area(bot_pos)
        if self.terrain.is_crouch_area(current_area):
            flags |= FLAG_DUCK

        return flags

    def _look_ahead(self, nav_state: BotNavState) -> tuple[float, float, float]:
        """Look at the next waypoint after the current one (look-ahead)."""
        idx = nav_state.waypoint_idx
        if idx + 1 < len(nav_state.waypoints):
            return nav_state.waypoints[idx + 1].pos
        # At last waypoint — look at it directly
        if idx < len(nav_state.waypoints):
            return nav_state.waypoints[idx].pos
        return nav_state.waypoints[-1].pos

    def compute_commands(self, state: GameState) -> list[BotCommand]:
        commands: list[BotCommand] = []

        first_alive = next((b for b in state.bots.values() if b.alive), None)
        if first_alive is None:
            return commands
        goal_area = self._ensure_target(first_alive.pos)

        for bot in state.bots.values():
            if not bot.alive:
                self._bot_nav.pop(bot.id, None)
                self._unreachable.discard(bot.id)
                continue

            if bot.id in self._unreachable:
                continue

            nav_state = self._bot_nav.get(bot.id)

            # Compute path for new / respawned bots
            if nav_state is None:
                nav_state = self._compute_path(bot.id, bot.pos, goal_area, state.tick)
                if nav_state is None:
                    log.warning("bot=%d: no path found", bot.id)
                    self._unreachable.add(bot.id)
                    continue
                self._bot_nav[bot.id] = nav_state

            # Advance past reached waypoints
            while nav_state.waypoint_idx < len(nav_state.waypoints):
                wp = nav_state.waypoints[nav_state.waypoint_idx]
                dx = bot.pos[0] - wp.pos[0]
                dy = bot.pos[1] - wp.pos[1]
                if math.sqrt(dx * dx + dy * dy) < WAYPOINT_REACH_DIST:
                    nav_state.waypoint_idx += 1
                else:
                    break

            # Already at destination
            if nav_state.waypoint_idx >= len(nav_state.waypoints):
                continue

            # If currently nudging, send the nudge target
            if nav_state.nudge_target is not None:
                if state.tick < nav_state.nudge_until:
                    commands.append(BotCommand(
                        id=bot.id, move_target=nav_state.nudge_target,
                        look_target=nav_state.nudge_target,
                    ))
                    continue
                # Nudge done — repath from new position
                log.info("bot=%d: nudge done, repathing", bot.id)
                nav_state.nudge_target = None
                new_state = self._compute_path(bot.id, bot.pos, goal_area, state.tick)
                if new_state is not None:
                    self._bot_nav[bot.id] = new_state
                    nav_state = new_state
                    if nav_state.waypoint_idx >= len(nav_state.waypoints):
                        continue
                else:
                    self._bot_nav.pop(bot.id, None)
                    continue

            # Stuck detection: if bot hasn't moved enough, nudge in random direction
            if (state.tick - nav_state.last_progress_tick) >= STUCK_TICKS:
                pdx = bot.pos[0] - nav_state.last_progress_pos[0]
                pdy = bot.pos[1] - nav_state.last_progress_pos[1]
                moved = math.sqrt(pdx * pdx + pdy * pdy)
                if moved < STUCK_MOVE_DIST:
                    angle = random.uniform(0, 2 * math.pi)
                    nudge = (
                        bot.pos[0] + math.cos(angle) * NUDGE_DIST,
                        bot.pos[1] + math.sin(angle) * NUDGE_DIST,
                        bot.pos[2],
                    )
                    nav_state.nudge_target = nudge
                    nav_state.nudge_until = state.tick + NUDGE_TICKS
                    log.warning(
                        "bot=%d: stuck (moved=%.0f), nudging to (%.0f,%.0f)",
                        bot.id, moved, nudge[0], nudge[1],
                    )
                    commands.append(BotCommand(
                        id=bot.id, move_target=nudge, look_target=nudge,
                    ))
                    continue
                # Made progress — reset tracker
                nav_state.last_progress_tick = state.tick
                nav_state.last_progress_pos = bot.pos

            # Repath if too far from next waypoint (bot drifted off course)
            wp = nav_state.waypoints[nav_state.waypoint_idx]
            dx = bot.pos[0] - wp.pos[0]
            dy = bot.pos[1] - wp.pos[1]
            dist = math.sqrt(dx * dx + dy * dy)

            if dist > REPATH_DIST and (state.tick - nav_state.last_repath_tick) >= REPATH_INTERVAL:
                log.info("bot=%d: repathing (dist=%.0f > %.0f)", bot.id, dist, REPATH_DIST)
                new_state = self._compute_path(bot.id, bot.pos, goal_area, state.tick)
                if new_state is not None:
                    nav_state = new_state
                    self._bot_nav[bot.id] = nav_state
                    if nav_state.waypoint_idx >= len(nav_state.waypoints):
                        continue
                    wp = nav_state.waypoints[nav_state.waypoint_idx]
                    dx = bot.pos[0] - wp.pos[0]
                    dy = bot.pos[1] - wp.pos[1]
                    dist = math.sqrt(dx * dx + dy * dy)

            flags = self._compute_flags(nav_state, bot.pos, state.tick)
            look_target = self._look_ahead(nav_state)

            commands.append(BotCommand(
                id=bot.id, move_target=wp.pos, look_target=look_target, flags=flags,
            ))

            if state.tick % 40 == 0:
                log.info(
                    "  bot=%d wp=%d/%d pos=(%.0f,%.0f) -> wp=(%.0f,%.0f) dist=%.0f"
                    " flags=%d jump=%s crouch=%s",
                    bot.id, nav_state.waypoint_idx, len(nav_state.waypoints),
                    bot.pos[0], bot.pos[1], wp.pos[0], wp.pos[1], dist,
                    flags, wp.needs_jump, wp.needs_crouch,
                )

        return commands
