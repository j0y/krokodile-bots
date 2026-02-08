"""Movement controller — pathfind all alive bots to a gathering point."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field

from smartbots.navigation import NavGraph
from smartbots.protocol import BotCommand
from smartbots.state import GameState

log = logging.getLogger(__name__)

# How close (Source units) a bot must be to a waypoint before advancing.
WAYPOINT_REACH_DIST = 150.0
# If the bot is further than this from its next waypoint, recompute the path.
REPATH_DIST = 300.0
# Re-check path validity every N ticks (~5 seconds at 8Hz).
REPATH_INTERVAL = 40
# If a bot hasn't moved at least this far in STUCK_TICKS, skip the waypoint.
STUCK_MOVE_DIST = 20.0
STUCK_TICKS = 40  # ~5 seconds at 8Hz


@dataclass
class BotNavState:
    """Per-bot navigation state."""

    waypoints: list[tuple[float, float, float]]
    waypoint_idx: int = 0
    last_repath_tick: int = 0
    last_progress_tick: int = 0
    last_progress_pos: tuple[float, float, float] = (0.0, 0.0, 0.0)


class MovementController:
    """Computes movement commands using nav mesh pathfinding."""

    def __init__(self, nav: NavGraph) -> None:
        self.nav = nav
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

        waypoints = self.nav.path_to_waypoints(path)
        nav_state = BotNavState(
            waypoints=waypoints, last_repath_tick=tick,
            last_progress_tick=tick, last_progress_pos=pos,
        )
        log.info(
            "bot=%d: path %d -> %d (%d waypoints)",
            bot_id, path[0], path[-1], len(waypoints),
        )
        return nav_state

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
                dx = bot.pos[0] - wp[0]
                dy = bot.pos[1] - wp[1]
                if math.sqrt(dx * dx + dy * dy) < WAYPOINT_REACH_DIST:
                    nav_state.waypoint_idx += 1
                else:
                    break

            # Already at destination (or all waypoints skipped)
            if nav_state.waypoint_idx >= len(nav_state.waypoints):
                # Check if we're actually near the goal or just burned through skips
                goal_center = self.nav.area_center(goal_area)
                gdx = bot.pos[0] - goal_center[0]
                gdy = bot.pos[1] - goal_center[1]
                if math.sqrt(gdx * gdx + gdy * gdy) > WAYPOINT_REACH_DIST:
                    # Not at goal — force repath on next tick
                    self._bot_nav.pop(bot.id, None)
                continue

            # Stuck detection: if bot hasn't moved enough, skip waypoint
            if (state.tick - nav_state.last_progress_tick) >= STUCK_TICKS:
                pdx = bot.pos[0] - nav_state.last_progress_pos[0]
                pdy = bot.pos[1] - nav_state.last_progress_pos[1]
                moved = math.sqrt(pdx * pdx + pdy * pdy)
                if moved < STUCK_MOVE_DIST:
                    old_idx = nav_state.waypoint_idx
                    nav_state.waypoint_idx += 1
                    log.warning(
                        "bot=%d: stuck (moved=%.0f in %d ticks), skip wp %d -> %d/%d",
                        bot.id, moved, STUCK_TICKS, old_idx,
                        nav_state.waypoint_idx, len(nav_state.waypoints),
                    )
                    if nav_state.waypoint_idx >= len(nav_state.waypoints):
                        continue
                    # After skipping, suppress repath for a while so we don't
                    # immediately repath back to waypoint 0 (skip→repath loop).
                    nav_state.last_repath_tick = state.tick
                # Reset progress tracker
                nav_state.last_progress_tick = state.tick
                nav_state.last_progress_pos = bot.pos

            # Repath if too far from next waypoint (bot drifted off course)
            wp = nav_state.waypoints[nav_state.waypoint_idx]
            dx = bot.pos[0] - wp[0]
            dy = bot.pos[1] - wp[1]
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
                    dx = bot.pos[0] - wp[0]
                    dy = bot.pos[1] - wp[1]
                    dist = math.sqrt(dx * dx + dy * dy)

            commands.append(BotCommand(id=bot.id, target=wp, speed=1.0))

            if state.tick % 40 == 0:
                log.info(
                    "  bot=%d wp=%d/%d pos=(%.0f,%.0f) -> wp=(%.0f,%.0f) dist=%.0f",
                    bot.id, nav_state.waypoint_idx, len(nav_state.waypoints),
                    bot.pos[0], bot.pos[1], wp[0], wp[1], dist,
                )

        return commands
