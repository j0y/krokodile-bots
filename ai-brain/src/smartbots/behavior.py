"""Per-bot behavior model with state machine and goal system."""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

from smartbots.navigation import AnnotatedWaypoint, NavGraph
from smartbots.protocol import BotCommand, FLAG_DUCK, FLAG_JUMP, FLAG_TELEPORT
from smartbots.state import BotState, GameState
from smartbots.terrain import TerrainAnalyzer

if TYPE_CHECKING:
    from smartbots.strategy import Strategy

log = logging.getLogger(__name__)

# Navigation constants
WAYPOINT_REACH_DIST = 40.0
REPATH_DIST = 300.0
REPATH_INTERVAL = 40
STUCK_MOVE_DIST = 20.0
STUCK_TICKS = 40
JUMP_TRIGGER_DIST = 50.0
JUMP_COOLDOWN = 4
CROUCH_APPROACH_DIST = 100.0
LOOK_AHEAD_DIST = 200.0


class BotGoalType(Enum):
    MOVE_TO = auto()
    HOLD = auto()
    PATROL = auto()
    IDLE = auto()
    EXPLORE = auto()  # Direct walk toward target, no pathfinding


class BotBehaviorState(Enum):
    IDLE = auto()
    NAVIGATING = auto()
    ARRIVED = auto()
    HOLDING = auto()


@dataclass
class BotGoal:
    type: BotGoalType = BotGoalType.IDLE
    position: tuple[float, float, float] | None = None
    look_dir: tuple[float, float, float] | None = None
    patrol_points: list[tuple[float, float, float]] = field(default_factory=list)
    patrol_idx: int = 0


@dataclass
class BotNavState:
    """Per-bot navigation state."""

    waypoints: list[AnnotatedWaypoint]
    waypoint_idx: int = 0
    last_repath_tick: int = 0
    last_progress_tick: int = 0
    last_progress_pos: tuple[float, float, float] = (0.0, 0.0, 0.0)
    last_jump_tick: int = 0
    stuck_repaths: int = 0


@dataclass
class BotBrain:
    bot_id: int
    state: BotBehaviorState = BotBehaviorState.IDLE
    goal: BotGoal = field(default_factory=BotGoal)
    nav_state: BotNavState | None = None


class BotManager:
    """Manages per-bot behavior and produces movement commands."""

    def __init__(
        self, nav: NavGraph, terrain: TerrainAnalyzer, strategy: Strategy,
    ) -> None:
        self.nav = nav
        self.terrain = terrain
        self.strategy = strategy
        self._brains: dict[int, BotBrain] = {}

    def _get_brain(self, bot_id: int) -> BotBrain:
        if bot_id not in self._brains:
            self._brains[bot_id] = BotBrain(bot_id=bot_id)
        return self._brains[bot_id]

    def set_goal(self, bot_id: int, goal: BotGoal) -> None:
        brain = self._get_brain(bot_id)
        brain.goal = goal
        brain.nav_state = None
        if goal.type == BotGoalType.IDLE:
            brain.state = BotBehaviorState.IDLE
        else:
            brain.state = BotBehaviorState.NAVIGATING
        log.info("bot=%d: goal set type=%s state=%s", bot_id, goal.type.name, brain.state.name)

    def compute_commands(self, state: GameState) -> list[BotCommand]:
        # Let strategy assign/update goals
        new_goals = self.strategy.assign_goals(state, self._brains, self.nav)
        for bot_id, goal in new_goals.items():
            self.set_goal(bot_id, goal)

        # Clean up dead bots
        for bot in state.bots.values():
            if not bot.alive:
                if bot.id in self._brains:
                    brain = self._brains[bot.id]
                    brain.state = BotBehaviorState.IDLE
                    brain.nav_state = None

        commands: list[BotCommand] = []
        for bot in state.bots.values():
            if not bot.alive:
                continue
            cmd = self._tick_bot(self._get_brain(bot.id), bot, state.tick)
            if cmd is not None:
                commands.append(cmd)

        return commands

    def _tick_bot(self, brain: BotBrain, bot: BotState, tick: int) -> BotCommand | None:
        if brain.state == BotBehaviorState.IDLE:
            return None

        if brain.state == BotBehaviorState.HOLDING:
            look = brain.goal.look_dir or brain.goal.position or bot.pos
            return BotCommand(id=bot.id, move_target=bot.pos, look_target=look)

        if brain.state == BotBehaviorState.ARRIVED:
            brain.state = BotBehaviorState.HOLDING
            log.info("bot=%d: ARRIVED -> HOLDING", bot.id)
            look = brain.goal.look_dir or brain.goal.position or bot.pos
            return BotCommand(id=bot.id, move_target=bot.pos, look_target=look)

        # NAVIGATING — dispatch by goal type
        if brain.goal.type == BotGoalType.EXPLORE:
            return self._tick_explore(brain, bot, tick)
        return self._tick_navigate(brain, bot, tick)

    def _tick_explore(self, brain: BotBrain, bot: BotState, tick: int) -> BotCommand | None:
        """Teleport to goal position, then walk in a random direction."""
        target = brain.goal.position
        if target is None:
            brain.state = BotBehaviorState.IDLE
            return None

        # First tick: teleport to the target area, pick a random walk direction
        if brain.nav_state is None:
            angle = random.uniform(0, 2 * math.pi)
            walk_target = (
                target[0] + math.cos(angle) * 500.0,
                target[1] + math.sin(angle) * 500.0,
                target[2],
            )
            brain.nav_state = BotNavState(
                waypoints=[], last_progress_tick=tick, last_progress_pos=target,
            )
            brain.goal.look_dir = walk_target  # stash walk target
            log.info("bot=%d: teleport to (%.0f,%.0f,%.0f), walk toward (%.0f,%.0f)",
                     brain.bot_id, *target, walk_target[0], walk_target[1])
            return BotCommand(
                id=bot.id, move_target=target, look_target=target, flags=FLAG_TELEPORT,
            )

        # Subsequent ticks: walk toward the random direction
        walk_target = brain.goal.look_dir or target
        dx = bot.pos[0] - walk_target[0]
        dy = bot.pos[1] - walk_target[1]
        dist = math.sqrt(dx * dx + dy * dy)

        # Arrived at walk target
        if dist < WAYPOINT_REACH_DIST:
            brain.state = BotBehaviorState.IDLE
            return BotCommand(id=bot.id, move_target=bot.pos, look_target=bot.pos)

        # Stuck detection
        ns = brain.nav_state
        if (tick - ns.last_progress_tick) >= STUCK_TICKS:
            pdx = bot.pos[0] - ns.last_progress_pos[0]
            pdy = bot.pos[1] - ns.last_progress_pos[1]
            if math.sqrt(pdx * pdx + pdy * pdy) < STUCK_MOVE_DIST:
                brain.state = BotBehaviorState.IDLE
                log.info("bot=%d: explore stuck, going IDLE", brain.bot_id)
                return BotCommand(id=bot.id, move_target=bot.pos, look_target=bot.pos)
            ns.last_progress_tick = tick
            ns.last_progress_pos = bot.pos

        return BotCommand(id=bot.id, move_target=walk_target, look_target=walk_target)

    def _compute_path(
        self, brain: BotBrain, pos: tuple[float, float, float],
        target: tuple[float, float, float], tick: int,
    ) -> BotNavState | None:
        current_area = self.nav.find_area(pos)
        goal_area = self.nav.find_area(target)
        path = self.nav.find_path(current_area, goal_area)

        if path is None:
            local_target = self.nav.find_gathering_point(current_area)
            path = self.nav.find_path(current_area, local_target)

        if path is None:
            return None

        waypoints = self.nav.path_to_safe_waypoints(path, self.terrain)
        nav = BotNavState(
            waypoints=waypoints, last_repath_tick=tick,
            last_progress_tick=tick, last_progress_pos=pos,
        )
        log.info(
            "bot=%d: path %d -> %d (%d waypoints)",
            brain.bot_id, path[0], path[-1], len(waypoints),
        )
        return nav

    def _tick_navigate(self, brain: BotBrain, bot: BotState, tick: int) -> BotCommand | None:
        target_pos = brain.goal.position
        if target_pos is None:
            brain.state = BotBehaviorState.IDLE
            return None

        nav = brain.nav_state

        # Compute initial path
        if nav is None:
            nav = self._compute_path(brain, bot.pos, target_pos, tick)
            if nav is None:
                log.warning("bot=%d: no path found", brain.bot_id)
                brain.state = BotBehaviorState.IDLE
                return None
            brain.nav_state = nav

        # Advance past reached waypoints
        while nav.waypoint_idx < len(nav.waypoints):
            wp = nav.waypoints[nav.waypoint_idx]
            dx = bot.pos[0] - wp.pos[0]
            dy = bot.pos[1] - wp.pos[1]
            if math.sqrt(dx * dx + dy * dy) < WAYPOINT_REACH_DIST:
                nav.waypoint_idx += 1
            else:
                break

        # Reached destination
        if nav.waypoint_idx >= len(nav.waypoints):
            brain.state = BotBehaviorState.ARRIVED
            log.info("bot=%d: NAVIGATING -> ARRIVED", brain.bot_id)
            if brain.goal.type == BotGoalType.PATROL and brain.goal.patrol_points:
                brain.goal.patrol_idx = (
                    (brain.goal.patrol_idx + 1) % len(brain.goal.patrol_points)
                )
                brain.goal.position = brain.goal.patrol_points[brain.goal.patrol_idx]
                brain.nav_state = None
                brain.state = BotBehaviorState.NAVIGATING
                log.info("bot=%d: patrol -> next point %d", brain.bot_id, brain.goal.patrol_idx)
            return BotCommand(id=bot.id, move_target=bot.pos, look_target=target_pos)

        # Stuck detection — simple repath
        if (tick - nav.last_progress_tick) >= STUCK_TICKS:
            pdx = bot.pos[0] - nav.last_progress_pos[0]
            pdy = bot.pos[1] - nav.last_progress_pos[1]
            moved = math.sqrt(pdx * pdx + pdy * pdy)
            if moved < STUCK_MOVE_DIST:
                nav.stuck_repaths += 1
                log.warning(
                    "bot=%d: stuck (moved=%.0f), repath attempt=%d",
                    brain.bot_id, moved, nav.stuck_repaths,
                )
                new_nav = self._compute_path(brain, bot.pos, target_pos, tick)
                if new_nav is not None:
                    new_nav.stuck_repaths = nav.stuck_repaths
                    brain.nav_state = new_nav
                    nav = new_nav
                else:
                    brain.nav_state = None
                    brain.state = BotBehaviorState.IDLE
                    return None
            else:
                nav.last_progress_tick = tick
                nav.last_progress_pos = bot.pos
                nav.stuck_repaths = 0

        # Repath if off course
        wp = nav.waypoints[nav.waypoint_idx]
        dx = bot.pos[0] - wp.pos[0]
        dy = bot.pos[1] - wp.pos[1]
        dist = math.sqrt(dx * dx + dy * dy)

        if dist > REPATH_DIST and (tick - nav.last_repath_tick) >= REPATH_INTERVAL:
            log.info("bot=%d: repathing (dist=%.0f > %.0f)", brain.bot_id, dist, REPATH_DIST)
            new_nav = self._compute_path(brain, bot.pos, target_pos, tick)
            if new_nav is not None:
                nav = new_nav
                brain.nav_state = nav
                if nav.waypoint_idx >= len(nav.waypoints):
                    brain.state = BotBehaviorState.ARRIVED
                    return BotCommand(id=bot.id, move_target=bot.pos, look_target=target_pos)
                wp = nav.waypoints[nav.waypoint_idx]
                dx = bot.pos[0] - wp.pos[0]
                dy = bot.pos[1] - wp.pos[1]
                dist = math.sqrt(dx * dx + dy * dy)

        flags = self._compute_flags(nav, bot.pos, tick)
        look_target = self._path_lookahead(nav, bot.pos)

        if tick % 40 == 0:
            log.info(
                "  bot=%d state=%s wp=%d/%d pos=(%.0f,%.0f) -> wp=(%.0f,%.0f) dist=%.0f"
                " flags=%d",
                brain.bot_id, brain.state.name,
                nav.waypoint_idx, len(nav.waypoints),
                bot.pos[0], bot.pos[1], wp.pos[0], wp.pos[1], dist,
                flags,
            )

        return BotCommand(id=bot.id, move_target=wp.pos, look_target=look_target, flags=flags)

    def _compute_flags(
        self, nav: BotNavState, bot_pos: tuple[float, float, float], tick: int,
    ) -> int:
        flags = 0
        idx = nav.waypoint_idx
        if idx >= len(nav.waypoints):
            return flags

        wp = nav.waypoints[idx]
        dx = bot_pos[0] - wp.pos[0]
        dy = bot_pos[1] - wp.pos[1]
        dist = math.sqrt(dx * dx + dy * dy)

        if wp.needs_jump and dist < JUMP_TRIGGER_DIST:
            if (tick - nav.last_jump_tick) >= JUMP_COOLDOWN:
                flags |= FLAG_JUMP
                nav.last_jump_tick = tick

        if wp.needs_crouch:
            flags |= FLAG_DUCK
        elif idx + 1 < len(nav.waypoints):
            next_wp = nav.waypoints[idx + 1]
            if next_wp.needs_crouch:
                ndx = bot_pos[0] - next_wp.pos[0]
                ndy = bot_pos[1] - next_wp.pos[1]
                ndist = math.sqrt(ndx * ndx + ndy * ndy)
                if ndist < CROUCH_APPROACH_DIST:
                    flags |= FLAG_DUCK

        current_area = self.nav.find_area(bot_pos)
        if self.terrain.is_crouch_area(current_area):
            flags |= FLAG_DUCK

        return flags

    def _path_lookahead(
        self, nav: BotNavState, bot_pos: tuple[float, float, float],
        lookahead: float = LOOK_AHEAD_DIST,
    ) -> tuple[float, float, float]:
        """Find a point on the path polyline *lookahead* units ahead of the bot."""
        idx = nav.waypoint_idx
        if idx >= len(nav.waypoints):
            return nav.waypoints[-1].pos

        remaining = lookahead
        current = bot_pos

        for i in range(idx, len(nav.waypoints)):
            wp_pos = nav.waypoints[i].pos
            dx = wp_pos[0] - current[0]
            dy = wp_pos[1] - current[1]
            seg_len = math.sqrt(dx * dx + dy * dy)

            if seg_len >= remaining and seg_len > 0.001:
                t = remaining / seg_len
                return (
                    current[0] + dx * t,
                    current[1] + dy * t,
                    current[2] + (wp_pos[2] - current[2]) * t,
                )

            remaining -= seg_len
            current = wp_pos

        return nav.waypoints[-1].pos
