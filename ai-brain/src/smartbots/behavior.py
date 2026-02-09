"""Per-bot behavior model with state machine and NextBot-style path following."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

from smartbots.navigation import NavGraph
from smartbots.pathfollower import PathFollower, compute_path
from smartbots.protocol import BotCommand
from smartbots.state import BotState, GameState
from smartbots.terrain import TerrainAnalyzer

if TYPE_CHECKING:
    from smartbots.clearance import ClearanceMap
    from smartbots.collision_map import CollisionMap
    from smartbots.strategy import Strategy
    from smartbots.visibility import VisibilityMap

log = logging.getLogger(__name__)

# Navigation constants
REPATH_DEVIATION = 200.0
REPATH_INTERVAL = 40
STUCK_MOVE_DIST = 20.0
STUCK_TICKS = 40
# After this many consecutive stuck repaths, run back-up → jump → normal cycle
STUCK_JUMP_THRESHOLD = 5
STUCK_JUMP_PERIOD = 24  # full cycle length in ticks (3 phases of 8 ticks each)


class BotGoalType(Enum):
    MOVE_TO = auto()
    HOLD = auto()
    PATROL = auto()
    IDLE = auto()


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
    """Per-bot navigation state using PathFollower."""

    path: PathFollower
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
        self,
        nav: NavGraph,
        terrain: TerrainAnalyzer,
        strategy: Strategy,
        collision_map: CollisionMap | None = None,
        visibility: VisibilityMap | None = None,
        clearance: ClearanceMap | None = None,
    ) -> None:
        self.nav = nav
        self.terrain = terrain
        self.strategy = strategy
        self.collision_map = collision_map
        self.visibility = visibility
        self.clearance = clearance
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
            cmd = self._tick_bot(self._get_brain(bot.id), bot, state)
            if cmd is not None:
                commands.append(cmd)

        return commands

    def _tick_bot(
        self, brain: BotBrain, bot: BotState, state: GameState,
    ) -> BotCommand | None:
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

        # NAVIGATING
        return self._tick_navigate(brain, bot, state)

    def _compute_path(
        self, brain: BotBrain, pos: tuple[float, float, float],
        target: tuple[float, float, float], tick: int,
    ) -> BotNavState | None:
        follower = compute_path(
            pos, target, self.nav, self.terrain, self.collision_map, self.clearance,
        )

        if follower is None:
            # Fallback: try navigating to nearest large area
            current_area = self.nav.find_area(pos)
            local_target = self.nav.find_gathering_point(current_area)
            local_pos = self.nav.area_center(local_target)
            follower = compute_path(
                pos, local_pos, self.nav, self.terrain, self.collision_map, self.clearance,
            )

        if follower is None:
            return None

        nav = BotNavState(
            path=follower, last_repath_tick=tick,
            last_progress_tick=tick, last_progress_pos=pos,
        )
        log.info(
            "bot=%d: path computed (%d segments)",
            brain.bot_id, len(follower.segments),
        )
        return nav

    def _tick_navigate(
        self, brain: BotBrain, bot: BotState, state: GameState,
    ) -> BotCommand | None:
        tick = state.tick
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

        pf = nav.path

        # Advance past reached goals (NextBot-style dividing plane check)
        while pf.is_at_goal(bot.pos):
            if not pf.advance():
                # Path complete
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

        # Skip close ground-level goals to avoid orbiting tight waypoints
        # (mirrors Valve PathFollower::CheckProgress m_minLookAheadRange)
        pf.skip_close_goals(bot.pos)

        # Stuck detection
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
        deviation = pf.deviation(bot.pos)
        if deviation > REPATH_DEVIATION and (tick - nav.last_repath_tick) >= REPATH_INTERVAL:
            log.info("bot=%d: repathing (deviation=%.0f > %.0f)", brain.bot_id, deviation, REPATH_DEVIATION)
            new_nav = self._compute_path(brain, bot.pos, target_pos, tick)
            if new_nav is not None:
                brain.nav_state = new_nav
                nav = new_nav
                pf = nav.path

        # Movement targets
        move_target = pf.get_move_target(bot.pos)
        look_target = pf.get_look_target(bot.pos)
        flags, nav.last_jump_tick = pf.compute_flags(bot.pos, tick, nav.last_jump_tick)

        # Unstick: clearance-directed escape when deeply stuck.
        if nav.stuck_repaths >= STUCK_JUMP_THRESHOLD:
            from smartbots.protocol import FLAG_JUMP
            if self.clearance is not None:
                area_id = self.nav.find_area(bot.pos)
                best_angle = self.clearance.get_open_direction(area_id)
                move_target = (
                    bot.pos[0] + 80.0 * math.cos(best_angle),
                    bot.pos[1] + 80.0 * math.sin(best_angle),
                    bot.pos[2],
                )
                # Jump every other cycle to clear obstacles
                if (tick % STUCK_JUMP_PERIOD) < STUCK_JUMP_PERIOD // 2:
                    flags |= FLAG_JUMP
            else:
                # Fallback: back away then jump forward
                cycle = tick % STUCK_JUMP_PERIOD
                third = STUCK_JUMP_PERIOD // 3
                if cycle < third:
                    dx = bot.pos[0] - move_target[0]
                    dy = bot.pos[1] - move_target[1]
                    mag = math.sqrt(dx * dx + dy * dy)
                    if mag > 0.001:
                        move_target = (
                            bot.pos[0] + dx / mag * 80.0,
                            bot.pos[1] + dy / mag * 80.0,
                            bot.pos[2],
                        )
                elif cycle < third * 2:
                    flags |= FLAG_JUMP

        if tick % 40 == 0:
            goal = pf.get_goal()
            goal_pos = goal.pos if goal else move_target
            dx = bot.pos[0] - goal_pos[0]
            dy = bot.pos[1] - goal_pos[1]
            dist = math.sqrt(dx * dx + dy * dy)
            log.info(
                "  bot=%d state=%s seg=%d/%d pos=(%.0f,%.0f) -> goal=(%.0f,%.0f)"
                " dist=%.0f flags=%d",
                brain.bot_id, brain.state.name,
                pf.goal_idx, len(pf.segments),
                bot.pos[0], bot.pos[1], goal_pos[0], goal_pos[1], dist,
                flags,
            )

        return BotCommand(
            id=bot.id, move_target=move_target,
            look_target=look_target, flags=flags,
        )
