"""Strategy layer — goal assignment for bots."""

from __future__ import annotations

import logging
from typing import Protocol

from smartbots.behavior import BotBrain, BotBehaviorState, BotGoal, BotGoalType
from smartbots.navigation import NavGraph
from smartbots.state import GameState

log = logging.getLogger(__name__)


class Strategy(Protocol):
    """Interface for goal-assignment strategies."""

    def assign_goals(
        self,
        state: GameState,
        brains: dict[int, BotBrain],
        nav: NavGraph,
    ) -> dict[int, BotGoal]: ...


class GatheringStrategy:
    """Default strategy: all bots navigate to a central gathering point."""

    def __init__(self) -> None:
        self._target_area: int | None = None
        self._target_pos: tuple[float, float, float] | None = None

    def assign_goals(
        self,
        state: GameState,
        brains: dict[int, BotBrain],
        nav: NavGraph,
    ) -> dict[int, BotGoal]:
        # Compute gathering point once
        if self._target_pos is None:
            first_alive = next((b for b in state.bots.values() if b.alive), None)
            if first_alive is None:
                return {}
            near_area = nav.find_area(first_alive.pos)
            self._target_area = nav.find_gathering_point(near_area)
            self._target_pos = nav.area_center(self._target_area)
            log.info(
                "Gathering target: area %d at (%.0f, %.0f, %.0f)",
                self._target_area, *self._target_pos,
            )

        # Only assign goals to bots that are IDLE (new/respawned)
        new_goals: dict[int, BotGoal] = {}
        for bot in state.bots.values():
            if not bot.alive:
                continue
            brain = brains.get(bot.id)
            if brain is None or brain.state == BotBehaviorState.IDLE:
                new_goals[bot.id] = BotGoal(
                    type=BotGoalType.MOVE_TO, position=self._target_pos,
                )
        return new_goals
