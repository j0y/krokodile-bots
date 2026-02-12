"""Tactical planner: score grid positions using the influence map and assign bots.

Falls back to a fixed rally point if no map data is available.
"""

from __future__ import annotations

import logging

from tactical.influence_map import InfluenceMap, WEIGHT_PROFILES
from tactical.protocol import BotCommand
from tactical.state import GameState
from tactical.telemetry import BotCommandRow

log = logging.getLogger(__name__)


class Planner:
    def __init__(
        self,
        rally: tuple[float, float, float],
        controlled_team: int = 2,
        influence_map: InfluenceMap | None = None,
    ) -> None:
        self.rally = rally
        self.controlled_team = controlled_team
        self.influence_map = influence_map
        self.profile_name = "defend"

    def compute_commands(
        self, state: GameState,
    ) -> tuple[list[BotCommand], list[BotCommandRow]]:
        # Our bots: alive fake clients on the controlled team
        our_bots = [
            b for b in state.bots.values()
            if b.alive and b.is_bot and b.team == self.controlled_team
        ]
        if not our_bots:
            return [], []

        # Friendly = all alive players on our team (bots + humans, for spread penalty)
        friendly_positions = [
            b.pos for b in state.bots.values()
            if b.alive and b.team == self.controlled_team
        ]
        # Enemy = all alive players on other teams (skip spectators / unassigned: team <= 1)
        enemy_positions = [
            b.pos for b in state.bots.values()
            if b.alive and b.team != self.controlled_team and b.team > 1
        ]

        if self.influence_map is None:
            commands = self._rally_commands(our_bots)
        else:
            commands = self._influence_commands(
                our_bots, friendly_positions, enemy_positions,
            )

        rows = [
            BotCommandRow(
                tick=state.tick,
                bot_id=cmd.id,
                target_x=cmd.move_target[0],
                target_y=cmd.move_target[1],
                target_z=cmd.move_target[2],
                profile=self.profile_name,
            )
            for cmd in commands
        ]
        return commands, rows

    def _rally_commands(self, our_bots: list) -> list[BotCommand]:
        """Fallback: send all bots to the fixed rally point."""
        return [
            BotCommand(id=bot.id, move_target=self.rally, look_target=self.rally, flags=0)
            for bot in our_bots
        ]

    def _influence_commands(
        self,
        our_bots: list,
        friendly_positions: list[tuple[float, float, float]],
        enemy_positions: list[tuple[float, float, float]],
    ) -> list[BotCommand]:
        """Score positions using influence map and assign one per bot."""
        assert self.influence_map is not None

        weights = WEIGHT_PROFILES.get(self.profile_name, WEIGHT_PROFILES["defend"])

        positions = self.influence_map.best_positions(
            weights,
            num=len(our_bots),
            objective_center=self.rally,
            objective_positions=[self.rally],
            friendly_positions=friendly_positions,
            enemy_positions=enemy_positions,
        )

        commands: list[BotCommand] = []
        for bot, target in zip(our_bots, positions):
            commands.append(
                BotCommand(
                    id=bot.id,
                    move_target=target,
                    look_target=target,
                    flags=0,
                )
            )
        return commands
