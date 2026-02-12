"""Tactical planner: score grid positions using the influence map and assign bots.

Falls back to a fixed rally point if no map data is available.
"""

from __future__ import annotations

import logging

from tactical.influence_map import InfluenceMap, WEIGHT_PROFILES
from tactical.protocol import BotCommand
from tactical.state import GameState

log = logging.getLogger(__name__)


class Planner:
    def __init__(
        self,
        rally: tuple[float, float, float],
        influence_map: InfluenceMap | None = None,
    ) -> None:
        self.rally = rally
        self.influence_map = influence_map
        self.profile_name = "defend"

    def compute_commands(self, state: GameState) -> list[BotCommand]:
        alive_bots = [b for b in state.bots.values() if b.alive]
        if not alive_bots:
            return []

        if self.influence_map is None:
            return self._rally_commands(alive_bots)

        return self._influence_commands(alive_bots)

    def _rally_commands(self, alive_bots: list) -> list[BotCommand]:
        """Fallback: send all bots to the fixed rally point."""
        return [
            BotCommand(id=bot.id, move_target=self.rally, look_target=self.rally, flags=0)
            for bot in alive_bots
        ]

    def _influence_commands(self, alive_bots: list) -> list[BotCommand]:
        """Score positions using influence map and assign one per bot."""
        assert self.influence_map is not None

        weights = WEIGHT_PROFILES.get(self.profile_name, WEIGHT_PROFILES["defend"])
        friendly_positions = [bot.pos for bot in alive_bots]

        # Use rally point as objective center (placeholder until game events provide it)
        positions = self.influence_map.best_positions(
            weights,
            num=len(alive_bots),
            objective_center=self.rally,
            objective_positions=[self.rally],
            friendly_positions=friendly_positions,
        )

        commands: list[BotCommand] = []
        for bot, target in zip(alive_bots, positions):
            commands.append(
                BotCommand(
                    id=bot.id,
                    move_target=target,
                    look_target=target,
                    flags=0,
                )
            )
        return commands
