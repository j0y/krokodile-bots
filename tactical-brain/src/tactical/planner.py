"""Minimal tactical planner: assign all alive bots to a fixed rally point.

This is a proof-of-concept that validates the UDP bridge works end-to-end.
A real planner would use nav mesh data, team coordination, etc.
"""

from __future__ import annotations

from tactical.protocol import BotCommand
from tactical.state import GameState


class Planner:
    def __init__(self, rally: tuple[float, float, float]) -> None:
        self.rally = rally

    def compute_commands(self, state: GameState) -> list[BotCommand]:
        commands: list[BotCommand] = []
        for bot in state.bots.values():
            if bot.alive:
                commands.append(
                    BotCommand(
                        id=bot.id,
                        move_target=self.rally,
                        look_target=self.rally,
                        flags=0,
                    )
                )
        return commands
